package guardian

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

type Service struct {
	cfg             Config
	store           *Store
	sub2api         *Sub2APIClient
	refresher       *OAuthRefresher
	auditor         *Auditor
	seenMu          sync.Mutex
	seen            map[int64]struct{}
	deletedReviveMu sync.Mutex
	deletedRevive   DeletedReviveJobStatus
}

type DeletedReviveJobStatus struct {
	Running       bool      `json:"running"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	Total         int       `json:"total"`
	Processed     int       `json:"processed"`
	Restored      int       `json:"restored"`
	QuotaRestored int       `json:"quota_restored"`
	KeptDeleted   int       `json:"kept_deleted"`
	Unknown       int       `json:"unknown"`
	Failed        int       `json:"failed"`
	LastError     string    `json:"last_error"`
}

func NewService(cfg Config, store *Store, sub2api *Sub2APIClient, refresher *OAuthRefresher, auditor *Auditor) *Service {
	return &Service{cfg: cfg, store: store, sub2api: sub2api, refresher: refresher, auditor: auditor, seen: map[int64]struct{}{}}
}

func (s *Service) Run(ctx context.Context) error {
	locked, err := s.store.TryAdvisoryLock(ctx)
	if err != nil {
		return err
	}
	if !locked {
		return fmt.Errorf("another guardian instance holds advisory lock")
	}
	log.Printf("guardian started dry_run=%v once=%v audit=%s", s.cfg.DryRun, s.cfg.Once, s.auditor.Path())
	events := make(chan int64, 1024)
	if !s.cfg.Once {
		go s.listenForever(ctx, events)
	}
	if err := s.ScanOnce(ctx); err != nil {
		log.Printf("initial scan failed: %v", err)
	}
	if s.cfg.Once {
		return nil
	}
	ticker := time.NewTicker(s.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case id := <-events:
			s.Enqueue(ctx, id)
		case <-ticker.C:
			if err := s.ScanOnce(ctx); err != nil {
				log.Printf("scan failed: %v", err)
			}
		}
	}
}

func (s *Service) listenForever(ctx context.Context, events chan<- int64) {
	for {
		if ctx.Err() != nil {
			return
		}
		log.Printf("listener starting channel=%s", s.cfg.ListenChannel)
		err := s.store.Listen(ctx, events)
		if ctx.Err() != nil {
			return
		}
		log.Printf("listener stopped: %v; reconnecting in 5s", err)
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return
		}
	}
}

func (s *Service) ScanOnce(ctx context.Context) error {
	accounts, err := s.store.EligibleAccounts(ctx, s.cfg.BatchSize)
	if err != nil {
		return err
	}
	if len(accounts) == 0 {
		log.Printf("scan complete scanned=0")
		return nil
	}
	jobs := make(chan Account)
	var wg sync.WaitGroup
	workers := min(s.cfg.TestWorkers, len(accounts))
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for acc := range jobs {
				s.ProcessAccount(ctx, acc)
			}
		}()
	}
	for _, acc := range accounts {
		jobs <- acc
	}
	close(jobs)
	wg.Wait()
	log.Printf("scan complete scanned=%d", len(accounts))
	return nil
}

func (s *Service) Enqueue(ctx context.Context, id int64) {
	s.seenMu.Lock()
	if _, ok := s.seen[id]; ok {
		s.seenMu.Unlock()
		return
	}
	s.seen[id] = struct{}{}
	s.seenMu.Unlock()
	go func() {
		defer func() {
			s.seenMu.Lock()
			delete(s.seen, id)
			s.seenMu.Unlock()
		}()
		acc, err := s.store.GetAccount(ctx, id)
		if err != nil {
			log.Printf("load account %d failed: %v", id, err)
			return
		}
		if !IsEligibleAccount(acc.Platform, acc.Type, acc.Status, acc.Deleted, acc.ErrorMessage) {
			s.writeAudit(AuditRecord{AccountID: id, AccountName: acc.Name, InitialStatus: acc.Status, InitialErrorMessage: acc.ErrorMessage, Classification: ClassifyEvidence(acc.ErrorMessage), FinalAction: "skipped_not_eligible", FinalReason: "account is not an eligible account-internal failure", StartedAt: time.Now(), FinishedAt: time.Now(), DryRun: s.cfg.DryRun})
			return
		}
		s.ProcessAccount(ctx, acc)
	}()
}

func (s *Service) ProcessAccount(ctx context.Context, acc Account) {
	started := time.Now()
	rec := AuditRecord{AccountID: acc.ID, AccountName: acc.Name, InitialStatus: acc.Status, InitialErrorMessage: acc.ErrorMessage, Classification: ClassifyEvidence(acc.ErrorMessage), StartedAt: started, DryRun: s.cfg.DryRun}
	defer func() {
		rec.FinishedAt = time.Now()
		s.writeAudit(rec)
		log.Printf("account=%d action=%s reason=%s", rec.AccountID, rec.FinalAction, rec.FinalReason)
	}()
	inactiveSchedulable := IsInactiveSchedulableAccount(acc)
	if rec.Classification != ClassEligibleAuth && !inactiveSchedulable {
		rec.FinalAction = "skipped_not_eligible"
		rec.FinalReason = "not account-internal auth evidence"
		log.Printf("account=%d phase=classify result=%s action=skip", acc.ID, rec.Classification)
		return
	}
	log.Printf("account=%d phase=classify result=%s", acc.ID, rec.Classification)
	if s.cfg.DryRun {
		rec.FinalAction = "would_process"
		rec.FinalReason = "dry-run: would disable scheduling, attempt revive, verify with Sub2API test, then restore/quota-keep/soft-delete based on result"
		log.Printf("account=%d phase=dry_run result=would_process", acc.ID)
		return
	}
	log.Printf("account=%d phase=disable_scheduling start", acc.ID)
	if err := s.store.DisableScheduling(ctx, acc.ID, "guardian processing account-internal auth failure"); err != nil {
		rec.FinalAction = "kept_unknown"
		rec.FinalReason = "disable scheduling failed: " + err.Error()
		log.Printf("account=%d phase=disable_scheduling result=failed reason=%s", acc.ID, err.Error())
		return
	}
	rec.SchedulingDisabled = true
	log.Printf("account=%d phase=disable_scheduling result=ok", acc.ID)
	refreshToken, _ := acc.Credentials["refresh_token"].(string)
	if refreshToken != "" {
		rec.RefreshAttempted = true
		log.Printf("account=%d phase=refresh start", acc.ID)
		tokens, reason, err := s.refresher.RefreshWithRetries(ctx, refreshToken)
		rec.RefreshReason = reason
		if err == nil {
			log.Printf("account=%d phase=refresh result=ok", acc.ID)
			log.Printf("account=%d phase=credentials_patch start", acc.ID)
			if err := s.store.PatchCredentials(ctx, acc.ID, tokens); err != nil {
				rec.RefreshResult = "update_failed"
				rec.FinalAction = "kept_unknown"
				rec.FinalReason = "credential patch failed: " + err.Error()
				log.Printf("account=%d phase=credentials_patch result=failed reason=%s", acc.ID, err.Error())
				return
			}
			log.Printf("account=%d phase=credentials_patch result=ok", acc.ID)
			fresh, loadErr := waitForRefreshedAccount(ctx, s.store.GetAccount, acc.ID, s.cfg.RetryAttempts, s.cfg.RetryDelay)
			if loadErr != nil {
				rec.RefreshResult = "verify_failed"
				rec.FinalAction = "kept_unknown"
				rec.FinalReason = "load account after refresh failed: " + loadErr.Error()
				log.Printf("account=%d phase=refresh_verify result=failed reason=%s", acc.ID, loadErr.Error())
				return
			}
			if IsRefreshableMissingAccessTokenAccount(fresh) {
				rec.RefreshResult = "verify_failed"
				rec.FinalAction = "kept_unknown"
				rec.FinalReason = "access_token still missing after refresh"
				log.Printf("account=%d phase=refresh_verify result=failed reason=access_token still missing after refresh", acc.ID)
				return
			}
			rec.RefreshResult = "ok"
		} else {
			rec.RefreshResult = "failed"
			log.Printf("account=%d phase=refresh result=failed reason=%s", acc.ID, reason)
			if ClassifyEvidence(reason) == ClassNeedsRelogin {
				rec.FinalAction = "needs_relogin"
				rec.FinalReason = "needs manual relogin: " + reason
				log.Printf("account=%d phase=needs_relogin start", acc.ID)
				if err := s.store.MarkNeedsRelogin(ctx, acc.ID, rec.FinalReason); err != nil {
					rec.FinalAction = "kept_unknown"
					rec.FinalReason = "mark needs relogin failed: " + err.Error()
					log.Printf("account=%d phase=needs_relogin result=failed reason=%s", acc.ID, err.Error())
				} else {
					log.Printf("account=%d phase=needs_relogin result=ok", acc.ID)
				}
				return
			}
			if ClassifyEvidence(reason) != ClassEligibleAuth {
				rec.FinalAction = "kept_unknown"
				rec.FinalReason = "refresh uncertain: " + reason
				return
			}
		}
	} else {
		rec.RefreshResult = "missing_refresh_token"
		log.Printf("account=%d phase=refresh result=missing_refresh_token", acc.ID)
		if inactiveSchedulable && acc.ErrorMessage == "" {
			rec.FinalAction = "disabled_inactive"
			rec.FinalReason = "inactive account scheduling disabled; no refresh token available"
			return
		}
	}

	log.Printf("account=%d phase=test start model=%s", acc.ID, s.cfg.TestModel)
	testResult, testReason := s.sub2api.TestAccountWithRetries(ctx, acc.ID)
	rec.TestResult = testResult
	rec.TestReason = testReason
	log.Printf("account=%d phase=test result=%s reason=%s", acc.ID, testResult, testReason)
	finalAction, finalReason := resolveTestFinalAction(testResult, testReason)
	rec.FinalAction = finalAction
	rec.FinalReason = finalReason
	switch finalAction {
	case "revived":
		log.Printf("account=%d phase=mark_live start", acc.ID)
		if err := s.store.MarkLive(ctx, acc.ID); err != nil {
			rec.FinalAction = "kept_unknown"
			rec.FinalReason = "mark live failed: " + err.Error()
			log.Printf("account=%d phase=mark_live result=failed reason=%s", acc.ID, err.Error())
		} else {
			rec.FinalAction = "revived"
			rec.FinalReason = "live check succeeded"
			log.Printf("account=%d phase=mark_live result=ok", acc.ID)
		}
	case "kept_quota":
		log.Printf("account=%d phase=keep_quota start", acc.ID)
		if err := s.store.KeepQuota(ctx, acc.ID); err != nil {
			rec.FinalAction = "kept_unknown"
			rec.FinalReason = "mark quota keep failed: " + err.Error()
			log.Printf("account=%d phase=keep_quota result=failed reason=%s", acc.ID, err.Error())
		} else {
			rec.FinalAction = "kept_quota"
			rec.FinalReason = "quota/rate-limit belongs to Sub2API handling"
			log.Printf("account=%d phase=keep_quota result=ok", acc.ID)
		}
	case "soft_deleted":
		log.Printf("account=%d phase=soft_delete start", acc.ID)
		if err := s.store.SoftDelete(ctx, acc.ID, "deterministic auth death after revive/test: "+testReason); err != nil {
			rec.FinalAction = "kept_unknown"
			rec.FinalReason = "soft delete failed: " + err.Error()
			log.Printf("account=%d phase=soft_delete result=failed reason=%s", acc.ID, err.Error())
		} else {
			rec.FinalAction = "soft_deleted"
			rec.FinalReason = "deterministic auth death after revive/test"
			log.Printf("account=%d phase=soft_delete result=ok", acc.ID)
		}
	case "needs_relogin":
		log.Printf("account=%d phase=needs_relogin start", acc.ID)
		if err := s.store.MarkNeedsRelogin(ctx, acc.ID, "needs manual relogin: "+testReason); err != nil {
			rec.FinalAction = "kept_unknown"
			rec.FinalReason = "mark needs relogin failed: " + err.Error()
			log.Printf("account=%d phase=needs_relogin result=failed reason=%s", acc.ID, err.Error())
		} else {
			rec.FinalAction = "needs_relogin"
			rec.FinalReason = "needs manual relogin: " + testReason
			log.Printf("account=%d phase=needs_relogin result=ok", acc.ID)
		}
	default:
		rec.FinalAction = "kept_unknown"
		rec.FinalReason = "test uncertain: " + testReason
	}
}

func resolveTestFinalAction(result TestResult, reason string) (string, string) {
	switch result {
	case TestOK:
		return "revived", "live check succeeded"
	case TestQuota:
		return "kept_quota", "quota/rate-limit belongs to Sub2API handling"
	case TestDead:
		return "soft_deleted", "deterministic auth death after revive/test"
	case TestNeedsRelogin:
		return "needs_relogin", "needs manual relogin: " + reason
	default:
		if ClassifyEvidence(reason) == ClassNeedsRelogin {
			return "needs_relogin", "needs manual relogin: " + reason
		}
		return "kept_unknown", "test uncertain: " + reason
	}
}

func waitForRefreshedAccount(
	ctx context.Context,
	load func(context.Context, int64) (Account, error),
	id int64,
	attempts int,
	delay time.Duration,
) (Account, error) {
	if attempts < 1 {
		attempts = 1
	}
	var last Account
	for attempt := 1; attempt <= attempts; attempt++ {
		acc, err := load(ctx, id)
		if err != nil {
			return Account{}, err
		}
		last = acc
		if !IsRefreshableMissingAccessTokenAccount(acc) {
			return acc, nil
		}
		if attempt < attempts {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return Account{}, ctx.Err()
			}
		}
	}
	return last, fmt.Errorf("access_token still missing after refresh")
}

func (s *Service) CheckDeletedReviveCandidates(ctx context.Context, limit int) []AuditRecord {
	if limit < 1 {
		limit = 1
	}
	if limit > 50 {
		limit = 50
	}
	accounts, err := s.store.DeletedReviveCandidates(ctx, limit)
	if err != nil {
		rec := AuditRecord{FinalAction: "revive_deleted_failed", FinalReason: err.Error(), StartedAt: time.Now(), FinishedAt: time.Now(), DryRun: s.cfg.DryRun}
		s.writeAudit(rec)
		return []AuditRecord{rec}
	}
	out := make([]AuditRecord, 0, len(accounts))
	for _, acc := range accounts {
		out = append(out, s.CheckDeletedReviveCandidate(ctx, acc))
	}
	return out
}

func (s *Service) StartDeletedReviveAll(workers int) (DeletedReviveJobStatus, bool) {
	if workers < 1 {
		workers = 5
	}
	if workers > 20 {
		workers = 20
	}
	s.deletedReviveMu.Lock()
	if s.deletedRevive.Running {
		status := s.deletedRevive
		s.deletedReviveMu.Unlock()
		return status, false
	}
	s.deletedRevive = DeletedReviveJobStatus{Running: true, StartedAt: time.Now()}
	status := s.deletedRevive
	s.deletedReviveMu.Unlock()

	go s.runDeletedReviveAll(context.Background(), workers)
	return status, true
}

func (s *Service) DeletedReviveStatus() DeletedReviveJobStatus {
	s.deletedReviveMu.Lock()
	defer s.deletedReviveMu.Unlock()
	return s.deletedRevive
}

func (s *Service) runDeletedReviveAll(ctx context.Context, workers int) {
	log.Printf("deleted_revive_all start workers=%d", workers)
	accounts, err := s.store.DeletedReviveCandidates(ctx, 0)
	if err != nil {
		s.deletedReviveMu.Lock()
		s.deletedRevive.Running = false
		s.deletedRevive.FinishedAt = time.Now()
		s.deletedRevive.Failed++
		s.deletedRevive.LastError = err.Error()
		s.deletedReviveMu.Unlock()
		s.writeAudit(AuditRecord{FinalAction: "revive_deleted_failed", FinalReason: err.Error(), StartedAt: time.Now(), FinishedAt: time.Now(), DryRun: s.cfg.DryRun})
		log.Printf("deleted_revive_all failed load_candidates reason=%s", err.Error())
		return
	}
	s.deletedReviveMu.Lock()
	s.deletedRevive.Total = len(accounts)
	s.deletedReviveMu.Unlock()
	if len(accounts) == 0 {
		s.deletedReviveMu.Lock()
		s.deletedRevive.Running = false
		s.deletedRevive.FinishedAt = time.Now()
		s.deletedReviveMu.Unlock()
		log.Printf("deleted_revive_all complete total=0")
		return
	}
	jobs := make(chan Account)
	var wg sync.WaitGroup
	workerCount := min(workers, len(accounts))
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for acc := range jobs {
				rec := s.CheckDeletedReviveCandidate(ctx, acc)
				s.recordDeletedReviveProgress(rec)
			}
		}()
	}
	for _, acc := range accounts {
		jobs <- acc
	}
	close(jobs)
	wg.Wait()
	s.deletedReviveMu.Lock()
	s.deletedRevive.Running = false
	s.deletedRevive.FinishedAt = time.Now()
	done := s.deletedRevive
	s.deletedReviveMu.Unlock()
	log.Printf("deleted_revive_all complete total=%d processed=%d restored=%d quota_restored=%d kept_deleted=%d unknown=%d failed=%d",
		done.Total, done.Processed, done.Restored, done.QuotaRestored, done.KeptDeleted, done.Unknown, done.Failed)
}

func (s *Service) recordDeletedReviveProgress(rec AuditRecord) {
	s.deletedReviveMu.Lock()
	defer s.deletedReviveMu.Unlock()
	s.deletedRevive.Processed++
	switch rec.FinalAction {
	case "restored_deleted":
		s.deletedRevive.Restored++
	case "restored_deleted_quota":
		s.deletedRevive.QuotaRestored++
	case "deleted_kept":
		s.deletedRevive.KeptDeleted++
	case "kept_unknown":
		s.deletedRevive.Unknown++
	default:
		s.deletedRevive.Failed++
	}
	if rec.FinalReason != "" {
		s.deletedRevive.LastError = rec.FinalReason
	}
}

func (s *Service) CheckDeletedReviveCandidate(ctx context.Context, acc Account) AuditRecord {
	started := time.Now()
	rec := AuditRecord{
		AccountID:           acc.ID,
		AccountName:         acc.Name,
		InitialStatus:       acc.Status,
		InitialErrorMessage: acc.ErrorMessage,
		Classification:      ClassifyEvidence(acc.ErrorMessage),
		StartedAt:           started,
		DryRun:              s.cfg.DryRun,
	}
	defer func() {
		rec.FinishedAt = time.Now()
		s.writeAudit(rec)
		log.Printf("account=%d action=%s reason=%s", rec.AccountID, rec.FinalAction, rec.FinalReason)
	}()
	if s.cfg.DryRun {
		rec.FinalAction = "would_check_deleted_revive"
		rec.FinalReason = "dry-run: would refresh, temporarily restore, test, then restore or re-soft-delete"
		return rec
	}
	refreshToken, _ := acc.Credentials["refresh_token"].(string)
	if refreshToken == "" {
		rec.RefreshResult = "missing_refresh_token"
		rec.FinalAction = "deleted_kept"
		rec.FinalReason = "soft-deleted account has no refresh token"
		return rec
	}
	rec.RefreshAttempted = true
	log.Printf("account=%d phase=deleted_revive_refresh start", acc.ID)
	tokens, reason, err := s.refresher.RefreshWithRetries(ctx, refreshToken)
	rec.RefreshReason = reason
	if err != nil {
		rec.RefreshResult = "failed"
		rec.FinalAction = "deleted_kept"
		rec.FinalReason = "refresh failed for soft-deleted account: " + reason
		return rec
	}
	rec.RefreshResult = "ok"
	log.Printf("account=%d phase=deleted_revive_refresh result=ok", acc.ID)
	log.Printf("account=%d phase=deleted_revive_credentials_patch start", acc.ID)
	if err := s.store.PatchCredentialsAnyState(ctx, acc.ID, tokens); err != nil {
		rec.FinalAction = "deleted_kept"
		rec.FinalReason = "credential patch failed for soft-deleted account: " + err.Error()
		log.Printf("account=%d phase=deleted_revive_credentials_patch result=failed reason=%s", acc.ID, err.Error())
		return rec
	}
	log.Printf("account=%d phase=deleted_revive_credentials_patch result=ok", acc.ID)
	log.Printf("account=%d phase=deleted_revive_temporary_restore start", acc.ID)
	if err := s.store.TemporarilyRestoreForTest(ctx, acc.ID); err != nil {
		rec.FinalAction = "deleted_kept"
		rec.FinalReason = "temporary restore failed: " + err.Error()
		log.Printf("account=%d phase=deleted_revive_temporary_restore result=failed reason=%s", acc.ID, err.Error())
		return rec
	}
	log.Printf("account=%d phase=deleted_revive_temporary_restore result=ok", acc.ID)
	log.Printf("account=%d phase=deleted_revive_test start model=%s", acc.ID, s.cfg.TestModel)
	result, testReason := s.sub2api.TestAccountWithRetries(ctx, acc.ID)
	rec.TestResult = result
	rec.TestReason = testReason
	log.Printf("account=%d phase=deleted_revive_test result=%s reason=%s", acc.ID, result, testReason)
	switch result {
	case TestOK:
		if err := s.store.RestoreSoftDeleted(ctx, acc.ID); err != nil {
			rec.FinalAction = "kept_unknown"
			rec.FinalReason = "restore soft-deleted account failed: " + err.Error()
			return rec
		}
		rec.FinalAction = "restored_deleted"
		rec.FinalReason = "soft-deleted account revived and live check succeeded"
	case TestQuota:
		if err := s.store.RestoreSoftDeleted(ctx, acc.ID); err != nil {
			rec.FinalAction = "kept_unknown"
			rec.FinalReason = "restore quota soft-deleted account failed: " + err.Error()
			return rec
		}
		rec.FinalAction = "restored_deleted_quota"
		rec.FinalReason = "soft-deleted account refreshed but quota/rate-limited; restored for Sub2API handling"
	default:
		_ = s.store.ReSoftDelete(ctx, acc.ID, "deleted revive check failed: "+testReason)
		rec.FinalAction = "deleted_kept"
		rec.FinalReason = "soft-deleted account still not live: " + testReason
	}
	return rec
}

func (s *Service) writeAudit(rec AuditRecord) {
	if err := s.auditor.Write(rec); err != nil {
		log.Printf("audit write failed: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

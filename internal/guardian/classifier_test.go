package guardian

import (
	"context"
	"testing"
	"time"
)

func TestClassifyEvidenceTreatsAccountInternalAuthAsEligible(t *testing.T) {
	cases := []string{
		"Token revoked (401): Encountered invalidated oauth token for user, failing request",
		"Authentication failed (401): token_invalidated",
		"Provided authentication token is expired. Please try signing in again.",
		"invalid_grant: refresh token expired",
		"No access token available",
	}
	for _, input := range cases {
		if got := ClassifyEvidence(input); got != ClassEligibleAuth {
			t.Fatalf("ClassifyEvidence(%q)=%s, want %s", input, got, ClassEligibleAuth)
		}
	}
}

func TestClassifyEvidenceExcludesInfrastructureAndQuota(t *testing.T) {
	cases := map[string]EvidenceClass{
		`Post "https://chatgpt.com/backend-api/codex/responses": EOF`:                    ClassInfrastructure,
		`dial tcp: lookup chatgpt.com on 127.0.0.11:53: server misbehaving`:              ClassInfrastructure,
		`Post "https://chatgpt.com/backend-api/codex/responses": remote error: tls fail`: ClassInfrastructure,
		`HTTP 403: {"code":"unsupported_country_region_territory"}`:                      ClassInfrastructure,
		`HTTP 403: <html><title>Just a moment...</title>Cloudflare cf-ray</html>`:        ClassInfrastructure,
		`Recovered upstream error 429: The usage limit has been reached`:                 ClassQuota,
		`Unsupported parameter: disable_response_storage`:                                ClassRequestParameter,
		`HTTP 401: code refresh_token_reused`:                                            ClassNeedsRelogin,
		`Your session has ended. Please log in again. code app_session_terminated`:       ClassNeedsRelogin,
	}
	for input, want := range cases {
		if got := ClassifyEvidence(input); got != want {
			t.Fatalf("ClassifyEvidence(%q)=%s, want %s", input, got, want)
		}
	}
}

func TestIsInactiveSchedulableAccount(t *testing.T) {
	acc := Account{Platform: "openai", Type: "oauth", Status: "inactive", Schedulable: true}
	if !IsInactiveSchedulableAccount(acc) {
		t.Fatal("expected inactive openai oauth schedulable account to require guardian protection")
	}
	cases := []Account{
		{Platform: "openai", Type: "oauth", Status: "inactive", Schedulable: false},
		{Platform: "openai", Type: "oauth", Status: "active", Schedulable: true},
		{Platform: "gemini", Type: "oauth", Status: "inactive", Schedulable: true},
		{Platform: "openai", Type: "api_key", Status: "inactive", Schedulable: true},
		{Platform: "openai", Type: "oauth", Status: "inactive", Schedulable: true, Deleted: true},
	}
	for _, tc := range cases {
		if IsInactiveSchedulableAccount(tc) {
			t.Fatalf("expected %+v to be ignored", tc)
		}
	}
}

func TestIsGuardianCandidateAccount(t *testing.T) {
	now := time.Date(2026, 5, 22, 4, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Minute)
	future := now.Add(time.Minute)
	base := Account{
		Platform:    "openai",
		Type:        "oauth",
		Status:      "active",
		Schedulable: true,
		Credentials: map[string]any{
			"access_token": "at",
		},
	}
	cases := []struct {
		name string
		acc  Account
		want bool
	}{
		{"normal", base, false},
		{"network", withError(base, "timeout EOF"), false},
		{"network already disabled", Account{Platform: "openai", Type: "oauth", Status: "error", Schedulable: false, ErrorMessage: "Access forbidden (403): <html>Cloudflare</html>", Credentials: map[string]any{"access_token": "at"}}, true},
		{"cloudflare html disabled", Account{Platform: "openai", Type: "oauth", Status: "error", Schedulable: false, ErrorMessage: "HTTP 403: <html><title>Just a moment...</title>Cloudflare cf-ray</html>", Credentials: map[string]any{"access_token": "at"}}, true},
		{"quota", withError(base, "429 rate limit"), false},
		{"request parameter", withError(base, "unsupported model"), false},
		{"auth", withError(base, "token_revoked"), true},
		{"needs relogin", withError(base, "refresh_token_reused"), true},
		{"stale processing", Account{Platform: "openai", Type: "oauth", Status: "active", Schedulable: false, TempUnschedulableReason: "guardian processing account-internal auth failure", Credentials: map[string]any{"access_token": "at", "refresh_token": "rt"}}, true},
		{"stale deleted revive testing", Account{Platform: "openai", Type: "oauth", Status: "active", Schedulable: false, TempUnschedulableReason: "guardian: testing soft-deleted revive", Credentials: map[string]any{"access_token": "at", "refresh_token": "rt"}}, true},
		{"disabled without evidence", Account{Platform: "openai", Type: "oauth", Status: "active", Schedulable: false, Credentials: map[string]any{"access_token": "at", "refresh_token": "rt"}}, true},
		{"auth in temp reason", Account{Platform: "openai", Type: "oauth", Status: "active", Schedulable: false, TempUnschedulableReason: `token refresh retry exhausted: status 401 refresh_token_invalidated`, Credentials: map[string]any{"refresh_token": "rt"}}, true},
		{"missing access token", Account{Platform: "openai", Type: "oauth", Status: "active", Credentials: map[string]any{}}, true},
		{"expired temporary marker", withTemp(base, &expired, "OpenAI 403 temporary cooldown"), true},
		{"future temporary marker", withTemp(base, &future, "OpenAI 403 temporary cooldown"), false},
		{"old live marker", withTemp(base, nil, "confirmed live by 8001 live check"), true},
	}
	for _, tc := range cases {
		if got := IsGuardianCandidateAccount(tc.acc, now); got != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func withError(acc Account, err string) Account {
	acc.ErrorMessage = err
	return acc
}

func withTemp(acc Account, until *time.Time, reason string) Account {
	acc.TempUnschedulableUntil = until
	acc.TempUnschedulableReason = reason
	return acc
}

func TestEnvironmentHoldCandidateOnlyLiveTestsAfterRetryTime(t *testing.T) {
	now := time.Date(2026, 5, 22, 4, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Minute)
	future := now.Add(time.Minute)
	acc := Account{
		Platform:                "openai",
		Type:                    "oauth",
		Status:                  "error",
		Schedulable:             false,
		ErrorMessage:            "Access forbidden (403): <html>Cloudflare</html>",
		TempUnschedulableReason: "guardian env hold: cf_403",
		TempUnschedulableUntil:  &expired,
		Credentials:             map[string]any{"access_token": "at", "refresh_token": "rt"},
	}
	if !IsGuardianCandidateAccount(acc, now) {
		t.Fatal("expired environment hold must be scanned for live-test-only retry")
	}
	if !IsEnvironmentHoldCandidate(acc, now) {
		t.Fatal("expired environment hold must use live-test-only path")
	}
	acc.TempUnschedulableUntil = &future
	if IsGuardianCandidateAccount(acc, now) {
		t.Fatal("future environment hold must not be scanned every interval")
	}
}

func TestClassifyTestErrorSeparatesNetworkFromAuthDeath(t *testing.T) {
	cases := map[string]TestResult{
		`Access forbidden (403): <html>Cloudflare</html>`: TestInfrastructure,
		`Post "https://api.openai.com": EOF`:              TestInfrastructure,
		`API returned 401: No access token available`:     TestDead,
	}
	for input, want := range cases {
		if got := ClassifyTestError(input); got != want {
			t.Fatalf("ClassifyTestError(%q)=%s, want %s", input, got, want)
		}
	}
}

func TestClassifyTestError(t *testing.T) {
	cases := map[string]TestResult{
		"API returned 401: token_invalidated": TestDead,
		"429 usage limit":                     TestQuota,
		"EOF":                                 TestInfrastructure,
		"Unsupported parameter":               TestUnknown,
	}
	for input, want := range cases {
		if got := ClassifyTestError(input); got != want {
			t.Fatalf("ClassifyTestError(%q)=%s, want %s", input, got, want)
		}
	}
}

func TestRefreshTokenReusedIsNotTransientRefreshFailure(t *testing.T) {
	reason := `Sub2API refresh HTTP 502: {"message":"token refresh failed: status 401","code":"refresh_token_reused"}`
	if isTransientRefreshFailure(reason) {
		t.Fatal("refresh_token_reused must not be retried as transient infrastructure failure")
	}
}

func TestWaitForRefreshedAccountRetriesUntilAccessTokenAppears(t *testing.T) {
	var calls int
	load := func(ctx context.Context, id int64) (Account, error) {
		calls++
		acc := Account{
			ID:       id,
			Platform: "openai",
			Type:     "oauth",
			Status:   "active",
			Deleted:  false,
			Credentials: map[string]any{
				"refresh_token": "rt-ok",
			},
		}
		if calls >= 3 {
			acc.Credentials["access_token"] = "at-ok"
		}
		return acc, nil
	}
	acc, err := waitForRefreshedAccount(context.Background(), load, 42, 5, 0)
	if err != nil {
		t.Fatalf("waitForRefreshedAccount returned error: %v", err)
	}
	if got := acc.Credentials["access_token"]; got != "at-ok" {
		t.Fatalf("waitForRefreshedAccount access_token=%v, want at-ok", got)
	}
	if calls != 3 {
		t.Fatalf("waitForRefreshedAccount calls=%d, want 3", calls)
	}
}

func TestResolveInfrastructureAndAuthActions(t *testing.T) {
	if action, _ := resolveTestFinalAction(TestInfrastructure, "Access forbidden (403)"); action != "environment_hold" {
		t.Fatalf("infrastructure action=%q, want environment_hold", action)
	}
	if action, _ := resolveTestFinalAction(TestDead, "401"); action != "soft_deleted" {
		t.Fatalf("auth death action=%q, want soft_deleted", action)
	}
}

func TestResolveTestFinalActionHandlesNeedsRelogin(t *testing.T) {
	action, reason := resolveTestFinalAction(TestNeedsRelogin, "HTTP 401: refresh_token_reused")
	if action != "soft_deleted" {
		t.Fatalf("action=%q, want soft_deleted", action)
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestDeletedReviveStartDecisionDoesNotRefreshInfrastructure(t *testing.T) {
	acc := Account{
		Platform:     "openai",
		Type:         "oauth",
		Status:       "error",
		Deleted:      true,
		ErrorMessage: `HTTP 403: <html><title>Just a moment...</title>Cloudflare cf-ray</html>`,
		Credentials:  map[string]any{"refresh_token": "rt"},
	}
	decision := decideDeletedReviveStart(acc)
	if decision.RefreshAllowed {
		t.Fatal("soft-deleted infrastructure failures must not refresh token")
	}
	if decision.FinalAction != "deleted_kept_environment" {
		t.Fatalf("FinalAction=%q, want deleted_kept_environment", decision.FinalAction)
	}
}

func TestDeletedReviveStartDecisionAllowsDeterministicAuthDeathRefresh(t *testing.T) {
	acc := Account{
		Platform:     "openai",
		Type:         "oauth",
		Status:       "error",
		Deleted:      true,
		ErrorMessage: "deterministic auth death after revive/test: token_invalidated",
		Credentials:  map[string]any{"refresh_token": "rt"},
	}
	decision := decideDeletedReviveStart(acc)
	if !decision.RefreshAllowed {
		t.Fatalf("deterministic auth death should allow refresh, got action=%q reason=%q", decision.FinalAction, decision.FinalReason)
	}
}

func TestDeletedReviveTestDecisionKeepsInfrastructureForRetry(t *testing.T) {
	decision := decideDeletedReviveTestResult(TestInfrastructure, "HTTP 403: <html><title>Just a moment...</title>Cloudflare cf-ray</html>")
	if decision.FinalAction != "deleted_kept_environment" {
		t.Fatalf("FinalAction=%q, want deleted_kept_environment", decision.FinalAction)
	}
	if decision.ReSoftDelete {
		t.Fatal("infrastructure test failure must not re-soft-delete soft-deleted revive candidate")
	}
}

func TestDeletedReviveEnvironmentRetryReasonAllowsNextRefresh(t *testing.T) {
	reason := deletedReviveEnvironmentRetryReason("HTTP 403: Cloudflare cf-ray")
	decision := decideDeletedReviveStart(Account{
		Platform:     "openai",
		Type:         "oauth",
		Deleted:      true,
		ErrorMessage: reason,
		Credentials:  map[string]any{"refresh_token": "rt"},
	})
	if !decision.RefreshAllowed {
		t.Fatalf("environment retry soft-delete reason should allow next deleted revive refresh, got action=%q reason=%q", decision.FinalAction, decision.FinalReason)
	}
}

package guardian

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool *pgxpool.Pool
	cfg  Config
}

func NewStore(ctx context.Context, cfg Config) (*Store, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	poolConfig.ConnConfig.LookupFunc = func(ctx context.Context, host string) ([]string, error) { return []string{host}, nil }
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool, cfg: cfg}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) TryAdvisoryLock(ctx context.Context) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, s.cfg.AdvisoryLockKey).Scan(&ok)
	return ok, err
}

func (s *Store) EligibleAccounts(ctx context.Context, limit int) ([]Account, error) {
	rows, err := s.pool.Query(ctx, eligibleAccountsQuery(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		acc, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		if IsGuardianCandidateAccount(acc, time.Now()) {
			out = append(out, acc)
		}
	}
	return out, rows.Err()
}

func eligibleAccountsQuery() string {
	return `
		SELECT id, name, platform, type, status, schedulable, deleted_at IS NOT NULL AS deleted,
		       COALESCE(error_message, '') AS error_message,
		       COALESCE(credentials, '{}'::jsonb) AS credentials,
		       updated_at,
		       temp_unschedulable_until,
		       COALESCE(temp_unschedulable_reason, '') AS temp_unschedulable_reason
		FROM accounts
		WHERE deleted_at IS NULL
		  AND platform = 'openai'
		  AND type = 'oauth'
		  AND (temp_unschedulable_until IS NULL OR temp_unschedulable_until <= now())
		  AND NOT (` + quotaOrRequestParameterEvidenceSQL() + `)
		  AND NOT (schedulable = true AND (` + infrastructureEvidenceSQL() + `))
		  AND (
		    (status IN ('error', 'active', 'inactive') AND (` + accountAuthEvidenceSQL() + `))
		    OR (status IN ('error', 'active', 'inactive') AND schedulable = false AND (` + infrastructureEvidenceSQL() + `))
		    OR (status = 'inactive' AND schedulable = true)
		    OR (status = 'active' AND schedulable = false)
		    OR (temp_unschedulable_until IS NOT NULL AND temp_unschedulable_until <= now())
		    OR (COALESCE(temp_unschedulable_reason, '') <> '' AND (temp_unschedulable_until IS NULL OR temp_unschedulable_until <= now()))
		    OR NOT (COALESCE(credentials, '{}'::jsonb) ? 'access_token')
		    OR COALESCE(credentials->>'access_token', '') = ''
		  )
		ORDER BY updated_at ASC
		LIMIT $1`
}

func accountAuthEvidenceSQL() string {
	return `
		      lower(COALESCE(error_message, '')) LIKE '%401%'
		      OR lower(COALESCE(error_message, '')) LIKE '%token_revoked%'
		      OR lower(COALESCE(error_message, '')) LIKE '%token_expired%'
		      OR lower(COALESCE(error_message, '')) LIKE '%token_invalidated%'
		      OR lower(COALESCE(error_message, '')) LIKE '%refresh_token_reused%'
		      OR lower(COALESCE(error_message, '')) LIKE '%app_session_terminated%'
		      OR lower(COALESCE(error_message, '')) LIKE '%session has ended%'
		      OR lower(COALESCE(error_message, '')) LIKE '%no access token available%'
		      OR lower(COALESCE(error_message, '')) LIKE '%openai account has been deactivated%'
		      OR lower(COALESCE(error_message, '')) LIKE '%account has been deactivated%'
		      OR lower(COALESCE(error_message, '')) LIKE '%no access token%'`
}

func infrastructureEvidenceSQL() string {
	return `
		      lower(COALESCE(error_message, '')) LIKE '%cloudflare%'
		      OR lower(COALESCE(error_message, '')) LIKE '%unexpected eof%'
		      OR lower(COALESCE(error_message, '')) LIKE '%cf-ray%'
		      OR lower(COALESCE(error_message, '')) LIKE '%just a moment%'
		      OR lower(COALESCE(error_message, '')) LIKE '%attention required%'
		      OR lower(COALESCE(error_message, '')) LIKE '%unsupported_country_region_territory%'
		      OR lower(COALESCE(error_message, '')) LIKE '%country, region, or territory not supported%'
		      OR lower(COALESCE(error_message, '')) LIKE '%request_forbidden%'
		      OR lower(COALESCE(error_message, '')) LIKE '%access forbidden (403)%'
		      OR lower(COALESCE(error_message, '')) LIKE '%403 temporary cooldown%'
		      OR lower(COALESCE(error_message, '')) LIKE '%consecutive_403%'
		      OR lower(COALESCE(error_message, '')) LIKE '%timeout%'
		      OR lower(COALESCE(error_message, '')) LIKE '%timed out%'
		      OR lower(COALESCE(error_message, '')) LIKE '%deadline exceeded%'
		      OR lower(COALESCE(error_message, '')) LIKE '%tls%'
		      OR lower(COALESCE(error_message, '')) LIKE '%dns%'
		      OR lower(COALESCE(error_message, '')) LIKE '%lookup%'
		      OR lower(COALESCE(error_message, '')) LIKE '%eof%'
		      OR lower(COALESCE(error_message, '')) LIKE '%connection refused%'
		      OR lower(COALESCE(error_message, '')) LIKE '%connection reset%'
		      OR lower(COALESCE(error_message, '')) LIKE '%network%'
		      OR lower(COALESCE(error_message, '')) LIKE '%proxy%'
		      OR lower(COALESCE(error_message, '')) LIKE '%server misbehaving%'
		      OR lower(COALESCE(error_message, '')) LIKE '%temporary unavailable%'
		      OR lower(COALESCE(error_message, '')) LIKE '%status 500%'
		      OR lower(COALESCE(error_message, '')) LIKE '%status 502%'
		      OR lower(COALESCE(error_message, '')) LIKE '%status 503%'
		      OR lower(COALESCE(error_message, '')) LIKE '%status 504%'
		      OR lower(COALESCE(error_message, '')) LIKE '% 500%'
		      OR lower(COALESCE(error_message, '')) LIKE '% 502%'
		      OR lower(COALESCE(error_message, '')) LIKE '% 503%'
		      OR lower(COALESCE(error_message, '')) LIKE '% 504%'
		      OR lower(COALESCE(error_message, '')) LIKE '%upstream request failed%'
		      OR lower(COALESCE(error_message, '')) LIKE '%no terminal sse%'
		      OR lower(COALESCE(error_message, '')) LIKE '%http 500%'
		      OR lower(COALESCE(error_message, '')) LIKE '%http 502%'
		      OR lower(COALESCE(error_message, '')) LIKE '%http 503%'
		      OR lower(COALESCE(error_message, '')) LIKE '%http 504%'`
}

func quotaOrRequestParameterEvidenceSQL() string {
	return `
		    lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%429%'
		    OR lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%rate_limit%'
		    OR lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%rate limit%'
		    OR lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%usage limit%'
		    OR lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%too many request%'
		    OR lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%quota%'
		    OR lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%invalid request%'
		    OR lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%unsupported parameter%'
		    OR lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%unknown parameter%'
		    OR lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%unsupported model%'
		    OR lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%missing model%'
		    OR lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%model not found%'
		    OR lower(COALESCE(error_message, '') || ' ' || COALESCE(temp_unschedulable_reason, '')) LIKE '%disable_response_storage%'`
}

func (s *Store) AccountSummary(ctx context.Context) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE deleted_at IS NULL) AS total_active_inventory,
			COUNT(*) FILTER (WHERE deleted_at IS NULL AND status='active') AS status_active,
			COUNT(*) FILTER (WHERE deleted_at IS NULL AND status='error') AS status_error,
			COUNT(*) FILTER (WHERE deleted_at IS NULL AND schedulable=true) AS schedulable_on,
			COUNT(*) FILTER (WHERE deleted_at IS NULL AND schedulable=false) AS schedulable_off,
			COUNT(*) FILTER (WHERE deleted_at IS NOT NULL) AS soft_deleted,
			COUNT(*) FILTER (WHERE deleted_at IS NULL AND COALESCE(error_message, '') <> '') AS has_error_message
		FROM accounts
		WHERE platform='openai' AND type='oauth'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return map[string]int64{}, rows.Err()
	}
	var total, active, statusErr, schedOn, schedOff, softDeleted, hasErr int64
	if err := rows.Scan(&total, &active, &statusErr, &schedOn, &schedOff, &softDeleted, &hasErr); err != nil {
		return nil, err
	}
	return map[string]int64{
		"未删除账号": total,
		"状态正常":  active,
		"状态错误":  statusErr,
		"调度开启":  schedOn,
		"调度关闭":  schedOff,
		"已软删除":  softDeleted,
		"有错误信息": hasErr,
	}, nil
}

func (s *Store) RecentAccounts(ctx context.Context, limit int) ([]Account, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, platform, type, status, schedulable, deleted_at IS NOT NULL AS deleted,
		       COALESCE(error_message, '') AS error_message,
		       COALESCE(credentials, '{}'::jsonb) AS credentials,
		       updated_at,
		       temp_unschedulable_until,
		       COALESCE(temp_unschedulable_reason, '') AS temp_unschedulable_reason
		FROM accounts
		WHERE platform='openai' AND type='oauth'
		  AND (deleted_at IS NULL OR updated_at > now() - interval '24 hours')
		ORDER BY updated_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		acc, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, acc)
	}
	return out, rows.Err()
}

func (s *Store) DeletedReviveCandidates(ctx context.Context, limit int) ([]Account, error) {
	limitClause := ""
	args := []any{}
	if limit > 0 {
		limitClause = " LIMIT $1"
		args = append(args, limit)
	}
	rows, err := s.pool.Query(ctx, deletedReviveCandidatesQuery(limitClause), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Account
	for rows.Next() {
		acc, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, acc)
	}
	return out, rows.Err()
}

func deletedReviveCandidatesQuery(limitClause string) string {
	return `
		SELECT id, name, platform, type, status, schedulable, deleted_at IS NOT NULL AS deleted,
		       COALESCE(error_message, '') AS error_message,
		       COALESCE(credentials, '{}'::jsonb) AS credentials,
		       updated_at,
		       temp_unschedulable_until,
		       COALESCE(temp_unschedulable_reason, '') AS temp_unschedulable_reason
		FROM accounts
		WHERE deleted_at IS NOT NULL
		  AND platform = 'openai'
		  AND type = 'oauth'
		  AND COALESCE(credentials, '{}'::jsonb) ? 'refresh_token'
		ORDER BY deleted_at DESC` + limitClause
}

func (s *Store) TemporarilyRestoreForTest(ctx context.Context, id int64) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE accounts
			SET deleted_at=NULL,
			    status='active',
			    schedulable=false,
			    error_message='guardian: testing soft-deleted revive',
			    temp_unschedulable_reason='guardian: testing soft-deleted revive',
			    updated_at=now()
			WHERE id=$1`, id); err != nil {
			return err
		}
		return s.enqueueChangedTx(ctx, tx, id)
	})
}

func (s *Store) RestoreSoftDeleted(ctx context.Context, id int64) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE accounts
			SET deleted_at=NULL,
			    status='active',
			    error_message='',
			    schedulable=true,
			    temp_unschedulable_until=NULL,
			    temp_unschedulable_reason=NULL,
			    updated_at=now()
			WHERE id=$1`, id); err != nil {
			return err
		}
		if err := s.ensureGroupTx(ctx, tx, id); err != nil {
			return err
		}
		return s.enqueueChangedTx(ctx, tx, id)
	})
}

func (s *Store) ReSoftDelete(ctx context.Context, id int64, reason string) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE accounts
			SET deleted_at=now(),
			    status='error',
			    schedulable=false,
			    error_message=$2,
			    temp_unschedulable_until=NULL,
			    temp_unschedulable_reason=NULL,
			    updated_at=now()
			WHERE id=$1`, id, reason); err != nil {
			return err
		}
		return s.enqueueChangedTx(ctx, tx, id)
	})
}

func (s *Store) DisableScheduling(ctx context.Context, id int64, reason string) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE accounts
			SET schedulable=false,
			    temp_unschedulable_reason=$2,
			    updated_at=now()
			WHERE id=$1 AND deleted_at IS NULL`, id, reason); err != nil {
			return err
		}
		return s.enqueueChangedTx(ctx, tx, id)
	})
}

func (s *Store) MarkSkippedNonAccountIssue(ctx context.Context, id int64, reason string) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE accounts
			SET temp_unschedulable_reason=$2,
			    updated_at=now()
			WHERE id=$1 AND deleted_at IS NULL`, id, reason); err != nil {
			return err
		}
		return s.enqueueChangedTx(ctx, tx, id)
	})
}

func (s *Store) MarkEnvironmentHold(ctx context.Context, id int64, reason string, retryAfter time.Duration) error {
	if retryAfter <= 0 {
		retryAfter = time.Minute
	}
	retryAfterSeconds := int64(retryAfter.Seconds())
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	return s.withTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, markEnvironmentHoldSQL(), id, reason, retryAfterSeconds); err != nil {
			return err
		}
		return s.enqueueChangedTx(ctx, tx, id)
	})
}

func markEnvironmentHoldSQL() string {
	return `
			UPDATE accounts
			SET schedulable=false,
			    temp_unschedulable_until=now() + ($3 * interval '1 second'),
			    temp_unschedulable_reason=$2,
			    updated_at=now()
			WHERE id=$1 AND deleted_at IS NULL`
}

func (s *Store) GetAccount(ctx context.Context, id int64) (Account, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, platform, type, status, schedulable, deleted_at IS NOT NULL AS deleted,
		       COALESCE(error_message, '') AS error_message,
		       COALESCE(credentials, '{}'::jsonb) AS credentials,
		       updated_at,
		       temp_unschedulable_until,
		       COALESCE(temp_unschedulable_reason, '') AS temp_unschedulable_reason
		FROM accounts
		WHERE id=$1`, id)
	return scanAccount(row)
}

func scanAccount(row pgx.Row) (Account, error) {
	var acc Account
	var credBytes []byte
	err := row.Scan(&acc.ID, &acc.Name, &acc.Platform, &acc.Type, &acc.Status, &acc.Schedulable, &acc.Deleted, &acc.ErrorMessage, &credBytes, &acc.UpdatedAt, &acc.TempUnschedulableUntil, &acc.TempUnschedulableReason)
	if err != nil {
		return acc, err
	}
	if len(credBytes) == 0 {
		acc.Credentials = map[string]any{}
	} else if err := json.Unmarshal(credBytes, &acc.Credentials); err != nil {
		return acc, err
	}
	return acc, nil
}

func (s *Store) PatchCredentials(ctx context.Context, id int64, tokens OAuthTokens) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE accounts
		SET credentials = jsonb_set(
			jsonb_set(
				jsonb_set(
					jsonb_set(COALESCE(credentials, '{}'::jsonb), '{access_token}', to_jsonb($2::text), true),
					'{refresh_token}', to_jsonb($3::text), true),
				'{id_token}', to_jsonb($4::text), true),
			'{expires_in}', to_jsonb($5::int), true),
			updated_at = now()
		WHERE id=$1 AND deleted_at IS NULL`, id, tokens.AccessToken, tokens.RefreshToken, tokens.IDToken, tokens.ExpiresIn)
	return err
}

func (s *Store) PatchCredentialsAnyState(ctx context.Context, id int64, tokens OAuthTokens) error {
	cmd, err := s.pool.Exec(ctx, `
		UPDATE accounts
		SET credentials = jsonb_set(
			jsonb_set(
				jsonb_set(
					jsonb_set(COALESCE(credentials, '{}'::jsonb), '{access_token}', to_jsonb($2::text), true),
					'{refresh_token}', to_jsonb($3::text), true),
				'{id_token}', to_jsonb($4::text), true),
			'{expires_in}', to_jsonb($5::int), true),
			updated_at = now()
		WHERE id=$1`, id, tokens.AccessToken, tokens.RefreshToken, tokens.IDToken, tokens.ExpiresIn)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return fmt.Errorf("credential patch affected 0 rows")
	}
	return nil
}

func (s *Store) MarkLive(ctx context.Context, id int64) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE accounts
			SET status='active', error_message='', schedulable=true,
			    temp_unschedulable_until=NULL, temp_unschedulable_reason=NULL,
			    deleted_at=NULL, updated_at=now()
			WHERE id=$1`, id); err != nil {
			return err
		}
		if err := s.ensureGroupTx(ctx, tx, id); err != nil {
			return err
		}
		return s.enqueueChangedTx(ctx, tx, id)
	})
}

func (s *Store) KeepQuota(ctx context.Context, id int64) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, keepQuotaSQL(), id); err != nil {
			return err
		}
		if err := s.ensureGroupTx(ctx, tx, id); err != nil {
			return err
		}
		return s.enqueueChangedTx(ctx, tx, id)
	})
}

func keepQuotaSQL() string {
	return `
			UPDATE accounts
			SET status='active',
			    error_message='',
			    schedulable=CASE
			      WHEN COALESCE(temp_unschedulable_reason, '') LIKE 'guardian%' THEN true
			      ELSE schedulable
			    END,
			    temp_unschedulable_until=CASE
			      WHEN COALESCE(temp_unschedulable_reason, '') LIKE 'guardian%' THEN NULL
			      ELSE temp_unschedulable_until
			    END,
			    temp_unschedulable_reason=CASE
			      WHEN COALESCE(temp_unschedulable_reason, '') LIKE 'guardian%' THEN NULL
			      ELSE temp_unschedulable_reason
			    END,
			    updated_at=now()
			WHERE id=$1 AND deleted_at IS NULL`
}

func (s *Store) SoftDelete(ctx context.Context, id int64, reason string) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		cmd, err := tx.Exec(ctx, `
			UPDATE accounts
			SET deleted_at=now(), status='error', schedulable=false,
			    temp_unschedulable_until=NULL, temp_unschedulable_reason=NULL,
			    error_message=$2, updated_at=now()
			WHERE id=$1 AND deleted_at IS NULL`, id, reason)
		if err != nil {
			return err
		}
		if cmd.RowsAffected() == 0 {
			return fmt.Errorf("soft delete affected 0 rows")
		}
		return s.enqueueChangedTx(ctx, tx, id)
	})
}

func (s *Store) ensureGroupTx(ctx context.Context, tx pgx.Tx, id int64) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO account_groups(account_id, group_id, priority)
		VALUES($1, $2, 1)
		ON CONFLICT DO NOTHING`, id, s.cfg.OpenAIGroupID)
	return err
}

func (s *Store) enqueueChangedTx(ctx context.Context, tx pgx.Tx, id int64) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO scheduler_outbox(event_type, account_id, payload, created_at)
		VALUES('account_changed', $1, NULL, now())`, id)
	return err
}

func (s *Store) withTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) Listen(ctx context.Context, out chan<- int64) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `LISTEN `+pgx.Identifier{s.cfg.ListenChannel}.Sanitize()); err != nil {
		return err
	}
	for {
		n, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var payload struct {
			AccountID int64 `json:"account_id"`
		}
		if err := json.Unmarshal([]byte(n.Payload), &payload); err == nil && payload.AccountID > 0 {
			select {
			case out <- payload.AccountID:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func (s *Store) Now(ctx context.Context) (time.Time, error) {
	var t time.Time
	err := s.pool.QueryRow(ctx, `SELECT now()`).Scan(&t)
	return t, err
}

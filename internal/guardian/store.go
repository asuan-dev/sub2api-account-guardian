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
		if IsEligibleAccount(acc.Platform, acc.Type, acc.Status, acc.Deleted, acc.ErrorMessage) || IsInactiveSchedulableAccount(acc) {
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
		       updated_at
		FROM accounts
		WHERE deleted_at IS NULL
		  AND platform = 'openai'
		  AND type = 'oauth'
		  AND (
		    (status IN ('error', 'active', 'inactive') AND COALESCE(error_message, '') <> '')
		    OR (status = 'inactive' AND schedulable = true)
		  )
		ORDER BY updated_at ASC
		LIMIT $1`
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
		       updated_at
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
		       updated_at
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

func (s *Store) MarkNeedsRelogin(ctx context.Context, id int64, reason string) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE accounts
			SET status='active',
			    schedulable=false,
			    error_message=$2,
			    temp_unschedulable_until=NULL,
			    temp_unschedulable_reason='guardian: needs manual relogin',
			    updated_at=now()
			WHERE id=$1 AND deleted_at IS NULL`, id, reason); err != nil {
			return err
		}
		return s.enqueueChangedTx(ctx, tx, id)
	})
}

func (s *Store) GetAccount(ctx context.Context, id int64) (Account, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, platform, type, status, schedulable, deleted_at IS NOT NULL AS deleted,
		       COALESCE(error_message, '') AS error_message,
		       COALESCE(credentials, '{}'::jsonb) AS credentials,
		       updated_at
		FROM accounts
		WHERE id=$1`, id)
	return scanAccount(row)
}

func scanAccount(row pgx.Row) (Account, error) {
	var acc Account
	var credBytes []byte
	err := row.Scan(&acc.ID, &acc.Name, &acc.Platform, &acc.Type, &acc.Status, &acc.Schedulable, &acc.Deleted, &acc.ErrorMessage, &credBytes, &acc.UpdatedAt)
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
		if _, err := tx.Exec(ctx, `
			UPDATE accounts
			SET status='active', error_message='', schedulable=true, updated_at=now()
			WHERE id=$1 AND deleted_at IS NULL`, id); err != nil {
			return err
		}
		if err := s.ensureGroupTx(ctx, tx, id); err != nil {
			return err
		}
		return s.enqueueChangedTx(ctx, tx, id)
	})
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

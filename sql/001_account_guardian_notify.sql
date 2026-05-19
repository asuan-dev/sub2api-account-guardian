-- Sub2API Account Guardian wake-up trigger.
-- Safe to re-run. Does not modify Sub2API source code.

CREATE OR REPLACE FUNCTION public.notify_sub2api_account_guardian()
RETURNS trigger AS $$
DECLARE
  msg text := lower(coalesce(NEW.error_message, ''));
  eligible boolean := false;
BEGIN
  IF NEW.deleted_at IS NOT NULL THEN
    RETURN NEW;
  END IF;
  IF NEW.platform <> 'openai' OR NEW.type <> 'oauth' OR NEW.status NOT IN ('error', 'active') THEN
    RETURN NEW;
  END IF;

  -- Account-internal auth evidence only. Infrastructure, quota, and request-shape errors are intentionally excluded.
  eligible :=
    msg LIKE '%token_invalidated%' OR
    msg LIKE '%token_revoked%' OR
    msg LIKE '%token revoked%' OR
    msg LIKE '%authentication token has been invalidated%' OR
    msg LIKE '%encountered invalidated oauth token%' OR
    msg LIKE '%provided authentication token is expired%' OR
    msg LIKE '%authentication failed (401)%' OR
    msg LIKE '%oauth 401%' OR
    msg LIKE '%invalid or expired credentials%' OR
    msg LIKE '%invalid_grant%' OR
    msg LIKE '%invalid refresh%' OR
    msg LIKE '%refresh token is invalid%' OR
    msg LIKE '%refresh token expired%' OR
    msg LIKE '%refresh_token_reused%' OR
    msg LIKE '%token_expired%' OR
    msg LIKE '%unauthorized (401)%';

  IF eligible THEN
    PERFORM pg_notify(
      'sub2api_account_error',
      json_build_object(
        'account_id', NEW.id,
        'status', NEW.status,
        'updated_at', NEW.updated_at,
        'source', 'accounts_trigger'
      )::text
    );
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sub2api_account_guardian_notify ON public.accounts;

CREATE TRIGGER trg_sub2api_account_guardian_notify
AFTER INSERT OR UPDATE OF status, error_message, deleted_at, schedulable ON public.accounts
FOR EACH ROW
EXECUTE FUNCTION public.notify_sub2api_account_guardian();

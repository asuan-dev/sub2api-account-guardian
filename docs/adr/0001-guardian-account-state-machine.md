# ADR 0001: Guardian account state machine

## Status

Accepted

## Context

Sub2API may mark accounts with a mix of account credential failures, rate limits, request-shape errors, and infrastructure/network errors. Previous Guardian logic had multiple partial branches. A known bad path was:

```text
classify = infrastructure -> disable_scheduling -> refresh token -> test
```

That is unsafe because Cloudflare/403/proxy/TLS/DNS errors can be caused by the current node or network, not by a dead account. Refreshing or deleting accounts during an environment failure risks damaging good accounts.

## Decision

Guardian uses one pipeline:

```text
scan account -> classify evidence -> decide action -> execute action -> audit
```

### Error/state handling table

| Evidence | Canonical class | First action | Follow-up |
|---|---|---|---|
| `token_invalidated`, `token_revoked`, `token_expired`, `401`, `No access token available` | Account auth failure | Disable scheduling | Refresh token, then test `gpt-5.4-mini`; live restores scheduling, confirmed auth death soft-deletes |
| `app_session_terminated`, `refresh_token_reused`, `please log in again` | Manual relogin / unrecoverable auth | Disable scheduling | Soft-delete unless a later explicit live test proves usable |
| `429`, `rate_limit`, `quota`, `usage limit` | Quota/rate-limit | Do not process | Leave to Sub2API |
| `Access forbidden (403)`, `request_forbidden`, `unsupported_country_region_territory`, Cloudflare HTML, timeout, EOF, TLS, DNS, 5xx, proxy | Environment/network failure | Mark environment hold / keep scheduling off | Do not refresh or delete; later only live-test. If live, restore. If still network, extend hold. If it becomes auth failure, enter revive flow |
| unsupported parameter/model/request shape | Request problem | Do not process | Leave untouched |
| Unknown | Unknown | Keep disabled only if already disabled | Audit; no refresh/delete |

### Invariants

1. Environment/network failure must never call OAuth refresh.
2. Environment/network failure must never soft-delete.
3. Quota/rate-limit must not be changed by Guardian.
4. A disabled account may be restored only after a successful Sub2API live test.
5. An account may be soft-deleted only after deterministic account-internal death evidence, not after transport errors.
6. If a network error occurs during testing, the account enters environment hold and waits for a later retry instead of continuing revive/delete.

## Consequences

- Guardian becomes more conservative during node/Cloudflare issues.
- Some temporarily disabled accounts may stay unavailable until the environment recovers and Guardian re-tests them.
- The code should prefer explicit decision functions over scattered `if` branches.

# Sub2API Account Guardian Context

## Glossary

- **Account**: A Sub2API `accounts` row for an OpenAI OAuth account.
- **Schedulable account**: An account with `schedulable=true`; Sub2API may route user API requests to it.
- **Problem account**: A non-deleted OpenAI OAuth account whose current status, error text, temporary scheduling marker, or missing access token requires Guardian classification.
- **Account-internal auth failure**: Evidence that the account credential/session itself is bad, such as 401, invalidated token, expired token, missing access token with refresh token, session ended, or refresh token reuse.
- **Environment/network failure**: Evidence that the node, proxy, DNS, TLS, Cloudflare, OpenAI edge, or upstream transport is failing. This is not account death.
- **Quota/rate-limit state**: Evidence such as 429, quota exhausted, rate limit, or usage limit. Guardian does not clean this; Sub2API owns cooldown/recovery.
- **Environment hold**: Guardian has disabled scheduling or kept scheduling disabled because the last evidence was environment/network failure. It must not refresh token or soft-delete while in this state.
- **Revive**: Refreshing OAuth tokens, writing refreshed credentials back to Sub2API DB, then proving the account with a Sub2API model test.
- **Soft delete**: Setting `deleted_at` on an account so Sub2API stops using it while preserving the row for audit or later manual recovery.

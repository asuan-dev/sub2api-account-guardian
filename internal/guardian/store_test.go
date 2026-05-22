package guardian

import (
	"strings"
	"testing"
)

func TestDeletedReviveCandidatesQueryIncludesAllSoftDeletedRefreshTokenAccounts(t *testing.T) {
	query := deletedReviveCandidatesQuery("")
	if strings.Contains(query, "deleted_at >= now()") {
		t.Fatalf("query should not restrict deleted revive candidates by deleted_at: %s", query)
	}
	if !strings.Contains(query, "deleted_at IS NOT NULL") {
		t.Fatalf("query should only include soft-deleted accounts: %s", query)
	}
	if !strings.Contains(query, "COALESCE(credentials, '{}'::jsonb) ? 'refresh_token'") {
		t.Fatalf("query should only include accounts with refresh_token: %s", query)
	}
}

func TestEligibleAccountsQueryIncludesInactiveSchedulableAccounts(t *testing.T) {
	query := eligibleAccountsQuery()
	if !strings.Contains(query, "status = 'inactive' AND schedulable = true") {
		t.Fatalf("query should include inactive schedulable accounts for scheduling protection: %s", query)
	}
	if !strings.Contains(query, "status = 'active' AND schedulable = false") {
		t.Fatalf("query should include active unschedulable accounts for live-test recovery: %s", query)
	}
	if strings.Contains(query, "OR temp_unschedulable_until IS NOT NULL") {
		t.Fatalf("query must not let future environment holds consume LIMIT before Go filtering: %s", query)
	}
	if !strings.Contains(query, "temp_unschedulable_until <= now()") {
		t.Fatalf("query should include only due temporary unschedulable accounts for expiry handling: %s", query)
	}
	if strings.Contains(query, "OR COALESCE(temp_unschedulable_reason, '') <> ''") {
		t.Fatalf("query must not let any non-empty temporary reason consume LIMIT before Go filtering: %s", query)
	}
	if !strings.Contains(query, "(COALESCE(temp_unschedulable_reason, '') <> '' AND (temp_unschedulable_until IS NULL OR temp_unschedulable_until <= now()))") {
		t.Fatalf("query should include reason-only or due temporary unschedulable markers without selecting future holds: %s", query)
	}
	if !strings.Contains(query, "access_token") {
		t.Fatalf("query should include missing access token candidates: %s", query)
	}
	if strings.Contains(query, "status IN ('error', 'active', 'inactive') AND COALESCE(error_message, '') <> ''") {
		t.Fatalf("query must not let quota/request-parameter error rows consume LIMIT before Go filtering: %s", query)
	}
	if !strings.Contains(query, "refresh_token_reused") || !strings.Contains(query, "token_revoked") {
		t.Fatalf("query should include deterministic account-auth error candidates in SQL: %s", query)
	}
	if !strings.Contains(query, "schedulable = false AND (") || !strings.Contains(query, "cloudflare") || !strings.Contains(query, "timeout") {
		t.Fatalf("query should only include infrastructure evidence when scheduling is already disabled: %s", query)
	}
	if !strings.Contains(query, "NOT (schedulable = true AND (") {
		t.Fatalf("query should exclude schedulable infrastructure rows before any broad branch can consume LIMIT: %s", query)
	}
	for _, marker := range []string{"%deadline exceeded%", "%dns%", "%lookup%", "%network%", "%proxy%", "%status 500%", "%request_forbidden%", "%access forbidden (403)%", "%403 temporary cooldown%"} {
		if !strings.Contains(query, marker) {
			t.Fatalf("query should align SQL infrastructure evidence with classifier marker %s: %s", marker, query)
		}
	}
	if !strings.Contains(query, "NOT (") || !strings.Contains(query, "rate limit") || !strings.Contains(query, "usage limit") {
		t.Fatalf("query should SQL-exclude quota/request-parameter evidence from all broad candidate branches before LIMIT: %s", query)
	}
	for _, marker := range []string{"%429%", "%rate_limit%", "%rate limit%", "%usage limit%", "%too many request%", "%unsupported parameter%", "%unknown parameter%", "%unsupported model%", "%missing model%", "%model not found%"} {
		if !strings.Contains(query, marker) {
			t.Fatalf("query should exclude %s evidence before broad branches can consume LIMIT: %s", marker, query)
		}
	}
}

func TestMarkEnvironmentHoldUsesPostgresSafeInterval(t *testing.T) {
	query := markEnvironmentHoldSQL()
	if !strings.Contains(query, "$3 * interval '1 second'") {
		t.Fatalf("environment hold should use numeric seconds interval, got: %s", query)
	}
}

func TestKeepQuotaDoesNotClearSub2APICooldown(t *testing.T) {
	query := keepQuotaSQL()
	if !strings.Contains(query, "ELSE temp_unschedulable_until") {
		t.Fatalf("quota handling must preserve Sub2API cooldown until, got: %s", query)
	}
	if !strings.Contains(query, "ELSE temp_unschedulable_reason") {
		t.Fatalf("quota handling must preserve Sub2API cooldown reason, got: %s", query)
	}
}

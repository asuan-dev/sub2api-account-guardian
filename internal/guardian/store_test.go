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
}

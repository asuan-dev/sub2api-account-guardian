package guardian

import (
	"context"
	"testing"
)

func TestClassifyEvidenceTreatsAccountInternalAuthAsEligible(t *testing.T) {
	cases := []string{
		"Token revoked (401): Encountered invalidated oauth token for user, failing request",
		"Authentication failed (401): token_invalidated",
		"Provided authentication token is expired. Please try signing in again.",
		"invalid_grant: refresh token expired",
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
		`Recovered upstream error 429: The usage limit has been reached`:                 ClassQuota,
		`Unsupported parameter: disable_response_storage`:                                ClassRequestParameter,
		`HTTP 401: code refresh_token_reused`:                                             ClassNeedsRelogin,
		`Your session has ended. Please log in again. code app_session_terminated`:       ClassNeedsRelogin,
	}
	for input, want := range cases {
		if got := ClassifyEvidence(input); got != want {
			t.Fatalf("ClassifyEvidence(%q)=%s, want %s", input, got, want)
		}
	}
}

func TestIsEligibleAccountRequiresOpenAIOAuthErrorNotDeleted(t *testing.T) {
	if !IsEligibleAccount("openai", "oauth", "error", false, "token_invalidated") {
		t.Fatal("expected openai oauth error account with auth evidence to be eligible")
	}
	if !IsEligibleAccount("openai", "oauth", "active", false, "token_expired") {
		t.Fatal("expected openai oauth active account with auth evidence to be eligible")
	}
	if !IsEligibleAccount("openai", "oauth", "inactive", false, "Authentication failed (401): token_revoked") {
		t.Fatal("expected inactive openai oauth account with auth evidence to be eligible")
	}
	cases := []struct {
		platform string
		typeName string
		status   string
		deleted  bool
		err      string
	}{
		{"gemini", "oauth", "error", false, "token_invalidated"},
		{"openai", "api_key", "error", false, "token_invalidated"},
		{"openai", "oauth", "active", false, ""},
		{"openai", "oauth", "disabled", false, "token_invalidated"},
		{"openai", "oauth", "error", true, "token_invalidated"},
		{"openai", "oauth", "error", false, "EOF"},
		{"openai", "oauth", "error", false, "429 usage limit"},
		{"openai", "oauth", "active", false, "needs manual relogin: app_session_terminated"},
	}
	for _, tc := range cases {
		if IsEligibleAccount(tc.platform, tc.typeName, tc.status, tc.deleted, tc.err) {
			t.Fatalf("expected %+v to be ineligible", tc)
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

func TestClassifyTestError(t *testing.T) {
	cases := map[string]TestResult{
		"API returned 401: token_invalidated": TestDead,
		"429 usage limit":                     TestQuota,
		"EOF":                                 TestUnknown,
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

func TestResolveTestFinalActionHandlesNeedsRelogin(t *testing.T) {
	action, reason := resolveTestFinalAction(TestNeedsRelogin, "HTTP 401: refresh_token_reused")
	if action != "needs_relogin" {
		t.Fatalf("action=%q, want needs_relogin", action)
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

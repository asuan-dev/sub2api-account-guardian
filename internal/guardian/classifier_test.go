package guardian

import "testing"

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

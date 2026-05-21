package guardian

import "strings"

type EvidenceClass string

const (
	ClassEligibleAuth     EvidenceClass = "eligible_auth"
	ClassInfrastructure   EvidenceClass = "infrastructure"
	ClassQuota            EvidenceClass = "quota"
	ClassRequestParameter EvidenceClass = "request_parameter"
	ClassNeedsRelogin     EvidenceClass = "needs_relogin"
	ClassNotEligible      EvidenceClass = "not_eligible"
)

type TestResult string

const (
	TestOK           TestResult = "ok"
	TestDead         TestResult = "dead"
	TestQuota        TestResult = "quota"
	TestNeedsRelogin TestResult = "needs_relogin"
	TestUnknown      TestResult = "unknown"
)

var quotaMarkers = []string{
	"429",
	"rate_limit",
	"rate limit",
	"too many request",
	"too many requests",
	"usage limit",
	"quota",
	"quota_exhausted",
	"quota exhausted",
}

var requestParameterMarkers = []string{
	"unsupported parameter",
	"disable_response_storage",
	"invalid request",
	"unknown parameter",
	"missing model",
	"model not found",
	"unsupported model",
}

var needsReloginMarkers = []string{
	"app_session_terminated",
	"your session has ended",
	"please log in again",
	"requires relogin",
	"needs relogin",
	"need relogin",
	"重新登录",
	"refresh_token_reused",
}

var infrastructureMarkers = []string{
	"eof",
	"unexpected eof",
	"timeout",
	"timed out",
	"deadline exceeded",
	"tls",
	"dns",
	"lookup",
	"connection refused",
	"connection reset",
	"network",
	"proxy",
	"server misbehaving",
	"temporary unavailable",
	"status 500",
	"status 502",
	"status 503",
	"status 504",
	" 500",
	" 502",
	" 503",
	" 504",
	"upstream request failed",
	"no terminal sse",
	"http 500",
	"http 502",
	"http 503",
	"http 504",
}

var authMarkers = []string{
	"token_invalidated",
	"token_revoked",
	"token revoked",
	"authentication token has been invalidated",
	"encountered invalidated oauth token",
	"provided authentication token is expired",
	"authentication failed (401)",
	"oauth 401",
	"invalid or expired credentials",
	"invalid_grant",
	"invalid refresh",
	"refresh token is invalid",
	"refresh token expired",
	"token_expired",
	"unauthorized (401)",
}

func ClassifyEvidence(values ...string) EvidenceClass {
	text := normalize(values...)
	if text == "" {
		return ClassNotEligible
	}
	if containsAny(text, quotaMarkers) {
		return ClassQuota
	}
	if containsAny(text, requestParameterMarkers) {
		return ClassRequestParameter
	}
	if containsAny(text, needsReloginMarkers) {
		return ClassNeedsRelogin
	}
	if containsAny(text, infrastructureMarkers) {
		return ClassInfrastructure
	}
	if containsAny(text, authMarkers) {
		return ClassEligibleAuth
	}
	if strings.Contains(text, "401") || strings.Contains(text, "http 401") || strings.Contains(text, "status 401") {
		return ClassEligibleAuth
	}
	return ClassNotEligible
}

func ClassifyTestError(errText string) TestResult {
	text := normalize(errText)
	if text == "" {
		return TestUnknown
	}
	cls := ClassifyEvidence(text)
	switch cls {
	case ClassEligibleAuth:
		return TestDead
	case ClassQuota:
		return TestQuota
	case ClassNeedsRelogin:
		return TestNeedsRelogin
	case ClassInfrastructure, ClassRequestParameter, ClassNotEligible:
		return TestUnknown
	default:
		return TestUnknown
	}
}

func IsEligibleAccount(platform, accountType, status string, deleted bool, errorText string) bool {
	return isEligibleBaseAccount(platform, accountType, status, deleted, errorText) && ClassifyEvidence(errorText) == ClassEligibleAuth
}

func IsRefreshableMissingAccessTokenAccount(acc Account) bool {
	if !isEligibleBaseAccount(acc.Platform, acc.Type, acc.Status, acc.Deleted, acc.ErrorMessage) {
		return false
	}
	accessToken, _ := acc.Credentials["access_token"].(string)
	refreshToken, _ := acc.Credentials["refresh_token"].(string)
	return strings.TrimSpace(accessToken) == "" && strings.TrimSpace(refreshToken) != ""
}

func IsInactiveSchedulableAccount(acc Account) bool {
	if acc.Deleted || !acc.Schedulable {
		return false
	}
	if strings.ToLower(strings.TrimSpace(acc.Platform)) != "openai" {
		return false
	}
	if strings.ToLower(strings.TrimSpace(acc.Type)) != "oauth" {
		return false
	}
	return strings.ToLower(strings.TrimSpace(acc.Status)) == "inactive"
}

func isEligibleBaseAccount(platform, accountType, status string, deleted bool, errorText string) bool {
	if deleted {
		return false
	}
	if strings.HasPrefix(strings.TrimSpace(strings.ToLower(errorText)), "deterministic auth death after revive/test:") {
		return false
	}
	if strings.HasPrefix(strings.TrimSpace(strings.ToLower(errorText)), "needs manual relogin:") {
		return false
	}
	if strings.ToLower(strings.TrimSpace(platform)) != "openai" {
		return false
	}
	if strings.ToLower(strings.TrimSpace(accountType)) != "oauth" {
		return false
	}
	normalizedStatus := strings.ToLower(strings.TrimSpace(status))
	if normalizedStatus != "error" && normalizedStatus != "active" && normalizedStatus != "inactive" {
		return false
	}
	return true
}

func normalize(values ...string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value != "" {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, "\n")
}

func containsAny(text string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

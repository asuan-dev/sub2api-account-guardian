package guardian

import (
	"strings"
	"time"
)

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
	TestOK             TestResult = "ok"
	TestDead           TestResult = "dead"
	TestQuota          TestResult = "quota"
	TestNeedsRelogin   TestResult = "needs_relogin"
	TestInfrastructure TestResult = "infrastructure"
	TestUnknown        TestResult = "unknown"
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
	"unsupported_country_region_territory",
	"country, region, or territory not supported",
	"request_forbidden",
	"access forbidden (403)",
	"403 temporary cooldown",
	"consecutive_403",
	"cloudflare",
	"cf-ray",
	"just a moment",
	"attention required",
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
	"no access token available",
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
	case ClassInfrastructure:
		return TestInfrastructure
	case ClassRequestParameter, ClassNotEligible:
		return TestUnknown
	default:
		return TestUnknown
	}
}

func IsRefreshableMissingAccessTokenAccount(acc Account) bool {
	if !isEligibleBaseAccount(acc.Platform, acc.Type, acc.Status, acc.Deleted, acc.ErrorMessage) {
		return false
	}
	return HasMissingAccessToken(acc)
}

func HasMissingAccessToken(acc Account) bool {
	accessToken, _ := acc.Credentials["access_token"].(string)
	refreshToken, _ := acc.Credentials["refresh_token"].(string)
	return strings.TrimSpace(accessToken) == "" && strings.TrimSpace(refreshToken) != ""
}

func HasNoAccessToken(acc Account) bool {
	accessToken, _ := acc.Credentials["access_token"].(string)
	return strings.TrimSpace(accessToken) == ""
}

func IsGuardianCandidateAccount(acc Account, now time.Time) bool {
	if acc.Deleted {
		return false
	}
	if strings.ToLower(strings.TrimSpace(acc.Platform)) != "openai" {
		return false
	}
	if strings.ToLower(strings.TrimSpace(acc.Type)) != "oauth" {
		return false
	}
	if strings.TrimSpace(acc.TempUnschedulableReason) == "confirmed live by 8001 live check" {
		return true
	}
	if IsGuardianProcessingStale(acc) {
		return true
	}
	if IsDisabledWithoutEvidence(acc) {
		return true
	}
	if IsEnvironmentHoldCandidate(acc, now) {
		return true
	}
	if IsFutureEnvironmentHold(acc, now) {
		return false
	}
	cls := ClassifyEvidence(acc.ErrorMessage, acc.TempUnschedulableReason)
	switch cls {
	case ClassInfrastructure:
		return !acc.Schedulable
	case ClassQuota, ClassRequestParameter:
		return false
	case ClassEligibleAuth, ClassNeedsRelogin:
		return true
	}
	if IsInactiveSchedulableAccount(acc) || HasNoAccessToken(acc) {
		return true
	}
	return false
}

func IsEnvironmentHoldCandidate(acc Account, now time.Time) bool {
	if acc.Deleted {
		return false
	}
	if strings.ToLower(strings.TrimSpace(acc.Platform)) != "openai" {
		return false
	}
	if strings.ToLower(strings.TrimSpace(acc.Type)) != "oauth" {
		return false
	}
	reason := strings.ToLower(strings.TrimSpace(acc.TempUnschedulableReason))
	isEnvHold := strings.HasPrefix(reason, "guardian env hold:") ||
		(acc.TempUnschedulableUntil != nil && ClassifyEvidence(acc.ErrorMessage, acc.TempUnschedulableReason) == ClassInfrastructure)
	if !isEnvHold {
		return false
	}
	if acc.TempUnschedulableUntil == nil {
		return true
	}
	return !acc.TempUnschedulableUntil.After(now)
}

func IsFutureEnvironmentHold(acc Account, now time.Time) bool {
	if acc.TempUnschedulableUntil == nil {
		return false
	}
	if !acc.TempUnschedulableUntil.After(now) {
		return false
	}
	reason := strings.ToLower(strings.TrimSpace(acc.TempUnschedulableReason))
	return strings.HasPrefix(reason, "guardian env hold:") ||
		ClassifyEvidence(acc.ErrorMessage, acc.TempUnschedulableReason) == ClassInfrastructure
}

func IsGuardianProcessingStale(acc Account) bool {
	reason := strings.ToLower(strings.TrimSpace(acc.TempUnschedulableReason))
	return !acc.Deleted &&
		strings.ToLower(strings.TrimSpace(acc.Platform)) == "openai" &&
		strings.ToLower(strings.TrimSpace(acc.Type)) == "oauth" &&
		!acc.Schedulable &&
		(strings.Contains(reason, "guardian processing") ||
			strings.Contains(reason, "guardian: testing soft-deleted revive"))
}

func IsDisabledWithoutEvidence(acc Account) bool {
	return !acc.Deleted &&
		strings.ToLower(strings.TrimSpace(acc.Platform)) == "openai" &&
		strings.ToLower(strings.TrimSpace(acc.Type)) == "oauth" &&
		strings.ToLower(strings.TrimSpace(acc.Status)) == "active" &&
		!acc.Schedulable &&
		strings.TrimSpace(acc.ErrorMessage) == "" &&
		strings.TrimSpace(acc.TempUnschedulableReason) == ""
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

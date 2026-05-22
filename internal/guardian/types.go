package guardian

import (
	"encoding/json"
	"time"
)

type Account struct {
	ID                      int64
	Name                    string
	Platform                string
	Type                    string
	Status                  string
	Schedulable             bool
	Deleted                 bool
	ErrorMessage            string
	Credentials             map[string]any
	UpdatedAt               time.Time
	TempUnschedulableUntil  *time.Time
	TempUnschedulableReason string
}

type AuditRecord struct {
	AccountID           int64         `json:"account_id"`
	AccountName         string        `json:"account_name"`
	InitialStatus       string        `json:"initial_status"`
	InitialErrorMessage string        `json:"initial_error_message"`
	Classification      EvidenceClass `json:"classification"`
	RefreshAttempted    bool          `json:"refresh_attempted"`
	RefreshResult       string        `json:"refresh_result"`
	RefreshReason       string        `json:"refresh_reason"`
	SchedulingDisabled  bool          `json:"scheduling_disabled"`
	TestResult          TestResult    `json:"test_result"`
	TestReason          string        `json:"test_reason"`
	FinalAction         string        `json:"final_action"`
	FinalReason         string        `json:"final_reason"`
	StartedAt           time.Time     `json:"started_at"`
	FinishedAt          time.Time     `json:"finished_at"`
	DryRun              bool          `json:"dry_run"`
}

type OAuthTokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresIn    int
	Raw          map[string]any
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

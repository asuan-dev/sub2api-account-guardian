package guardian

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type PanelConfig struct {
	Sub2APIURL             string `json:"sub2api_url"`
	Sub2APIKey             string `json:"sub2api_key"`
	DatabaseURL            string `json:"database_url"`
	PostgresHost           string `json:"postgres_host"`
	PostgresPort           string `json:"postgres_port"`
	PostgresDB             string `json:"postgres_db"`
	PostgresUser           string `json:"postgres_user"`
	PostgresPassword       string `json:"postgres_password"`
	TestModel              string `json:"test_model"`
	OpenAIGroupID          int64  `json:"openai_group_id"`
	MonitorIntervalSeconds int    `json:"monitor_interval_seconds"`
	MonitorBatchSize       int    `json:"monitor_batch_size"`
	TestWorkers            int    `json:"test_workers"`
	RefreshWorkers         int    `json:"refresh_workers"`
	RetryAttempts          int    `json:"retry_attempts"`
	RetryDelayMS           int    `json:"retry_delay_ms"`
	DryRun                 bool   `json:"dry_run"`
	UpdatedAt              string `json:"updated_at"`
}

func applyConfigFile(cfg *Config) error {
	if cfg.ConfigPath == "" {
		return nil
	}
	b, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var pc PanelConfig
	if err := json.Unmarshal(b, &pc); err != nil {
		return err
	}
	if pc.Sub2APIURL != "" {
		cfg.Sub2APIURL = pc.Sub2APIURL
	}
	if pc.Sub2APIKey != "" {
		cfg.Sub2APIKey = pc.Sub2APIKey
	}
	if pc.DatabaseURL != "" {
		cfg.DatabaseURL = pc.DatabaseURL
	}
	if pc.TestModel != "" {
		cfg.TestModel = pc.TestModel
	}
	if pc.OpenAIGroupID > 0 {
		cfg.OpenAIGroupID = pc.OpenAIGroupID
	}
	if pc.MonitorIntervalSeconds > 0 {
		cfg.Interval = time.Duration(pc.MonitorIntervalSeconds) * time.Second
	}
	if pc.MonitorBatchSize > 0 {
		cfg.BatchSize = pc.MonitorBatchSize
	}
	if pc.TestWorkers > 0 {
		cfg.TestWorkers = pc.TestWorkers
	}
	if pc.RefreshWorkers > 0 {
		cfg.RefreshWorkers = pc.RefreshWorkers
	}
	if pc.RetryAttempts > 0 {
		cfg.RetryAttempts = pc.RetryAttempts
	}
	if pc.RetryDelayMS > 0 {
		cfg.RetryDelay = time.Duration(pc.RetryDelayMS) * time.Millisecond
	}
	cfg.DryRun = pc.DryRun
	return nil
}

func (cfg Config) PanelConfig() PanelConfig {
	return PanelConfig{
		Sub2APIURL:             cfg.Sub2APIURL,
		Sub2APIKey:             maskSecret(cfg.Sub2APIKey),
		DatabaseURL:            maskDatabaseURL(cfg.DatabaseURL),
		TestModel:              cfg.TestModel,
		OpenAIGroupID:          cfg.OpenAIGroupID,
		MonitorIntervalSeconds: int(cfg.Interval / time.Second),
		MonitorBatchSize:       cfg.BatchSize,
		TestWorkers:            cfg.TestWorkers,
		RefreshWorkers:         cfg.RefreshWorkers,
		RetryAttempts:          cfg.RetryAttempts,
		RetryDelayMS:           int(cfg.RetryDelay / time.Millisecond),
		DryRun:                 cfg.DryRun,
	}
}

func SavePanelConfig(path string, pc PanelConfig) error {
	pc.UpdatedAt = time.Now().Format(time.RFC3339)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(pc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0600)
}

func maskSecret(s string) string {
	if len(s) <= 10 {
		if s == "" {
			return ""
		}
		return "***"
	}
	return s[:8] + "..." + s[len(s)-4:]
}

func maskDatabaseURL(s string) string {
	if s == "" {
		return ""
	}
	at := -1
	for i := range s {
		if s[i] == '@' {
			at = i
			break
		}
	}
	if at <= 0 {
		return s
	}
	schemeEnd := -1
	for i := 0; i+2 < len(s); i++ {
		if s[i:i+3] == "://" {
			schemeEnd = i + 3
			break
		}
	}
	if schemeEnd < 0 || schemeEnd >= at {
		return "***" + s[at:]
	}
	return s[:schemeEnd] + "***" + s[at:]
}

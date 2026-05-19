package guardian

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL     string
	Sub2APIURL      string
	Sub2APIKey      string
	TestModel       string
	OpenAIClientID  string
	OpenAITokenURL  string
	OpenAIGroupID   int64
	Interval        time.Duration
	BatchSize       int
	TestWorkers     int
	RefreshWorkers  int
	RetryAttempts   int
	RetryDelay      time.Duration
	DryRun          bool
	Once            bool
	AuditDir        string
	ListenChannel   string
	AdvisoryLockKey int64
	HTTPTimeout     time.Duration
	WebEnabled      bool
	WebAddr         string
	ConfigPath      string
}

func LoadConfig() (Config, error) {
	cfg := Config{
		DatabaseURL:     getenv("DATABASE_URL", ""),
		Sub2APIURL:      strings.TrimRight(getenv("SUB2API_URL", "http://sub2api:8080"), "/"),
		Sub2APIKey:      getenv("SUB2API_KEY", ""),
		TestModel:       getenv("TEST_MODEL", "gpt-5.4-mini"),
		OpenAIClientID:  getenv("OPENAI_CLIENT_ID", "app_EMoamEEZ73f0CkXaXp7hrann"),
		OpenAITokenURL:  getenv("OPENAI_TOKEN_URL", "https://auth.openai.com/oauth/token"),
		OpenAIGroupID:   int64(getenvInt("OPENAI_GROUP_ID", 2)),
		Interval:        time.Duration(getenvInt("MONITOR_INTERVAL_SECONDS", 30)) * time.Second,
		BatchSize:       getenvInt("MONITOR_BATCH_SIZE", 50),
		TestWorkers:     getenvInt("TEST_WORKERS", 10),
		RefreshWorkers:  getenvInt("REFRESH_WORKERS", 5),
		RetryAttempts:   getenvInt("RETRY_ATTEMPTS", 10),
		RetryDelay:      time.Duration(getenvInt("RETRY_DELAY_MS", 500)) * time.Millisecond,
		DryRun:          getenvBool("DRY_RUN", false),
		Once:            getenvBool("ONCE", false),
		AuditDir:        getenv("AUDIT_DIR", "/app/data/sub2api_guardian"),
		ListenChannel:   getenv("LISTEN_CHANNEL", "sub2api_account_error"),
		AdvisoryLockKey: int64(getenvInt("ADVISORY_LOCK_KEY", 91324001)),
		HTTPTimeout:     time.Duration(getenvInt("HTTP_TIMEOUT_SECONDS", 75)) * time.Second,
		WebEnabled:      getenvBool("WEB_ENABLED", true),
		WebAddr:         getenv("WEB_ADDR", ":8788"),
		ConfigPath:      getenv("CONFIG_PATH", "/app/data/sub2api_guardian/config.json"),
	}
	if err := applyConfigFile(&cfg); err != nil {
		return cfg, err
	}
	if cfg.DatabaseURL == "" {
		host := getenv("POSTGRES_HOST", "postgres")
		port := getenv("POSTGRES_PORT", "5432")
		user := getenv("POSTGRES_USER", "sub2api")
		pass := getenv("POSTGRES_PASSWORD", "")
		db := getenv("POSTGRES_DB", "sub2api")
		sslmode := getenv("POSTGRES_SSLMODE", "disable")
		cfg.DatabaseURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s", user, pass, host, port, db, sslmode)
	}
	if cfg.Sub2APIKey == "" {
		return cfg, fmt.Errorf("SUB2API_KEY is required")
	}
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 1
	}
	if cfg.TestWorkers < 1 {
		cfg.TestWorkers = 1
	}
	if cfg.RefreshWorkers < 1 {
		cfg.RefreshWorkers = 1
	}
	if cfg.RetryAttempts < 1 {
		cfg.RetryAttempts = 1
	}
	return cfg, nil
}

func getenv(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}

func getenvBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return def
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

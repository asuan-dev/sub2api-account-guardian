package guardian

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Sub2APIClient struct {
	client *http.Client
	cfg    Config
}

func NewSub2APIClient(cfg Config) *Sub2APIClient {
	return &Sub2APIClient{client: &http.Client{Timeout: cfg.HTTPTimeout}, cfg: cfg}
}

func (c *Sub2APIClient) TestAccountWithRetries(ctx context.Context, accountID int64) (TestResult, string) {
	var lastResult TestResult = TestUnknown
	var lastReason = "not attempted"
	for attempt := 1; attempt <= c.cfg.RetryAttempts; attempt++ {
		result, reason := c.TestAccount(ctx, accountID)
		if result != TestUnknown {
			return result, fmt.Sprintf("%s after %d attempt(s)", reason, attempt)
		}
		lastResult, lastReason = result, reason
		if attempt < c.cfg.RetryAttempts {
			select {
			case <-time.After(c.cfg.RetryDelay):
			case <-ctx.Done():
				return TestUnknown, ctx.Err().Error()
			}
		}
	}
	return lastResult, lastReason
}

func (c *Sub2APIClient) RefreshAccountWithRetries(ctx context.Context, accountID int64) (string, error) {
	var lastReason = "not attempted"
	for attempt := 1; attempt <= c.cfg.RetryAttempts; attempt++ {
		reason, err := c.RefreshAccount(ctx, accountID)
		if err == nil {
			return fmt.Sprintf("%s after %d attempt(s)", reason, attempt), nil
		}
		lastReason = reason
		if !isTransientRefreshFailure(reason) {
			return reason, err
		}
		if attempt < c.cfg.RetryAttempts {
			select {
			case <-time.After(c.cfg.RetryDelay):
			case <-ctx.Done():
				return ctx.Err().Error(), ctx.Err()
			}
		}
	}
	return lastReason, fmt.Errorf(lastReason)
}

func (c *Sub2APIClient) RefreshAccount(ctx context.Context, accountID int64) (string, error) {
	urls := []string{
		fmt.Sprintf("%s/api/v1/admin/openai/accounts/%d/refresh", c.cfg.Sub2APIURL, accountID),
		fmt.Sprintf("%s/api/v1/admin/accounts/%d/refresh", c.cfg.Sub2APIURL, accountID),
	}
	var lastReason string
	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
		if err != nil {
			return err.Error(), err
		}
		req.Header.Set("x-api-key", c.cfg.Sub2APIKey)
		req.Header.Set("Accept", "application/json")
		resp, err := c.client.Do(req)
		if err != nil {
			return err.Error(), err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		text := strings.TrimSpace(string(body))
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return fmt.Sprintf("Sub2API refresh HTTP %d: %s", resp.StatusCode, text), nil
		}
		lastReason = fmt.Sprintf("Sub2API refresh HTTP %d: %s", resp.StatusCode, text)
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			return lastReason, fmt.Errorf(lastReason)
		}
	}
	return lastReason, fmt.Errorf(lastReason)
}

func (c *Sub2APIClient) TestAccount(ctx context.Context, accountID int64) (TestResult, string) {
	payload := map[string]string{"model_id": c.cfg.TestModel}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/api/v1/admin/accounts/%d/test", c.cfg.Sub2APIURL, accountID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return TestUnknown, err.Error()
	}
	req.Header.Set("x-api-key", c.cfg.Sub2APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream, application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return TestUnknown, err.Error()
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, 4<<20)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(limited)
		return TestUnknown, fmt.Sprintf("Sub2API HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if raw == "" || raw == "[DONE]" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			continue
		}
		typeName, _ := event["type"].(string)
		switch typeName {
		case "test_complete":
			if ok, _ := event["success"].(bool); ok {
				return TestOK, "test completed"
			}
			return ClassifyTestError(eventText(event)), eventText(event)
		case "error":
			return ClassifyTestError(eventText(event)), eventText(event)
		}
	}
	if err := scanner.Err(); err != nil {
		return TestUnknown, err.Error()
	}
	return TestUnknown, "no terminal SSE event"
}

func eventText(event map[string]any) string {
	for _, key := range []string{"error", "text", "message"} {
		if v, ok := event[key].(string); ok && strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "empty SSE event"
}

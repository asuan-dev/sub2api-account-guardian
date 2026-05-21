package guardian

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OAuthRefresher struct {
	client *http.Client
	cfg    Config
}

func NewOAuthRefresher(cfg Config) *OAuthRefresher {
	return &OAuthRefresher{client: &http.Client{Timeout: cfg.HTTPTimeout}, cfg: cfg}
}

func (r *OAuthRefresher) RefreshWithRetries(ctx context.Context, refreshToken string) (OAuthTokens, string, error) {
	var lastReason string
	var zero OAuthTokens
	for attempt := 1; attempt <= r.cfg.RetryAttempts; attempt++ {
		tokens, reason, err := r.Refresh(ctx, refreshToken)
		if err == nil {
			return tokens, fmt.Sprintf("ok after %d attempt(s)", attempt), nil
		}
		lastReason = reason
		if !isTransientRefreshFailure(reason) {
			return zero, reason, err
		}
		if attempt < r.cfg.RetryAttempts {
			select {
			case <-time.After(r.cfg.RetryDelay):
			case <-ctx.Done():
				return zero, ctx.Err().Error(), ctx.Err()
			}
		}
	}
	return zero, lastReason, fmt.Errorf("refresh failed after retries: %s", lastReason)
}

func (r *OAuthRefresher) Refresh(ctx context.Context, refreshToken string) (OAuthTokens, string, error) {
	form := url.Values{}
	form.Set("client_id", r.cfg.OpenAIClientID)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("redirect_uri", "http://localhost:1455/auth/callback")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.OpenAITokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return OAuthTokens{}, err.Error(), err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/110.0 Sub2API-Guardian")
	resp, err := r.client.Do(req)
	if err != nil {
		return OAuthTokens{}, err.Error(), err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		reason := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		return OAuthTokens{}, reason, fmt.Errorf(reason)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return OAuthTokens{}, err.Error(), err
	}
	access, _ := payload["access_token"].(string)
	newRefresh, _ := payload["refresh_token"].(string)
	idToken, _ := payload["id_token"].(string)
	if newRefresh == "" {
		newRefresh = refreshToken
	}
	expires := 3600
	if v, ok := payload["expires_in"].(float64); ok && v > 0 {
		expires = int(v)
	}
	if access == "" {
		return OAuthTokens{}, "refresh response missing access_token", fmt.Errorf("refresh response missing access_token")
	}
	return OAuthTokens{AccessToken: access, RefreshToken: newRefresh, IDToken: idToken, ExpiresIn: expires, Raw: payload}, "ok", nil
}

func isTransientRefreshFailure(reason string) bool {
	text := strings.ToLower(reason)
	classification := ClassifyEvidence(text)
	if classification == ClassEligibleAuth || classification == ClassNeedsRelogin {
		return false
	}
	return containsAny(text, infrastructureMarkers)
}

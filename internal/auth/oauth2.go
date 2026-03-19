package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ersinkoc/phantomstrike/internal/config"
)

// OAuth2Handler handles OAuth2 login flows for external providers.
type OAuth2Handler struct {
	authSvc    *Service
	pool       *pgxpool.Pool
	github     config.OAuthProvider
	google     config.OAuthProvider
	httpClient *http.Client
}

// NewOAuth2Handler creates a new OAuth2Handler.
func NewOAuth2Handler(authSvc *Service, pool *pgxpool.Pool, oauth2Cfg config.OAuth2Config) *OAuth2Handler {
	return &OAuth2Handler{
		authSvc:    authSvc,
		pool:       pool,
		github:     oauth2Cfg.GitHub,
		google:     oauth2Cfg.Google,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// --- GitHub OAuth2 ---

// HandleGitHubLogin redirects the user to GitHub's OAuth authorize URL.
func (o *OAuth2Handler) HandleGitHubLogin(w http.ResponseWriter, r *http.Request) {
	if o.github.ClientID == "" {
		http.Error(w, `{"error":"GitHub OAuth is not configured"}`, http.StatusNotImplemented)
		return
	}

	state := uuid.New().String()
	params := url.Values{
		"client_id":    {o.github.ClientID},
		"redirect_uri": {o.github.RedirectURL},
		"scope":        {"user:email"},
		"state":        {state},
	}

	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+params.Encode(), http.StatusTemporaryRedirect)
}

// HandleGitHubCallback exchanges the authorization code for a token, fetches user info, and returns a JWT.
func (o *OAuth2Handler) HandleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, `{"error":"missing code parameter"}`, http.StatusBadRequest)
		return
	}

	// Exchange code for access token
	tokenURL := "https://github.com/login/oauth/access_token"
	form := url.Values{
		"client_id":     {o.github.ClientID},
		"client_secret": {o.github.ClientSecret},
		"code":          {code},
		"redirect_uri":  {o.github.RedirectURL},
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		slog.Error("github oauth: creating token request", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		slog.Error("github oauth: exchanging code", "error", err)
		http.Error(w, `{"error":"failed to exchange code"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil || tokenResp.AccessToken == "" {
		slog.Error("github oauth: decoding token response", "error", err, "oauth_error", tokenResp.Error)
		http.Error(w, `{"error":"failed to obtain access token"}`, http.StatusBadGateway)
		return
	}

	// Fetch user info from GitHub API
	email, name, err := o.fetchGitHubUser(r.Context(), tokenResp.AccessToken)
	if err != nil {
		slog.Error("github oauth: fetching user info", "error", err)
		http.Error(w, `{"error":"failed to fetch user info"}`, http.StatusBadGateway)
		return
	}

	// Find or create user, generate JWT, redirect
	o.completeOAuth(w, r, email, name, "github")
}

// fetchGitHubUser retrieves the user's email and name from the GitHub API.
func (o *OAuth2Handler) fetchGitHubUser(ctx context.Context, accessToken string) (email, name string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("github user API returned %d: %s", resp.StatusCode, body)
	}

	var user struct {
		Email string `json:"email"`
		Name  string `json:"name"`
		Login string `json:"login"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return "", "", err
	}

	if user.Name == "" {
		user.Name = user.Login
	}

	// If email is private, fetch from /user/emails
	if user.Email == "" {
		user.Email, err = o.fetchGitHubPrimaryEmail(ctx, accessToken)
		if err != nil {
			return "", "", fmt.Errorf("fetching primary email: %w", err)
		}
	}

	return user.Email, user.Name, nil
}

// fetchGitHubPrimaryEmail retrieves the primary verified email from the GitHub API.
func (o *OAuth2Handler) fetchGitHubPrimaryEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", fmt.Errorf("no email found on GitHub account")
}

// --- Google OAuth2 ---

// HandleGoogleLogin redirects the user to Google's OAuth authorize URL.
func (o *OAuth2Handler) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	if o.google.ClientID == "" {
		http.Error(w, `{"error":"Google OAuth is not configured"}`, http.StatusNotImplemented)
		return
	}

	state := uuid.New().String()
	params := url.Values{
		"client_id":     {o.google.ClientID},
		"redirect_uri":  {o.google.RedirectURL},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"access_type":   {"offline"},
	}

	http.Redirect(w, r, "https://accounts.google.com/o/oauth2/v2/auth?"+params.Encode(), http.StatusTemporaryRedirect)
}

// HandleGoogleCallback exchanges the authorization code for a token, fetches user info, and returns a JWT.
func (o *OAuth2Handler) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, `{"error":"missing code parameter"}`, http.StatusBadRequest)
		return
	}

	// Exchange code for access token
	tokenURL := "https://oauth2.googleapis.com/token"
	form := url.Values{
		"client_id":     {o.google.ClientID},
		"client_secret": {o.google.ClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {o.google.RedirectURL},
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		slog.Error("google oauth: creating token request", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		slog.Error("google oauth: exchanging code", "error", err)
		http.Error(w, `{"error":"failed to exchange code"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil || tokenResp.AccessToken == "" {
		slog.Error("google oauth: decoding token response", "error", err, "oauth_error", tokenResp.Error)
		http.Error(w, `{"error":"failed to obtain access token"}`, http.StatusBadGateway)
		return
	}

	// Fetch user info from Google API
	email, name, err := o.fetchGoogleUser(r.Context(), tokenResp.AccessToken)
	if err != nil {
		slog.Error("google oauth: fetching user info", "error", err)
		http.Error(w, `{"error":"failed to fetch user info"}`, http.StatusBadGateway)
		return
	}

	// Find or create user, generate JWT, redirect
	o.completeOAuth(w, r, email, name, "google")
}

// fetchGoogleUser retrieves the user's email and name from the Google userinfo API.
func (o *OAuth2Handler) fetchGoogleUser(ctx context.Context, accessToken string) (email, name string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("google userinfo API returned %d: %s", resp.StatusCode, body)
	}

	var user struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return "", "", err
	}

	return user.Email, user.Name, nil
}

// --- Common ---

// completeOAuth finds or creates a user and redirects with JWT tokens.
func (o *OAuth2Handler) completeOAuth(w http.ResponseWriter, r *http.Request, email, name, provider string) {
	if email == "" {
		http.Error(w, `{"error":"could not determine email from provider"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Try to find existing user by email
	var userID uuid.UUID
	var role string
	err := o.pool.QueryRow(ctx,
		"SELECT id, role FROM users WHERE email = $1", email,
	).Scan(&userID, &role)

	if err != nil {
		// User doesn't exist — create one
		role = "analyst"
		err = o.pool.QueryRow(ctx,
			`INSERT INTO users (email, name, password, role)
			 VALUES ($1, $2, $3, $4)
			 RETURNING id`,
			email, name, "oauth:"+provider, role,
		).Scan(&userID)
		if err != nil {
			slog.Error("oauth: creating user", "error", err, "provider", provider)
			http.Error(w, `{"error":"failed to create user"}`, http.StatusInternalServerError)
			return
		}
	}

	// Update last login
	_, _ = o.pool.Exec(ctx, "UPDATE users SET last_login = $1 WHERE id = $2", time.Now(), userID)

	// Generate JWT tokens
	token, err := o.authSvc.GenerateToken(userID, email, role)
	if err != nil {
		slog.Error("oauth: generating token", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	refreshToken, err := o.authSvc.GenerateRefreshToken(userID)
	if err != nil {
		slog.Error("oauth: generating refresh token", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Redirect back to the frontend with tokens in query params
	redirectURL := "/auth/callback?" + url.Values{
		"token":         {token},
		"refresh_token": {refreshToken},
	}.Encode()

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

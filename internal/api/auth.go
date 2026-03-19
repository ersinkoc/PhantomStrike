package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/ersinkoc/phantomstrike/internal/auth"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type authResponse struct {
	Token        string       `json:"token"`
	RefreshToken string       `json:"refresh_token"`
	User         userResponse `json:"user"`
}

type userResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	AvatarURL *string   `json:"avatar_url,omitempty"`
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	// Look up user
	var id uuid.UUID
	var name, hashedPw, role string
	var avatarURL *string
	err := h.db.Pool.QueryRow(r.Context(),
		"SELECT id, name, password, role, avatar_url FROM users WHERE email = $1",
		req.Email,
	).Scan(&id, &name, &hashedPw, &role, &avatarURL)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPw), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Generate tokens
	token, err := h.authSvc.GenerateToken(id, req.Email, role)
	if err != nil {
		slog.Error("generating token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	refreshToken, err := h.authSvc.GenerateRefreshToken(id)
	if err != nil {
		slog.Error("generating refresh token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Update last login
	_, _ = h.db.Pool.Exec(r.Context(), "UPDATE users SET last_login = $1 WHERE id = $2", time.Now(), id)

	writeJSON(w, http.StatusOK, authResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User: userResponse{
			ID:        id,
			Email:     req.Email,
			Name:      name,
			Role:      role,
			AvatarURL: avatarURL,
		},
	})
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.Auth.AllowRegistration {
		writeError(w, http.StatusForbidden, "registration is disabled")
		return
	}

	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Name == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email, name, and password are required")
		return
	}

	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	// Hash password
	hashed, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Insert user
	var id uuid.UUID
	err = h.db.Pool.QueryRow(r.Context(),
		`INSERT INTO users (email, name, password, role) VALUES ($1, $2, $3, 'analyst') RETURNING id`,
		req.Email, req.Name, string(hashed),
	).Scan(&id)
	if err != nil {
		writeError(w, http.StatusConflict, "email already registered")
		return
	}

	// Generate tokens
	token, _ := h.authSvc.GenerateToken(id, req.Email, "analyst")
	refreshToken, _ := h.authSvc.GenerateRefreshToken(id)

	writeJSON(w, http.StatusCreated, authResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User: userResponse{
			ID:    id,
			Email: req.Email,
			Name:  req.Name,
			Role:  "analyst",
		},
	})
}

func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decodeJSON(r, &req); err != nil || req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	// Validate refresh token
	claims, err := h.authSvc.ValidateToken(req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	// Look up user
	var email, name, role string
	err = h.db.Pool.QueryRow(r.Context(),
		"SELECT email, name, role FROM users WHERE id = $1",
		claims.UserID,
	).Scan(&email, &name, &role)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "user not found")
		return
	}

	// Generate new tokens
	token, _ := h.authSvc.GenerateToken(claims.UserID, email, role)
	newRefresh, _ := h.authSvc.GenerateRefreshToken(claims.UserID)

	writeJSON(w, http.StatusOK, map[string]string{
		"token":         token,
		"refresh_token": newRefresh,
	})
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var user userResponse
	var avatarURL *string
	err := h.db.Pool.QueryRow(r.Context(),
		"SELECT id, email, name, role, avatar_url FROM users WHERE id = $1",
		claims.UserID,
	).Scan(&user.ID, &user.Email, &user.Name, &user.Role, &avatarURL)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	user.AvatarURL = avatarURL

	writeJSON(w, http.StatusOK, user)
}

func (h *Handler) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req struct {
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	_, err := h.db.Pool.Exec(r.Context(),
		"UPDATE users SET name = COALESCE(NULLIF($1, ''), name), avatar_url = NULLIF($2, ''), updated_at = NOW() WHERE id = $3",
		req.Name, req.AvatarURL, claims.UserID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Extract token from request
	token := extractBearerToken(r)
	if token == "" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
		return
	}

	// Blacklist the token in Redis if cache is available
	if h.cache != nil {
		claims, err := h.authSvc.ValidateToken(token)
		if err == nil && claims.ExpiresAt != nil {
			remaining := time.Until(claims.ExpiresAt.Time)
			if remaining > 0 {
				key := fmt.Sprintf("blacklist:%s", token)
				_ = h.cache.Set(r.Context(), key, "1", remaining)
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// extractBearerToken gets the raw bearer token from the Authorization header.
func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// EnsureDefaultAdmin creates the default admin user if it doesn't exist.
func (h *Handler) EnsureDefaultAdmin(ctx context.Context) error {
	cfg := h.cfg.Auth.DefaultAdmin
	if cfg.Email == "" {
		return nil
	}

	var exists bool
	_ = h.db.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", cfg.Email).Scan(&exists)
	if exists {
		return nil
	}

	pw := cfg.Password
	if pw == "" {
		pw = uuid.New().String()[:16]
		slog.Info("generated admin password", "password", pw)
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		return err
	}

	_, err = h.db.Pool.Exec(ctx,
		`INSERT INTO users (email, name, password, role) VALUES ($1, 'Admin', $2, 'admin') ON CONFLICT (email) DO NOTHING`,
		cfg.Email, string(hashed),
	)
	return err
}

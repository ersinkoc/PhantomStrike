package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ersinkoc/phantomstrike/internal/config"
)

func newTestService() *Service {
	cfg := config.AuthConfig{
		JWTSecret:     "test-secret-key-for-testing-only",
		TokenExpiry:   1 * time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}
	return NewService(cfg, nil)
}

func TestGenerateAndValidateToken(t *testing.T) {
	svc := newTestService()

	userID := uuid.New()
	tokenStr, err := svc.GenerateToken(userID, "user@test.com", "analyst")
	require.NoError(t, err)
	assert.NotEmpty(t, tokenStr)

	claims, err := svc.ValidateToken(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "user@test.com", claims.Email)
	assert.Equal(t, "analyst", claims.Role)
	assert.Equal(t, "phantomstrike", claims.Issuer)
}

func TestGenerateRefreshToken(t *testing.T) {
	svc := newTestService()

	userID := uuid.New()
	token, err := svc.GenerateRefreshToken(userID)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestInvalidToken(t *testing.T) {
	svc := newTestService()

	_, err := svc.ValidateToken("invalid-token-string")
	assert.Error(t, err)
	assert.Equal(t, ErrInvalidToken, err)
}

func TestExpiredToken(t *testing.T) {
	cfg := config.AuthConfig{
		JWTSecret:   "test-secret",
		TokenExpiry: -1 * time.Hour, // already expired
	}
	svc := NewService(cfg, nil)

	userID := uuid.New()
	token, err := svc.GenerateToken(userID, "expired@test.com", "viewer")
	require.NoError(t, err)

	_, err = svc.ValidateToken(token)
	assert.Error(t, err)
	assert.Equal(t, ErrExpiredToken, err)
}

func TestTokenWithDifferentRoles(t *testing.T) {
	svc := newTestService()
	roles := []string{"admin", "manager", "analyst", "viewer"}

	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			token, err := svc.GenerateToken(uuid.New(), "test@test.com", role)
			require.NoError(t, err)

			claims, err := svc.ValidateToken(token)
			require.NoError(t, err)
			assert.Equal(t, role, claims.Role)
		})
	}
}

func TestErrorTypes(t *testing.T) {
	assert.Error(t, ErrInvalidToken)
	assert.Error(t, ErrExpiredToken)
	assert.Error(t, ErrInvalidCreds)
	assert.Error(t, ErrUserNotFound)
	assert.Error(t, ErrEmailTaken)
	assert.Error(t, ErrUnauthorized)
}

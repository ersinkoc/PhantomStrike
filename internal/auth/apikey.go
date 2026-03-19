package auth

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// ValidateAPIKey checks the database for a valid API key and returns claims.
// This allows users to authenticate via X-API-Key header without a JWT.
func (s *Service) ValidateAPIKey(ctx context.Context, apiKey string) (*Claims, error) {
	var id uuid.UUID
	var email, role string

	err := s.db.Pool.QueryRow(ctx,
		`SELECT id, email, role FROM users WHERE api_key = $1`,
		apiKey,
	).Scan(&id, &email, &role)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid API key", ErrUnauthorized)
	}

	return &Claims{
		UserID: id,
		Email:  email,
		Role:   role,
	}, nil
}

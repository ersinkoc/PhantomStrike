package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"
)

// User represents a system user
type User struct {
	ID           uuid.UUID       `json:"id"`
	Email        string          `json:"email"`
	Name         string          `json:"name"`
	Password     string          `json:"-"`
	Role         string          `json:"role"`
	APIKey       string          `json:"api_key"`
	AvatarURL    string          `json:"avatar_url"`
	Settings     JSONB           `json:"settings"`
	CreatedAt    pgtype.Timestamptz `json:"created_at"`
	UpdatedAt    pgtype.Timestamptz `json:"updated_at"`
	LastLogin    *pgtype.Timestamptz `json:"last_login"`
}

// CreateUser creates a new user with hashed password
func (db *DB) CreateUser(ctx context.Context, u *User) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	query := `
		INSERT INTO users (email, name, password, role, api_key, avatar_url, settings)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at, updated_at`

	return db.Pool.QueryRow(ctx, query,
		u.Email, u.Name, string(hashedPassword), u.Role, u.APIKey, u.AvatarURL, u.Settings,
	).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
}

// GetUserByID retrieves a user by ID
func (db *DB) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	query := `
		SELECT id, email, name, role, api_key, avatar_url, settings, created_at, updated_at, last_login
		FROM users WHERE id = $1`

	u := &User{}
	err := db.Pool.QueryRow(ctx, query, id).Scan(
		&u.ID, &u.Email, &u.Name, &u.Role, &u.APIKey, &u.AvatarURL,
		&u.Settings, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin,
	)
	if err != nil {
		return nil, fmt.Errorf("querying user: %w", err)
	}
	return u, nil
}

// GetUserByEmail retrieves a user by email
func (db *DB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, email, name, password, role, api_key, avatar_url, settings, created_at, updated_at, last_login
		FROM users WHERE email = $1`

	u := &User{}
	err := db.Pool.QueryRow(ctx, query, email).Scan(
		&u.ID, &u.Email, &u.Name, &u.Password, &u.Role, &u.APIKey,
		&u.AvatarURL, &u.Settings, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin,
	)
	if err != nil {
		return nil, fmt.Errorf("querying user: %w", err)
	}
	return u, nil
}

// GetUserByAPIKey retrieves a user by API key
func (db *DB) GetUserByAPIKey(ctx context.Context, apiKey string) (*User, error) {
	query := `
		SELECT id, email, name, role, api_key, avatar_url, settings, created_at, updated_at, last_login
		FROM users WHERE api_key = $1`

	u := &User{}
	err := db.Pool.QueryRow(ctx, query, apiKey).Scan(
		&u.ID, &u.Email, &u.Name, &u.Role, &u.APIKey, &u.AvatarURL,
		&u.Settings, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin,
	)
	if err != nil {
		return nil, fmt.Errorf("querying user: %w", err)
	}
	return u, nil
}

// VerifyPassword checks if the provided password matches
func VerifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// UpdateUser updates user information
func (db *DB) UpdateUser(ctx context.Context, u *User) error {
	query := `
		UPDATE users
		SET name = $2, email = $3, role = $4, avatar_url = $5, settings = $6
		WHERE id = $1`

	_, err := db.Pool.Exec(ctx, query,
		u.ID, u.Name, u.Email, u.Role, u.AvatarURL, u.Settings,
	)
	return err
}

// UpdateUserPassword updates user's password
func (db *DB) UpdateUserPassword(ctx context.Context, id uuid.UUID, newPassword string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	_, err = db.Pool.Exec(ctx, "UPDATE users SET password = $2 WHERE id = $1", id, string(hashedPassword))
	return err
}

// UpdateUserAPIKey updates user's API key
func (db *DB) UpdateUserAPIKey(ctx context.Context, id uuid.UUID, apiKey string) error {
	_, err := db.Pool.Exec(ctx, "UPDATE users SET api_key = $2 WHERE id = $1", id, apiKey)
	return err
}

// UpdateLastLogin updates the last login timestamp
func (db *DB) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, "UPDATE users SET last_login = NOW() WHERE id = $1", id)
	return err
}

// DeleteUser deletes a user
func (db *DB) DeleteUser(ctx context.Context, id uuid.UUID) error {
	_, err := db.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", id)
	return err
}

// ListUsers lists all users with pagination
func (db *DB) ListUsers(ctx context.Context, limit, offset int) ([]*User, int64, error) {
	// Count
	var total int64
	if err := db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&total); err != nil {
		return nil, 0, err
	}

	// Query
	query := `
		SELECT id, email, name, role, api_key, avatar_url, settings, created_at, updated_at, last_login
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := db.Pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("querying users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(
			&u.ID, &u.Email, &u.Name, &u.Role, &u.APIKey, &u.AvatarURL,
			&u.Settings, &u.CreatedAt, &u.UpdatedAt, &u.LastLogin,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning user: %w", err)
		}
		users = append(users, u)
	}

	return users, total, rows.Err()
}

// Organization represents a tenant organization
type Organization struct {
	ID        uuid.UUID       `json:"id"`
	Name      string          `json:"name"`
	Slug      string          `json:"slug"`
	Plan      string          `json:"plan"`
	Settings  JSONB           `json:"settings"`
	CreatedAt pgtype.Timestamptz `json:"created_at"`
}

// CreateOrganization creates a new organization
func (db *DB) CreateOrganization(ctx context.Context, o *Organization) error {
	query := `
		INSERT INTO organizations (name, slug, plan, settings)
		VALUES ($1, $2, $3, $4)
		RETURNING id, created_at`

	return db.Pool.QueryRow(ctx, query, o.Name, o.Slug, o.Plan, o.Settings).Scan(&o.ID, &o.CreatedAt)
}

// GetOrganizationByID retrieves an organization by ID
func (db *DB) GetOrganizationByID(ctx context.Context, id uuid.UUID) (*Organization, error) {
	query := `SELECT id, name, slug, plan, settings, created_at FROM organizations WHERE id = $1`

	o := &Organization{}
	err := db.Pool.QueryRow(ctx, query, id).Scan(&o.ID, &o.Name, &o.Slug, &o.Plan, &o.Settings, &o.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("querying organization: %w", err)
	}
	return o, nil
}

// AddOrgMember adds a user to an organization
func (db *DB) AddOrgMember(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	_, err := db.Pool.Exec(ctx,
		"INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
		orgID, userID, role,
	)
	return err
}

// GetUserOrgs retrieves organizations for a user
func (db *DB) GetUserOrgs(ctx context.Context, userID uuid.UUID) ([]*Organization, error) {
	query := `
		SELECT o.id, o.name, o.slug, o.plan, o.settings, o.created_at
		FROM organizations o
		JOIN org_members om ON o.id = om.org_id
		WHERE om.user_id = $1`

	rows, err := db.Pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("querying organizations: %w", err)
	}
	defer rows.Close()

	var orgs []*Organization
	for rows.Next() {
		o := &Organization{}
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.Plan, &o.Settings, &o.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning organization: %w", err)
		}
		orgs = append(orgs, o)
	}

	return orgs, rows.Err()
}

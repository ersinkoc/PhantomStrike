package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Conversation represents a chat session
type Conversation struct {
	ID          uuid.UUID       `json:"id"`
	MissionID   uuid.UUID       `json:"mission_id"`
	Title       string          `json:"title"`
	AgentType   string          `json:"agent_type"`
	Status      string          `json:"status"`
	Metadata    JSONB           `json:"metadata"`
	CreatedAt   pgtype.Timestamptz `json:"created_at"`
	UpdatedAt   pgtype.Timestamptz `json:"updated_at"`
}

// Message represents a chat message
type Message struct {
	ID             uuid.UUID       `json:"id"`
	ConversationID uuid.UUID       `json:"conversation_id"`
	Role           string          `json:"role"`
	Content        string          `json:"content"`
	ToolCalls      JSONB           `json:"tool_calls"`
	ToolCallID     string          `json:"tool_call_id"`
	TokensUsed     int             `json:"tokens_used"`
	Model          string          `json:"model"`
	Provider       string          `json:"provider"`
	CreatedAt      pgtype.Timestamptz `json:"created_at"`
}

// CreateConversation creates a new conversation
func (db *DB) CreateConversation(ctx context.Context, c *Conversation) error {
	query := `
		INSERT INTO conversations (mission_id, title, agent_type, status, metadata)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, created_at, updated_at`

	return db.Pool.QueryRow(ctx, query,
		c.MissionID, c.Title, c.AgentType, c.Status, c.Metadata,
	).Scan(&c.ID, &c.CreatedAt, &c.UpdatedAt)
}

// GetConversation retrieves a conversation by ID
func (db *DB) GetConversation(ctx context.Context, id uuid.UUID) (*Conversation, error) {
	query := `
		SELECT id, mission_id, title, agent_type, status, metadata, created_at, updated_at
		FROM conversations WHERE id = $1`

	c := &Conversation{}
	err := db.Pool.QueryRow(ctx, query, id).Scan(
		&c.ID, &c.MissionID, &c.Title, &c.AgentType, &c.Status,
		&c.Metadata, &c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("querying conversation: %w", err)
	}
	return c, nil
}

// ListConversationsByMission lists conversations for a mission
func (db *DB) ListConversationsByMission(ctx context.Context, missionID uuid.UUID) ([]*Conversation, error) {
	query := `
		SELECT id, mission_id, title, agent_type, status, metadata, created_at, updated_at
		FROM conversations
		WHERE mission_id = $1
		ORDER BY created_at DESC`

	rows, err := db.Pool.Query(ctx, query, missionID)
	if err != nil {
		return nil, fmt.Errorf("querying conversations: %w", err)
	}
	defer rows.Close()

	var conversations []*Conversation
	for rows.Next() {
		c := &Conversation{}
		if err := rows.Scan(
			&c.ID, &c.MissionID, &c.Title, &c.AgentType, &c.Status,
			&c.Metadata, &c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning conversation: %w", err)
		}
		conversations = append(conversations, c)
	}

	return conversations, rows.Err()
}

// CreateMessage creates a new message
func (db *DB) CreateMessage(ctx context.Context, m *Message) error {
	query := `
		INSERT INTO messages (conversation_id, role, content, tool_calls, tool_call_id, tokens_used, model, provider)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, created_at`

	return db.Pool.QueryRow(ctx, query,
		m.ConversationID, m.Role, m.Content, m.ToolCalls, m.ToolCallID,
		m.TokensUsed, m.Model, m.Provider,
	).Scan(&m.ID, &m.CreatedAt)
}

// GetMessages retrieves messages for a conversation with pagination
func (db *DB) GetMessages(ctx context.Context, conversationID uuid.UUID, limit, offset int) ([]*Message, int64, error) {
	// Count
	var total int64
	if err := db.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE conversation_id = $1", conversationID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting messages: %w", err)
	}

	// Query
	query := `
		SELECT id, conversation_id, role, content, tool_calls, tool_call_id,
		       tokens_used, model, provider, created_at
		FROM messages
		WHERE conversation_id = $1
		ORDER BY created_at ASC
		LIMIT $2 OFFSET $3`

	rows, err := db.Pool.Query(ctx, query, conversationID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("querying messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		m := &Message{}
		if err := rows.Scan(
			&m.ID, &m.ConversationID, &m.Role, &m.Content, &m.ToolCalls,
			&m.ToolCallID, &m.TokensUsed, &m.Model, &m.Provider, &m.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning message: %w", err)
		}
		messages = append(messages, m)
	}

	return messages, total, rows.Err()
}

// GetLastMessages retrieves the most recent messages for context
func (db *DB) GetLastMessages(ctx context.Context, conversationID uuid.UUID, limit int) ([]*Message, error) {
	query := `
		SELECT id, conversation_id, role, content, tool_calls, tool_call_id,
		       tokens_used, model, provider, created_at
		FROM messages
		WHERE conversation_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := db.Pool.Query(ctx, query, conversationID, limit)
	if err != nil {
		return nil, fmt.Errorf("querying messages: %w", err)
	}
	defer rows.Close()

	var messages []*Message
	for rows.Next() {
		m := &Message{}
		if err := rows.Scan(
			&m.ID, &m.ConversationID, &m.Role, &m.Content, &m.ToolCalls,
			&m.ToolCallID, &m.TokensUsed, &m.Model, &m.Provider, &m.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning message: %w", err)
		}
		messages = append(messages, m)
	}

	// Reverse to get chronological order
	for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
		messages[i], messages[j] = messages[j], messages[i]
	}

	return messages, rows.Err()
}

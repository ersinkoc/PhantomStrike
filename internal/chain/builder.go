package chain

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Node represents a node in the attack chain graph.
type Node struct {
	ID       uuid.UUID      `json:"id"`
	Type     string         `json:"type"` // target, tool, vulnerability, credential, pivot
	Label    string         `json:"label"`
	Data     map[string]any `json:"data"`
	Severity string         `json:"severity,omitempty"`
	Phase    string         `json:"phase,omitempty"`
}

// Edge represents an edge in the attack chain graph.
type Edge struct {
	ID       uuid.UUID `json:"id"`
	SourceID uuid.UUID `json:"source_id"`
	TargetID uuid.UUID `json:"target_id"`
	Type     string    `json:"type"` // discovered, exploited, pivoted, escalated
	Label    string    `json:"label,omitempty"`
}

// Builder constructs attack chain graphs from mission data.
type Builder struct {
	pool *pgxpool.Pool
}

// NewBuilder creates a new chain builder.
func NewBuilder(pool *pgxpool.Pool) *Builder {
	return &Builder{pool: pool}
}

// AddNode adds a node to the attack chain for a mission.
func (b *Builder) AddNode(ctx context.Context, missionID uuid.UUID, nodeType, label string, data map[string]any, severity, phase string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := b.pool.Exec(ctx,
		`INSERT INTO attack_chain_nodes (id, mission_id, node_type, label, data, severity, phase)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		id, missionID, nodeType, label, data, severity, phase,
	)
	if err != nil {
		slog.Error("failed to add chain node", "error", err)
		return uuid.Nil, err
	}
	return id, nil
}

// AddEdge adds an edge between two nodes.
func (b *Builder) AddEdge(ctx context.Context, missionID, sourceID, targetID uuid.UUID, edgeType, label string) (uuid.UUID, error) {
	id := uuid.New()
	_, err := b.pool.Exec(ctx,
		`INSERT INTO attack_chain_edges (id, mission_id, source_id, target_id, edge_type, label)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		id, missionID, sourceID, targetID, edgeType, label,
	)
	if err != nil {
		slog.Error("failed to add chain edge", "error", err)
		return uuid.Nil, err
	}
	return id, nil
}

// GetGraph returns the full attack chain graph for a mission.
func (b *Builder) GetGraph(ctx context.Context, missionID uuid.UUID) ([]Node, []Edge, error) {
	// Nodes
	nodeRows, err := b.pool.Query(ctx,
		`SELECT id, node_type, label, data, severity, phase FROM attack_chain_nodes WHERE mission_id = $1`, missionID)
	if err != nil {
		return nil, nil, err
	}
	defer nodeRows.Close()

	var nodes []Node
	for nodeRows.Next() {
		var n Node
		if err := nodeRows.Scan(&n.ID, &n.Type, &n.Label, &n.Data, &n.Severity, &n.Phase); err != nil {
			continue
		}
		nodes = append(nodes, n)
	}

	// Edges
	edgeRows, err := b.pool.Query(ctx,
		`SELECT id, source_id, target_id, edge_type, label FROM attack_chain_edges WHERE mission_id = $1`, missionID)
	if err != nil {
		return nodes, nil, err
	}
	defer edgeRows.Close()

	var edges []Edge
	for edgeRows.Next() {
		var e Edge
		if err := edgeRows.Scan(&e.ID, &e.SourceID, &e.TargetID, &e.Type, &e.Label); err != nil {
			continue
		}
		edges = append(edges, e)
	}

	return nodes, edges, nil
}

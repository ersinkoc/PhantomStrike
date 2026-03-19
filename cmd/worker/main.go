package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ersinkoc/phantomstrike/internal/config"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	pollInterval     = 5 * time.Second
	jobTimeout       = 30 * time.Minute
	maxRetries       = 3
	workerIDTemplate = "worker-%s"
)

// Job represents a background job
type Job struct {
	ID          uuid.UUID       `db:"id"`
	Type        string          `db:"job_type"`    // mission, report, scheduled, tool_retry
	Status      string          `db:"status"`      // pending, running, completed, failed
	Payload     json.RawMessage `db:"payload"`
	Result      json.RawMessage `db:"result"`
	Error       string          `db:"error"`
	RetryCount  int             `db:"retry_count"`
	WorkerID    string          `db:"worker_id"`
	CreatedAt   time.Time       `db:"created_at"`
	StartedAt   *time.Time      `db:"started_at"`
	CompletedAt *time.Time      `db:"completed_at"`
}

// Worker processes background jobs
type Worker struct {
	id       string
	config   *config.Config
	db       *pgxpool.Pool
	shutdown chan struct{}
	running  bool
}

// NewWorker creates a new worker instance
func NewWorker(cfg *config.Config, pool *pgxpool.Pool) *Worker {
	return &Worker{
		id:       fmt.Sprintf(workerIDTemplate, uuid.New().String()[:8]),
		config:   cfg,
		db:       pool,
		shutdown: make(chan struct{}),
	}
}

func main() {
	slog.Info("PhantomStrike Worker starting...")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	// Setup logging
	setupLogging(cfg.Logging.Level)

	// Connect to database
	if cfg.Database.URL == "" {
		slog.Error("DATABASE_URL not configured")
		os.Exit(1)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.Database.URL)
	if err != nil {
		slog.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Ensure jobs table exists
	if err := ensureJobsTable(ctx, pool); err != nil {
		slog.Error("Failed to setup jobs table", "error", err)
		os.Exit(1)
	}

	// Create and start worker
	worker := NewWorker(cfg, pool)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		slog.Info("Shutdown signal received, stopping worker...")
		worker.Stop()
	}()

	slog.Info("Worker started", "id", worker.id)
	if err := worker.Run(ctx); err != nil {
		slog.Error("Worker error", "error", err)
		os.Exit(1)
	}
}

// Run starts the worker loop
func (w *Worker) Run(ctx context.Context) error {
	w.running = true

	for w.running {
		select {
		case <-w.shutdown:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Try to claim and process a job
		processed, err := w.processNextJob(ctx)
		if err != nil {
			slog.Error("Job processing error", "error", err)
		}

		// If no job was available, wait before polling again
		if !processed {
			time.Sleep(pollInterval)
		}
	}

	return nil
}

// Stop gracefully stops the worker
func (w *Worker) Stop() {
	w.running = false
	close(w.shutdown)
}

// processNextJob claims and processes the next available job
func (w *Worker) processNextJob(ctx context.Context) (bool, error) {
	// Claim a pending job
	job, err := w.claimJob(ctx)
	if err != nil {
		if err == pgx.ErrNoRows {
			return false, nil // No jobs available
		}
		return false, err
	}

	slog.Info("Processing job",
		"job_id", job.ID,
		"type", job.Type,
		"retry", job.RetryCount)

	// Process the job with timeout
	processCtx, cancel := context.WithTimeout(ctx, jobTimeout)
	defer cancel()

	result, err := w.executeJob(processCtx, job)

	// Update job status
	if err != nil {
		slog.Error("Job failed", "job_id", job.ID, "error", err)
		if err := w.failJob(ctx, job.ID, err.Error()); err != nil {
			slog.Error("Failed to mark job as failed", "job_id", job.ID, "error", err)
		}

		// Schedule retry if applicable
		if job.RetryCount < maxRetries {
			if err := w.scheduleRetry(ctx, job); err != nil {
				slog.Error("Failed to schedule retry", "job_id", job.ID, "error", err)
			}
		}
	} else {
		if err := w.completeJob(ctx, job.ID, result); err != nil {
			slog.Error("Failed to complete job", "job_id", job.ID, "error", err)
		}
		slog.Info("Job completed", "job_id", job.ID)
	}

	return true, nil
}

// claimJob atomically claims a pending job for this worker
func (w *Worker) claimJob(ctx context.Context) (*Job, error) {
	// First, clean up stale jobs (running for too long)
	_, err := w.db.Exec(ctx,
		`UPDATE jobs
		 SET status = 'pending', worker_id = NULL, started_at = NULL
		 WHERE status = 'running'
		 AND started_at < NOW() - INTERVAL '30 minutes'`)
	if err != nil {
		slog.Warn("Failed to clean up stale jobs", "error", err)
	}

	// Claim next pending job
	var job Job
	err = w.db.QueryRow(ctx,
		`UPDATE jobs
		 SET status = 'running', worker_id = $1, started_at = NOW()
		 WHERE id = (
			SELECT id FROM jobs
			WHERE status = 'pending'
			AND (retry_after IS NULL OR retry_after <= NOW())
			ORDER BY created_at ASC
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		 )
		 RETURNING id, job_type, payload, retry_count, created_at`,
		w.id,
	).Scan(&job.ID, &job.Type, &job.Payload, &job.RetryCount, &job.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &job, nil
}

// executeJob executes the job based on its type
func (w *Worker) executeJob(ctx context.Context, job *Job) (json.RawMessage, error) {
	switch job.Type {
	case "mission":
		return w.executeMissionJob(ctx, job)
	case "report":
		return w.executeReportJob(ctx, job)
	case "scheduled":
		return w.executeScheduledJob(ctx, job)
	case "tool_retry":
		return w.executeToolRetryJob(ctx, job)
	default:
		return nil, fmt.Errorf("unknown job type: %s", job.Type)
	}
}

// executeMissionJob processes a mission execution job
func (w *Worker) executeMissionJob(ctx context.Context, job *Job) (json.RawMessage, error) {
	var payload struct {
		MissionID uuid.UUID       `json:"mission_id"`
		Target    json.RawMessage `json:"target"`
		Phases    []string        `json:"phases"`
	}

	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return nil, fmt.Errorf("invalid mission payload: %w", err)
	}

	// Update mission status to running
	_, err := w.db.Exec(ctx,
		"UPDATE missions SET status = 'running', started_at = NOW() WHERE id = $1",
		payload.MissionID)
	if err != nil {
		return nil, fmt.Errorf("failed to update mission status: %w", err)
	}

	// Mission execution is handled by the agent swarm through WebSocket events
	// The worker just marks it as started; the actual execution is async
	// For now, this is a placeholder that would integrate with the agent system

	result := map[string]interface{}{
		"mission_id": payload.MissionID,
		"status":     "started",
		"started_at": time.Now(),
	}

	return json.Marshal(result)
}

// executeReportJob generates a report
func (w *Worker) executeReportJob(ctx context.Context, job *Job) (json.RawMessage, error) {
	var payload struct {
		ReportID  uuid.UUID `json:"report_id"`
		MissionID uuid.UUID `json:"mission_id"`
		Format    string    `json:"format"`
	}

	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return nil, fmt.Errorf("invalid report payload: %w", err)
	}

	// Update report status
	_, err := w.db.Exec(ctx,
		"UPDATE reports SET status = 'generating' WHERE id = $1",
		payload.ReportID)
	if err != nil {
		return nil, fmt.Errorf("failed to update report status: %w", err)
	}

	// Generate report content based on mission findings
	// This is a simplified implementation
	reportData, err := w.generateReport(ctx, payload.MissionID, payload.Format)
	if err != nil {
		return nil, fmt.Errorf("failed to generate report: %w", err)
	}

	// Store report file
	filePath := fmt.Sprintf("reports/%s.%s", payload.ReportID, payload.Format)
	_, err = w.db.Exec(ctx,
		"UPDATE reports SET status = 'ready', file_path = $1, file_size = $2 WHERE id = $3",
		filePath, len(reportData), payload.ReportID)
	if err != nil {
		return nil, fmt.Errorf("failed to update report: %w", err)
	}

	result := map[string]interface{}{
		"report_id": payload.ReportID,
		"file_path": filePath,
		"size":      len(reportData),
	}

	return json.Marshal(result)
}

// executeScheduledJob runs a scheduled task
func (w *Worker) executeScheduledJob(ctx context.Context, job *Job) (json.RawMessage, error) {
	var payload struct {
		JobID   uuid.UUID `json:"scheduled_job_id"`
		Name    string    `json:"name"`
		CronExpr string   `json:"cron_expr"`
	}

	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return nil, fmt.Errorf("invalid scheduled job payload: %w", err)
	}

	// Update scheduled job stats
	_, err := w.db.Exec(ctx,
		`UPDATE scheduled_jobs
		 SET last_run = NOW(), run_count = run_count + 1
		 WHERE id = $1`,
		payload.JobID)
	if err != nil {
		return nil, fmt.Errorf("failed to update scheduled job: %w", err)
	}

	// Execute the scheduled task based on its name/type
	// This would dispatch to appropriate handlers

	result := map[string]interface{}{
		"scheduled_job_id": payload.JobID,
		"executed_at":      time.Now(),
	}

	return json.Marshal(result)
}

// executeToolRetryJob retries a failed tool execution
func (w *Worker) executeToolRetryJob(ctx context.Context, job *Job) (json.RawMessage, error) {
	var payload struct {
		ExecutionID uuid.UUID         `json:"execution_id"`
		ToolName    string            `json:"tool_name"`
		Params      map[string]any    `json:"params"`
	}

	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return nil, fmt.Errorf("invalid tool retry payload: %w", err)
	}

	// Tool retry would integrate with the tool executor
	// For now, just mark it as retried

	result := map[string]interface{}{
		"execution_id": payload.ExecutionID,
		"retried_at":   time.Now(),
		"status":       "retry_completed",
	}

	return json.Marshal(result)
}

// generateReport creates a report from mission data
func (w *Worker) generateReport(ctx context.Context, missionID uuid.UUID, format string) ([]byte, error) {
	// Get mission details
	var missionName string
	err := w.db.QueryRow(ctx,
		"SELECT name FROM missions WHERE id = $1", missionID).Scan(&missionName)
	if err != nil {
		return nil, err
	}

	// Get vulnerabilities
	rows, err := w.db.Query(ctx,
		`SELECT title, severity, description, cvss_score, evidence, remediation
		 FROM vulnerabilities WHERE mission_id = $1 ORDER BY cvss_score DESC NULLS LAST`,
		missionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []map[string]interface{}
	for rows.Next() {
		var v struct {
			Title       string
			Severity    string
			Description *string
			CVSSScore   *float64
			Evidence    *string
			Remediation *string
		}
		if err := rows.Scan(&v.Title, &v.Severity, &v.Description, &v.CVSSScore, &v.Evidence, &v.Remediation); err != nil {
			continue
		}
		vulns = append(vulns, map[string]interface{}{
			"title":       v.Title,
			"severity":    v.Severity,
			"description": v.Description,
			"cvss_score":  v.CVSSScore,
			"evidence":    v.Evidence,
			"remediation": v.Remediation,
		})
	}

	// Generate report based on format
	switch format {
	case "json":
		return json.MarshalIndent(map[string]interface{}{
			"mission":       missionName,
			"generated_at":  time.Now(),
			"vulnerabilities": vulns,
		}, "", "  ")
	case "md", "markdown":
		return generateMarkdownReport(missionName, vulns), nil
	default:
		// Default to JSON
		return json.MarshalIndent(map[string]interface{}{
			"mission":       missionName,
			"generated_at":  time.Now(),
			"vulnerabilities": vulns,
		}, "", "  ")
	}
}

// generateMarkdownReport creates a markdown formatted report
func generateMarkdownReport(missionName string, vulns []map[string]interface{}) []byte {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# Security Assessment Report\n\n"))
	b.WriteString(fmt.Sprintf("**Mission:** %s\n\n", missionName))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", time.Now().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("---\n\n"))
	b.WriteString(fmt.Sprintf("## Executive Summary\n\n"))
	b.WriteString(fmt.Sprintf("Total vulnerabilities found: **%d**\n\n", len(vulns)))

	// Count by severity
	severityCount := make(map[string]int)
	for _, v := range vulns {
		sev := v["severity"].(string)
		severityCount[sev]++
	}

	b.WriteString("### By Severity\n\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if count := severityCount[sev]; count > 0 {
			b.WriteString(fmt.Sprintf("- **%s:** %d\n", sev, count))
		}
	}
	b.WriteString("\n")

	// Detailed findings
	if len(vulns) > 0 {
		b.WriteString("## Detailed Findings\n\n")
		for i, v := range vulns {
			b.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, v["title"]))
			b.WriteString(fmt.Sprintf("**Severity:** %s\n\n", v["severity"]))
			if cvss := v["cvss_score"]; cvss != nil {
				b.WriteString(fmt.Sprintf("**CVSS Score:** %.1f\n\n", cvss))
			}
			if desc := v["description"]; desc != nil {
				b.WriteString(fmt.Sprintf("**Description:** %s\n\n", desc))
			}
			if evidence := v["evidence"]; evidence != nil {
				b.WriteString(fmt.Sprintf("**Evidence:**\n```\n%s\n```\n\n", evidence))
			}
			if remediation := v["remediation"]; remediation != nil {
				b.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", remediation))
			}
			b.WriteString("---\n\n")
		}
	}

	return []byte(b.String())
}

// completeJob marks a job as completed
func (w *Worker) completeJob(ctx context.Context, jobID uuid.UUID, result json.RawMessage) error {
	_, err := w.db.Exec(ctx,
		`UPDATE jobs
		 SET status = 'completed', result = $1, completed_at = NOW()
		 WHERE id = $2`,
		result, jobID)
	return err
}

// failJob marks a job as failed
func (w *Worker) failJob(ctx context.Context, jobID uuid.UUID, errorMsg string) error {
	_, err := w.db.Exec(ctx,
		`UPDATE jobs
		 SET status = 'failed', error = $1, completed_at = NOW()
		 WHERE id = $2`,
		errorMsg, jobID)
	return err
}

// scheduleRetry schedules a job for retry
func (w *Worker) scheduleRetry(ctx context.Context, job *Job) error {
	retryDelay := time.Duration(job.RetryCount+1) * time.Minute
	_, err := w.db.Exec(ctx,
		`UPDATE jobs
		 SET status = 'pending', retry_after = NOW() + $1::interval, retry_count = retry_count + 1
		 WHERE id = $2`,
		retryDelay, job.ID)
	return err
}

// ensureJobsTable creates the jobs table if it doesn't exist
func ensureJobsTable(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS jobs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			job_type VARCHAR(50) NOT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'pending',
			payload JSONB,
			result JSONB,
			error TEXT,
			retry_count INT DEFAULT 0,
			retry_after TIMESTAMP,
			worker_id VARCHAR(100),
			created_at TIMESTAMP DEFAULT NOW(),
			started_at TIMESTAMP,
			completed_at TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
		CREATE INDEX IF NOT EXISTS idx_jobs_type ON jobs(job_type);
		CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at);
	`)
	return err
}

// setupLogging configures the logger
func setupLogging(level string) {
	lvl := slog.LevelInfo
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	}))
	slog.SetDefault(logger)
}

// Package workflow provides a workflow engine for chaining security tests.
package workflow

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	"github.com/ersinkoc/phantomstrike/internal/tool"
)

// Status represents the execution status of a workflow or step.
type Status string

const (
	StatusPending    Status = "pending"
	StatusRunning    Status = "running"
	StatusCompleted  Status = "completed"
	StatusFailed     Status = "failed"
	StatusSkipped    Status = "skipped"
	StatusCancelled  Status = "cancelled"
)

// Workflow represents a security testing workflow definition.
type Workflow struct {
	ID          string            `yaml:"id" json:"id"`
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description" json:"description"`
	Version     string            `yaml:"version" json:"version"`
	Category    string            `yaml:"category" json:"category"`
	Tags        []string          `yaml:"tags,omitempty" json:"tags,omitempty"`
	Variables   map[string]any    `yaml:"variables,omitempty" json:"variables,omitempty"`
	Steps       []Step            `yaml:"steps" json:"steps"`
	OnError     string            `yaml:"on_error,omitempty" json:"on_error,omitempty"` // continue, stop, retry
	Timeout     time.Duration     `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Schedule    *ScheduleConfig   `yaml:"schedule,omitempty" json:"schedule,omitempty"`
	Conditions  *Conditions       `yaml:"conditions,omitempty" json:"conditions,omitempty"`
}

// ScheduleConfig defines when a workflow should run.
type ScheduleConfig struct {
	Cron     string    `yaml:"cron,omitempty" json:"cron,omitempty"`
	Interval string    `yaml:"interval,omitempty" json:"interval,omitempty"`
	At       time.Time `yaml:"at,omitempty" json:"at,omitempty"`
}

// Conditions define when a workflow should execute.
type Conditions struct {
	If   string `yaml:"if,omitempty" json:"if,omitempty"`   // Condition expression
	When string `yaml:"when,omitempty" json:"when,omitempty"` // Schedule condition
}

// Step represents a single step in a workflow.
type Step struct {
	ID          string                 `yaml:"id" json:"id"`
	Name        string                 `yaml:"name" json:"name"`
	Type        StepType               `yaml:"type" json:"type"`
	Tool        string                 `yaml:"tool,omitempty" json:"tool,omitempty"`
	Workflow    string                 `yaml:"workflow,omitempty" json:"workflow,omitempty"`
	Script      string                 `yaml:"script,omitempty" json:"script,omitempty"`
	Parallel    []Step                 `yaml:"parallel,omitempty" json:"parallel,omitempty"`
	Loop        *LoopConfig           `yaml:"loop,omitempty" json:"loop,omitempty"`
	Condition   string                 `yaml:"condition,omitempty" json:"condition,omitempty"`
	Inputs      map[string]any         `yaml:"inputs,omitempty" json:"inputs,omitempty"`
	Outputs     map[string]string      `yaml:"outputs,omitempty" json:"outputs,omitempty"`
	OnError     string                 `yaml:"on_error,omitempty" json:"on_error,omitempty"`
	Timeout     time.Duration          `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Retry       *RetryConfig          `yaml:"retry,omitempty" json:"retry,omitempty"`
	DependsOn   []string               `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
}

// StepType defines the type of a workflow step.
type StepType string

const (
	StepTypeTool     StepType = "tool"
	StepTypeWorkflow StepType = "workflow"
	StepTypeScript   StepType = "script"
	StepTypeParallel StepType = "parallel"
	StepTypeDecision StepType = "decision"
	StepTypeWait     StepType = "wait"
	StepTypeNotify   StepType = "notify"
)

// LoopConfig defines loop behavior.
type LoopConfig struct {
	Items   []any  `yaml:"items,omitempty" json:"items,omitempty"`
	Range   *struct {
		Start int `yaml:"start" json:"start"`
		End   int `yaml:"end" json:"end"`
		Step  int `yaml:"step,omitempty" json:"step,omitempty"`
	} `yaml:"range,omitempty" json:"range,omitempty"`
	As      string `yaml:"as,omitempty" json:"as,omitempty"`
}

// RetryConfig defines retry behavior.
type RetryConfig struct {
	MaxAttempts int           `yaml:"max_attempts" json:"max_attempts"`
	Delay       time.Duration `yaml:"delay,omitempty" json:"delay,omitempty"`
	Backoff     string        `yaml:"backoff,omitempty" json:"backoff,omitempty"` // linear, exponential
}

// Execution represents a running workflow instance.
type Execution struct {
	ID          uuid.UUID              `json:"id"`
	WorkflowID  string                 `json:"workflow_id"`
	MissionID   *uuid.UUID             `json:"mission_id,omitempty"`
	Status      Status                 `json:"status"`
	Variables   map[string]any         `json:"variables"`
	StepResults map[string]*StepResult `json:"step_results"`
	StartedAt   time.Time              `json:"started_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Error       string                 `json:"error,omitempty"`
	CreatedBy   string                 `json:"created_by"`
}

// StepResult represents the result of a step execution.
type StepResult struct {
	StepID      string         `json:"step_id"`
	Status      Status         `json:"status"`
	Output      map[string]any `json:"output,omitempty"`
	Error       string         `json:"error,omitempty"`
	StartedAt   time.Time      `json:"started_at"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	Attempts    int            `json:"attempts"`
}

// Engine executes workflows.
type Engine struct {
	db        *pgxpool.Pool
	executor  *tool.Executor
	workflows map[string]*Workflow
	mu        sync.RWMutex
}

// NewEngine creates a new workflow engine.
func NewEngine(db *pgxpool.Pool, executor *tool.Executor) *Engine {
	return &Engine{
		db:        db,
		executor:  executor,
		workflows: make(map[string]*Workflow),
	}
}

// LoadWorkflows loads workflow definitions from directory.
func (e *Engine) LoadWorkflows(dir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading workflows dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("failed to read workflow", "path", path, "error", err)
			continue
		}

		var wf Workflow
		if err := yaml.Unmarshal(data, &wf); err != nil {
			slog.Warn("failed to parse workflow", "path", path, "error", err)
			continue
		}

		if wf.ID == "" {
			wf.ID = filepath.Base(entry.Name())
		}

		e.workflows[wf.ID] = &wf
		slog.Info("loaded workflow", "id", wf.ID, "name", wf.Name)
	}

	return nil
}

// GetWorkflow returns a workflow by ID.
func (e *Engine) GetWorkflow(id string) (*Workflow, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	wf, ok := e.workflows[id]
	return wf, ok
}

// ListWorkflows returns all loaded workflows.
func (e *Engine) ListWorkflows() []*Workflow {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]*Workflow, 0, len(e.workflows))
	for _, wf := range e.workflows {
		result = append(result, wf)
	}
	return result
}

// Execute runs a workflow.
func (e *Engine) Execute(ctx context.Context, workflowID string, inputs map[string]any, missionID *uuid.UUID, createdBy string) (*Execution, error) {
	wf, ok := e.GetWorkflow(workflowID)
	if !ok {
		return nil, fmt.Errorf("workflow not found: %s", workflowID)
	}

	exec := &Execution{
		ID:          uuid.New(),
		WorkflowID:  workflowID,
		MissionID:   missionID,
		Status:      StatusRunning,
		Variables:   mergeMaps(wf.Variables, inputs),
		StepResults: make(map[string]*StepResult),
		StartedAt:   time.Now(),
		CreatedBy:   createdBy,
	}

	// Save execution to database
	if err := e.saveExecution(ctx, exec); err != nil {
		return nil, err
	}

	// Execute in background
	go e.runWorkflow(context.Background(), wf, exec)

	return exec, nil
}

// runWorkflow executes the workflow steps.
func (e *Engine) runWorkflow(ctx context.Context, wf *Workflow, exec *Execution) {
	defer func() {
		now := time.Now()
		exec.CompletedAt = &now
		if exec.Status == StatusRunning {
			exec.Status = StatusCompleted
		}
		e.updateExecution(ctx, exec)
	}()

	slog.Info("starting workflow execution", "execution_id", exec.ID, "workflow_id", wf.ID)

	// Execute steps respecting dependencies
	completed := make(map[string]bool)
	failed := make(map[string]bool)

	for len(completed) < len(wf.Steps) {
		select {
		case <-ctx.Done():
			exec.Status = StatusCancelled
			return
		default:
		}

		// Find steps ready to execute
		var ready []*Step
		for i := range wf.Steps {
			step := &wf.Steps[i]
			if completed[step.ID] || failed[step.ID] {
				continue
			}

			// Check dependencies
			depsMet := true
			for _, depID := range step.DependsOn {
				if !completed[depID] {
					depsMet = false
					break
				}
				// Check if dependency failed
				if result, ok := exec.StepResults[depID]; ok && result.Status == StatusFailed {
					if step.OnError != "continue" {
						depsMet = false
						break
					}
				}
			}

			if depsMet {
				ready = append(ready, step)
			}
		}

		if len(ready) == 0 {
			// Check for circular dependencies or stuck state
			if len(completed) < len(wf.Steps) {
				slog.Error("workflow stuck, possible circular dependency", "execution_id", exec.ID)
				exec.Status = StatusFailed
				exec.Error = "workflow stuck: possible circular dependency"
				return
			}
			break
		}

		// Execute ready steps
		var wg sync.WaitGroup
		for _, step := range ready {
			if step.Type == StepTypeParallel && len(step.Parallel) > 0 {
				// Execute parallel steps
				for i := range step.Parallel {
					parallelStep := &step.Parallel[i]
					wg.Add(1)
					go func(s *Step) {
						defer wg.Done()
						e.executeStep(ctx, wf, exec, s)
						if result, ok := exec.StepResults[s.ID]; ok {
							if result.Status == StatusCompleted {
								completed[s.ID] = true
							} else {
								failed[s.ID] = true
							}
						}
					}(parallelStep)
				}
			} else {
				// Execute sequentially
				e.executeStep(ctx, wf, exec, step)
				if result, ok := exec.StepResults[step.ID]; ok {
					if result.Status == StatusCompleted {
						completed[step.ID] = true
					} else {
						failed[step.ID] = true
						if wf.OnError != "continue" && step.OnError != "continue" {
							exec.Status = StatusFailed
							exec.Error = fmt.Sprintf("step %s failed: %s", step.ID, result.Error)
							return
						}
					}
				}
			}
		}
		wg.Wait()
	}

	slog.Info("workflow completed", "execution_id", exec.ID, "status", exec.Status)
}

// executeStep executes a single step.
func (e *Engine) executeStep(ctx context.Context, wf *Workflow, exec *Execution, step *Step) {
	result := &StepResult{
		StepID:    step.ID,
		Status:    StatusRunning,
		StartedAt: time.Now(),
	}
	exec.StepResults[step.ID] = result

	slog.Info("executing step", "execution_id", exec.ID, "step_id", step.ID, "type", step.Type)

	// Evaluate condition
	if step.Condition != "" {
		if !e.evaluateCondition(step.Condition, exec.Variables) {
			result.Status = StatusSkipped
			now := time.Now()
			result.CompletedAt = &now
			return
		}
	}

	// Handle loops
	if step.Loop != nil {
		e.executeLoop(ctx, wf, exec, step, result)
		return
	}

	// Execute based on type
	switch step.Type {
	case StepTypeTool:
		e.executeToolStep(ctx, exec, step, result)
	case StepTypeWorkflow:
		e.executeSubWorkflow(ctx, exec, step, result)
	case StepTypeScript:
		e.executeScriptStep(ctx, exec, step, result)
	case StepTypeWait:
		e.executeWaitStep(ctx, exec, step, result)
	case StepTypeNotify:
		e.executeNotifyStep(ctx, exec, step, result)
	default:
		result.Status = StatusFailed
		result.Error = fmt.Sprintf("unknown step type: %s", step.Type)
	}

	now := time.Now()
	result.CompletedAt = &now
	e.updateExecution(ctx, exec)
}

// executeLoop handles loop execution.
func (e *Engine) executeLoop(ctx context.Context, wf *Workflow, exec *Execution, step *Step, result *StepResult) {
	loopVar := step.Loop.As
	if loopVar == "" {
		loopVar = "item"
	}

	var items []any
	if len(step.Loop.Items) > 0 {
		items = step.Loop.Items
	} else if step.Loop.Range != nil {
		r := step.Loop.Range
		stepVal := r.Step
		if stepVal == 0 {
			stepVal = 1
		}
		for i := r.Start; i < r.End; i += stepVal {
			items = append(items, i)
		}
	}

	for i, item := range items {
		exec.Variables[loopVar] = item
		exec.Variables["index"] = i
		e.executeStep(ctx, wf, exec, step)
	}

	result.Status = StatusCompleted
	delete(exec.Variables, loopVar)
	delete(exec.Variables, "index")
}

// executeToolStep executes a tool step.
func (e *Engine) executeToolStep(ctx context.Context, exec *Execution, step *Step, result *StepResult) {
	if step.Tool == "" {
		result.Status = StatusFailed
		result.Error = "tool not specified"
		return
	}

	// Process inputs with variable substitution
	inputs := make(map[string]any)
	for k, v := range step.Inputs {
		inputs[k] = e.interpolateValue(v, exec.Variables)
	}

	// Execute tool
	toolResult, err := e.executor.Execute(ctx, step.Tool, inputs, exec.MissionID, nil)
	if err != nil {
		result.Status = StatusFailed
		result.Error = err.Error()

		// Handle retry
		if step.Retry != nil && result.Attempts < step.Retry.MaxAttempts {
			result.Attempts++
			delay := step.Retry.Delay
			if step.Retry.Backoff == "exponential" {
				delay = delay * time.Duration(1<<uint(result.Attempts-1))
			}
			time.Sleep(delay)
			e.executeToolStep(ctx, exec, step, result)
		}
		return
	}

	result.Status = StatusCompleted
	result.Output = map[string]any{
		"stdout": toolResult.Stdout,
		"stderr": toolResult.Stderr,
		"exit_code": toolResult.ExitCode,
	}

	// Process outputs
	for varName, outputKey := range step.Outputs {
		if outputKey == "stdout" {
			exec.Variables[varName] = toolResult.Stdout
		} else if outputKey == "stderr" {
			exec.Variables[varName] = toolResult.Stderr
		}
	}
}

// executeSubWorkflow executes a nested workflow.
func (e *Engine) executeSubWorkflow(ctx context.Context, exec *Execution, step *Step, result *StepResult) {
	subExec, err := e.Execute(ctx, step.Workflow, step.Inputs, exec.MissionID, exec.CreatedBy)
	if err != nil {
		result.Status = StatusFailed
		result.Error = err.Error()
		return
	}

	// Wait for completion (in real implementation, this would be async)
	for subExec.Status == StatusRunning {
		time.Sleep(100 * time.Millisecond)
	}

	result.Status = subExec.Status
	if subExec.Status == StatusFailed {
		result.Error = subExec.Error
	}
}

// executeScriptStep executes a custom script.
func (e *Engine) executeScriptStep(ctx context.Context, exec *Execution, step *Step, result *StepResult) {
	// TODO: Implement script execution (Python, JavaScript, etc.)
	result.Status = StatusCompleted
	result.Output = map[string]any{"message": "script execution not yet implemented"}
}

// executeWaitStep waits for a specified duration.
func (e *Engine) executeWaitStep(ctx context.Context, exec *Execution, step *Step, result *StepResult) {
	duration := step.Timeout
	if duration == 0 {
		duration = 5 * time.Second
	}

	select {
	case <-time.After(duration):
		result.Status = StatusCompleted
	case <-ctx.Done():
		result.Status = StatusCancelled
	}
}

// executeNotifyStep sends a notification.
func (e *Engine) executeNotifyStep(ctx context.Context, exec *Execution, step *Step, result *StepResult) {
	// TODO: Implement notification logic
	message := ""
	if msg, ok := step.Inputs["message"].(string); ok {
		message = e.interpolateString(msg, exec.Variables)
	}
	slog.Info("workflow notification", "execution_id", exec.ID, "message", message)
	result.Status = StatusCompleted
}

// evaluateCondition evaluates a condition expression.
func (e *Engine) evaluateCondition(condition string, vars map[string]any) bool {
	// Simple condition evaluation - can be extended with proper expression parser
	// For now, check if variable exists and is truthy
	val, ok := vars[condition]
	if !ok {
		return false
	}

	switch v := val.(type) {
	case bool:
		return v
	case string:
		return v != ""
	case int, int64:
		return v != 0
	default:
		return true
	}
}

// interpolateValue substitutes variables in a value.
func (e *Engine) interpolateValue(value any, vars map[string]any) any {
	switch v := value.(type) {
	case string:
		return e.interpolateString(v, vars)
	case map[string]any:
		result := make(map[string]any)
		for k, val := range v {
			result[k] = e.interpolateValue(val, vars)
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, val := range v {
			result[i] = e.interpolateValue(val, vars)
		}
		return result
	default:
		return value
	}
}

// interpolateString substitutes variables in a string.
func (e *Engine) interpolateString(s string, vars map[string]any) string {
	// Simple variable substitution: ${var_name}
	// TODO: Use proper template engine
	for key, val := range vars {
		placeholder := fmt.Sprintf("${%s}", key)
		s = replaceString(s, placeholder, fmt.Sprintf("%v", val))
	}
	return s
}

func replaceString(s, old, new string) string {
	// Simple string replacement
	result := ""
	i := 0
	for i < len(s) {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			result += new
			i += len(old)
		} else {
			result += string(s[i])
			i++
		}
	}
	return result
}

// buildDependencyGraph builds a dependency map.
func (e *Engine) buildDependencyGraph(steps []Step) map[string][]string {
	deps := make(map[string][]string)
	for _, step := range steps {
		deps[step.ID] = step.DependsOn
	}
	return deps
}

// mergeMaps merges multiple maps.
func mergeMaps(maps ...map[string]any) map[string]any {
	result := make(map[string]any)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// saveExecution saves execution to database.
func (e *Engine) saveExecution(ctx context.Context, exec *Execution) error {
	_, err := e.db.Exec(ctx,
		`INSERT INTO workflow_executions (id, workflow_id, mission_id, status, variables, step_results, started_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		exec.ID, exec.WorkflowID, exec.MissionID, exec.Status,
		exec.Variables, exec.StepResults, exec.StartedAt, exec.CreatedBy,
	)
	return err
}

// updateExecution updates execution in database.
func (e *Engine) updateExecution(ctx context.Context, exec *Execution) error {
	_, err := e.db.Exec(ctx,
		`UPDATE workflow_executions
		 SET status = $1, step_results = $2, completed_at = $3, error = $4
		 WHERE id = $5`,
		exec.Status, exec.StepResults, exec.CompletedAt, exec.Error, exec.ID,
	)
	return err
}

// GetExecution retrieves an execution by ID.
func (e *Engine) GetExecution(ctx context.Context, id uuid.UUID) (*Execution, error) {
	var exec Execution
	var missionID *uuid.UUID

	err := e.db.QueryRow(ctx,
		`SELECT id, workflow_id, mission_id, status, variables, step_results, started_at, completed_at, error, created_by
		 FROM workflow_executions WHERE id = $1`,
		id,
	).Scan(&exec.ID, &exec.WorkflowID, &missionID, &exec.Status,
		&exec.Variables, &exec.StepResults, &exec.StartedAt,
		&exec.CompletedAt, &exec.Error, &exec.CreatedBy)

	if err != nil {
		return nil, err
	}

	exec.MissionID = missionID
	return &exec, nil
}

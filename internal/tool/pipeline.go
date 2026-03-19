package tool

import (
	"strings"
)

// PipelineResult holds the processed output of a tool execution.
type PipelineResult struct {
	Summary      string   `json:"summary"`
	IsSuccess    bool     `json:"is_success"`
	Findings     []string `json:"findings,omitempty"`
	SeverityHits map[string][]string `json:"severity_hits,omitempty"`
	TruncatedTo  int      `json:"truncated_to,omitempty"`
	OriginalSize int      `json:"original_size"`
}

// ProcessOutput runs the result pipeline on raw tool output.
// It checks success/failure patterns, extracts severity indicators,
// and handles large outputs.
func ProcessOutput(def *Definition, result *ExecResult) *PipelineResult {
	output := result.Stdout
	pr := &PipelineResult{
		OriginalSize: len(output),
		SeverityHits: make(map[string][]string),
	}

	// Size-based handling
	const (
		directLimit    = 50 * 1024    // 50KB - include directly
		summarizeLimit = 500 * 1024   // 500KB - summarize
	)

	if len(output) > summarizeLimit {
		// Truncate very large outputs
		output = output[:summarizeLimit]
		pr.TruncatedTo = summarizeLimit
	}

	// Check success patterns
	for _, pattern := range def.Output.SuccessPatterns {
		if strings.Contains(strings.ToLower(output), strings.ToLower(pattern)) {
			pr.IsSuccess = true
			pr.Findings = append(pr.Findings, pattern)
		}
	}

	// Check failure patterns
	if !pr.IsSuccess {
		for _, pattern := range def.Output.FailurePatterns {
			if strings.Contains(strings.ToLower(output), strings.ToLower(pattern)) {
				pr.IsSuccess = false
				break
			}
		}
	}

	// Check severity indicators
	for severity, patterns := range def.Output.SeverityIndicators {
		for _, pattern := range patterns {
			if strings.Contains(strings.ToLower(output), strings.ToLower(pattern)) {
				pr.SeverityHits[severity] = append(pr.SeverityHits[severity], pattern)
			}
		}
	}

	// Generate summary
	if len(output) > directLimit {
		// Extract key lines for summary
		lines := strings.Split(output, "\n")
		var keyLines []string
		for _, line := range lines {
			lower := strings.ToLower(line)
			for _, pattern := range def.Output.SuccessPatterns {
				if strings.Contains(lower, strings.ToLower(pattern)) {
					keyLines = append(keyLines, strings.TrimSpace(line))
					break
				}
			}
			if len(keyLines) >= 50 {
				break
			}
		}
		pr.Summary = strings.Join(keyLines, "\n")
	} else {
		pr.Summary = output
	}

	return pr
}

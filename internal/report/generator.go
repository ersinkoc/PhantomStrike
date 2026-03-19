// Package report provides report generation for security assessments.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Generator handles report generation in various formats.
type Generator struct {
	missionID   uuid.UUID
	missionName string
	createdAt   time.Time
}

// NewGenerator creates a new report generator.
func NewGenerator(missionID uuid.UUID, missionName string) *Generator {
	return &Generator{
		missionID:   missionID,
		missionName: missionName,
		createdAt:   time.Now(),
	}
}

// Vulnerability represents a finding in the report.
type Vulnerability struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Description        string   `json:"description"`
	Severity           string   `json:"severity"`
	CVSSScore          *float64 `json:"cvss_score,omitempty"`
	CVSSVector         string   `json:"cvss_vector,omitempty"`
	Target             string   `json:"target"`
	AffectedComponent  string   `json:"affected_component,omitempty"`
	Evidence           string   `json:"evidence,omitempty"`
	Remediation        string   `json:"remediation,omitempty"`
	CVEIDs             []string `json:"cve_ids,omitempty"`
	CWEID              string   `json:"cwe_id,omitempty"`
	FoundBy            string   `json:"found_by"`
	CreatedAt          string   `json:"created_at"`
}

// Summary provides aggregate statistics.
type Summary struct {
	Total        int            `json:"total"`
	BySeverity   map[string]int `json:"by_severity"`
	ByCategory   map[string]int `json:"by_category,omitempty"`
}

// Data contains all information needed for report generation.
type Data struct {
	MissionID       uuid.UUID         `json:"mission_id"`
	MissionName     string            `json:"mission_name"`
	MissionDesc     string            `json:"mission_description,omitempty"`
	Target          map[string]any    `json:"target,omitempty"`
	StartTime       *time.Time        `json:"start_time,omitempty"`
	EndTime         *time.Time        `json:"end_time,omitempty"`
	GeneratedAt     time.Time         `json:"generated_at"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
	Summary         Summary           `json:"summary"`
	AttackChain     []ChainNode       `json:"attack_chain,omitempty"`
}

// ChainNode represents a node in the attack chain.
type ChainNode struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Label    string `json:"label"`
	Severity string `json:"severity,omitempty"`
	Phase    string `json:"phase,omitempty"`
}

// GenerateJSON creates a JSON report.
func (g *Generator) GenerateJSON(data *Data) ([]byte, error) {
	data.GeneratedAt = g.createdAt
	data.MissionID = g.missionID
	data.MissionName = g.missionName
	return json.MarshalIndent(data, "", "  ")
}

// GenerateMarkdown creates a Markdown report.
func (g *Generator) GenerateMarkdown(data *Data) []byte {
	var b strings.Builder

	// Header
	b.WriteString("# Security Assessment Report\n\n")
	b.WriteString(fmt.Sprintf("**Mission:** %s\n\n", html.EscapeString(g.missionName)))
	if data.MissionDesc != "" {
		b.WriteString(fmt.Sprintf("**Description:** %s\n\n", html.EscapeString(data.MissionDesc)))
	}
	b.WriteString(fmt.Sprintf("**Report ID:** %s\n\n", g.missionID))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n\n", g.createdAt.Format(time.RFC3339)))

	// Target info
	if len(data.Target) > 0 {
		b.WriteString("## Target\n\n")
		if scope, ok := data.Target["scope"].([]any); ok {
			b.WriteString("**Scope:**\n")
			for _, s := range scope {
				b.WriteString(fmt.Sprintf("- %v\n", s))
			}
			b.WriteString("\n")
		}
	}

	// Executive Summary
	b.WriteString("## Executive Summary\n\n")
	b.WriteString(fmt.Sprintf("Total vulnerabilities found: **%d**\n\n", data.Summary.Total))

	if data.Summary.Total > 0 {
		b.WriteString("### Severity Breakdown\n\n")
		b.WriteString("| Severity | Count |\n")
		b.WriteString("|----------|-------|\n")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count := data.Summary.BySeverity[sev]; count > 0 {
				emoji := getSeverityEmoji(sev)
				b.WriteString(fmt.Sprintf("| %s %s | %d |\n", emoji, strings.ToUpper(sev), count))
			}
		}
		b.WriteString("\n")
	}

	// Timeline
	if data.StartTime != nil {
		b.WriteString("### Timeline\n\n")
		b.WriteString(fmt.Sprintf("- **Started:** %s\n", data.StartTime.Format(time.RFC3339)))
		if data.EndTime != nil {
			b.WriteString(fmt.Sprintf("- **Completed:** %s\n", data.EndTime.Format(time.RFC3339)))
			duration := data.EndTime.Sub(*data.StartTime)
			b.WriteString(fmt.Sprintf("- **Duration:** %s\n", formatDuration(duration)))
		}
		b.WriteString("\n")
	}

	// Detailed Findings
	if len(data.Vulnerabilities) > 0 {
		b.WriteString("## Detailed Findings\n\n")

		// Group by severity
		bySeverity := make(map[string][]Vulnerability)
		for _, v := range data.Vulnerabilities {
			bySeverity[v.Severity] = append(bySeverity[v.Severity], v)
		}

		// Output in severity order
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			vulns := bySeverity[sev]
			if len(vulns) == 0 {
				continue
			}

			b.WriteString(fmt.Sprintf("### %s %s (%d)\n\n", getSeverityEmoji(sev), strings.ToUpper(sev), len(vulns)))

			for i, v := range vulns {
				b.WriteString(fmt.Sprintf("#### %d. %s\n\n", i+1, html.EscapeString(v.Title)))

				// Metadata table
				b.WriteString("| Field | Value |\n")
				b.WriteString("|-------|-------|\n")
				if v.CVSSScore != nil {
					b.WriteString(fmt.Sprintf("| CVSS Score | %.1f |\n", *v.CVSSScore))
				}
				if v.CVSSVector != "" {
					b.WriteString(fmt.Sprintf("| CVSS Vector | %s |\n", v.CVSSVector))
				}
				if v.Target != "" {
					b.WriteString(fmt.Sprintf("| Target | %s |\n", html.EscapeString(v.Target)))
				}
				if v.AffectedComponent != "" {
					b.WriteString(fmt.Sprintf("| Component | %s |\n", html.EscapeString(v.AffectedComponent)))
				}
				if v.CWEID != "" {
					b.WriteString(fmt.Sprintf("| CWE | %s |\n", v.CWEID))
				}
				if len(v.CVEIDs) > 0 {
					b.WriteString(fmt.Sprintf("| CVEs | %s |\n", strings.Join(v.CVEIDs, ", ")))
				}
				if v.FoundBy != "" {
					b.WriteString(fmt.Sprintf("| Found By | %s |\n", html.EscapeString(v.FoundBy)))
				}
				b.WriteString(fmt.Sprintf("| Discovered | %s |\n", v.CreatedAt))
				b.WriteString("\n")

				// Description
				if v.Description != "" {
					b.WriteString(fmt.Sprintf("**Description:**\n\n%s\n\n", html.EscapeString(v.Description)))
				}

				// Evidence
				if v.Evidence != "" {
					b.WriteString("**Evidence:**\n\n")
					b.WriteString("```\n")
					b.WriteString(html.EscapeString(v.Evidence))
					b.WriteString("\n```\n\n")
				}

				// Remediation
				if v.Remediation != "" {
					b.WriteString(fmt.Sprintf("**Remediation:**\n\n%s\n\n", html.EscapeString(v.Remediation)))
				}

				b.WriteString("---\n\n")
			}
		}
	} else {
		b.WriteString("## Findings\n\nNo vulnerabilities were discovered during this assessment.\n\n")
	}

	// Methodology
	b.WriteString("## Methodology\n\n")
	b.WriteString("This security assessment was conducted using PhantomStrike, an AI-native")
	b.WriteString("autonomous security testing platform. The assessment included:\n\n")
	b.WriteString("- Automated reconnaissance\n")
	b.WriteString("- Vulnerability scanning\n")
	b.WriteString("- Configuration analysis\n")
	b.WriteString("- Security control testing\n\n")

	// Disclaimer
	b.WriteString("---\n\n")
	b.WriteString("*This report was generated automatically by PhantomStrike. ")
	b.WriteString("Manual verification of findings is recommended.*\n")

	return []byte(b.String())
}

// GenerateHTML creates an HTML report.
func (g *Generator) GenerateHTML(data *Data) []byte {
	var b bytes.Buffer

	// CSS styles
	css := `
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 40px 20px; line-height: 1.6; color: #333; }
h1 { color: #1a1a1a; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }
h2 { color: #2c3e50; margin-top: 30px; border-bottom: 2px solid #ecf0f1; padding-bottom: 8px; }
h3 { color: #34495e; }
h4 { color: #e74c3c; }
table { border-collapse: collapse; width: 100%; margin: 15px 0; }
th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
th { background-color: #f8f9fa; font-weight: 600; }
.critical { color: #e74c3c; font-weight: bold; }
.high { color: #e67e22; font-weight: bold; }
.medium { color: #f39c12; font-weight: bold; }
.low { color: #3498db; }
.info { color: #95a5a6; }
.severity-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
.badge-critical { background: #fee; color: #c0392b; }
.badge-high { background: #fff3cd; color: #856404; }
.badge-medium { background: #fff3cd; color: #856404; }
.badge-low { background: #d1ecf1; color: #0c5460; }
.badge-info { background: #e2e3e5; color: #383d41; }
pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; border: 1px solid #e9ecef; }
.summary-box { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }
.header-info { color: #6c757d; margin: 5px 0; }
.finding { border-left: 4px solid #e74c3c; padding-left: 20px; margin: 20px 0; }
</style>`

	b.WriteString("<!DOCTYPE html><html><head><meta charset='UTF-8'>")
	b.WriteString("<title>Security Assessment Report - ")
	b.WriteString(html.EscapeString(g.missionName))
	b.WriteString("</title>")
	b.WriteString(css)
	b.WriteString("</head><body>")

	// Header
	b.WriteString("<h1>Security Assessment Report</h1>")
	b.WriteString(fmt.Sprintf("<p class='header-info'><strong>Mission:</strong> %s</p>", html.EscapeString(g.missionName)))
	if data.MissionDesc != "" {
		b.WriteString(fmt.Sprintf("<p class='header-info'><strong>Description:</strong> %s</p>", html.EscapeString(data.MissionDesc)))
	}
	b.WriteString(fmt.Sprintf("<p class='header-info'><strong>Report ID:</strong> %s</p>", g.missionID))
	b.WriteString(fmt.Sprintf("<p class='header-info'><strong>Generated:</strong> %s</p>", g.createdAt.Format(time.RFC3339)))

	// Executive Summary
	b.WriteString("<h2>Executive Summary</h2>")
	b.WriteString(fmt.Sprintf("<p>Total vulnerabilities found: <strong>%d</strong></p>", data.Summary.Total))

	if data.Summary.Total > 0 {
		b.WriteString("<h3>Severity Breakdown</h3>")
		b.WriteString("<table>")
		b.WriteString("<tr><th>Severity</th><th>Count</th></tr>")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count := data.Summary.BySeverity[sev]; count > 0 {
				b.WriteString(fmt.Sprintf("<tr><td><span class='%s'>%s %s</span></td><td>%d</td></tr>",
					sev, getSeverityEmoji(sev), strings.ToUpper(sev), count))
			}
		}
		b.WriteString("</table>")
	}

	// Findings
	if len(data.Vulnerabilities) > 0 {
		b.WriteString("<h2>Detailed Findings</h2>")

		// Group by severity
		bySeverity := make(map[string][]Vulnerability)
		for _, v := range data.Vulnerabilities {
			bySeverity[v.Severity] = append(bySeverity[v.Severity], v)
		}

		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			vulns := bySeverity[sev]
			if len(vulns) == 0 {
				continue
			}

			b.WriteString(fmt.Sprintf("<h3><span class='badge badge-%s'>%s</span> %s (%d)</h3>",
				sev, strings.ToUpper(sev), getSeverityEmoji(sev), len(vulns)))

			for _, v := range vulns {
				b.WriteString("<div class='finding'>")
				b.WriteString(fmt.Sprintf("<h4>%s</h4>", html.EscapeString(v.Title)))

				b.WriteString("<table>")
				if v.CVSSScore != nil {
					b.WriteString(fmt.Sprintf("<tr><td>CVSS Score</td><td>%.1f</td></tr>", *v.CVSSScore))
				}
				if v.Target != "" {
					b.WriteString(fmt.Sprintf("<tr><td>Target</td><td>%s</td></tr>", html.EscapeString(v.Target)))
				}
				if v.FoundBy != "" {
					b.WriteString(fmt.Sprintf("<tr><td>Found By</td><td>%s</td></tr>", html.EscapeString(v.FoundBy)))
				}
				b.WriteString("</table>")

				if v.Description != "" {
					b.WriteString(fmt.Sprintf("<p><strong>Description:</strong></p><p>%s</p>",
						html.EscapeString(v.Description)))
				}
				if v.Evidence != "" {
					b.WriteString("<p><strong>Evidence:</strong></p><pre>")
					b.WriteString(html.EscapeString(v.Evidence))
					b.WriteString("</pre>")
				}
				if v.Remediation != "" {
					b.WriteString(fmt.Sprintf("<p><strong>Remediation:</strong></p><p>%s</p>",
						html.EscapeString(v.Remediation)))
				}

				b.WriteString("</div>")
			}
		}
	}

	// Footer
	b.WriteString("<hr><p><small><em>This report was generated automatically by PhantomStrike.</em></small></p>")
	b.WriteString("</body></html>")

	return b.Bytes()
}

// Helper functions
func getSeverityEmoji(severity string) string {
	switch severity {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	case "info":
		return "ℹ️"
	default:
		return "⚪"
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

// Package compliance provides vulnerability classification and reporting for security standards.
package compliance

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Framework represents a compliance framework.
type Framework string

const (
	FrameworkOWASPTop10    Framework = "owasp-top-10"
	FrameworkOWASPTop102021 Framework = "owasp-top-10-2021"
	FrameworkCWE25         Framework = "cwe-top-25"
	FrameworkNISTCSF       Framework = "nist-csf"
	FrameworkCISControls   Framework = "cis-controls"
	FrameworkISO27001      Framework = "iso-27001"
	FrameworkGDPR          Framework = "gdpr"
	FrameworkPCIDSS        Framework = "pci-dss"
	FrameworkHIPAA         Framework = "hipaa"
)

// Requirement represents a specific requirement in a framework.
type Requirement struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Controls    []string `json:"controls"`
	CWEMappings []int    `json:"cwe_mappings"`
}

// ComplianceReport represents a compliance assessment report.
type ComplianceReport struct {
	Framework    Framework              `json:"framework"`
	Version      string                 `json:"version"`
	TotalVulns   int                    `json:"total_vulnerabilities"`
	Requirements []RequirementResult    `json:"requirements"`
	Score        float64                `json:"compliance_score"`
	Summary      map[string]int         `json:"summary"`
	Findings     []Finding              `json:"findings"`
}

// RequirementResult shows compliance status for a requirement.
type RequirementResult struct {
	Requirement     Requirement `json:"requirement"`
	Status          string      `json:"status"` // compliant, partial, non-compliant
	Vulnerabilities []int       `json:"vulnerabilities"` // Vuln IDs
	Evidence        string      `json:"evidence"`
	Remediation     string      `json:"remediation"`
}

// Finding represents a compliance finding.
type Finding struct {
	VulnID      string `json:"vuln_id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	FrameworkID string `json:"framework_id"`
	Control     string `json:"control"`
	Status      string `json:"status"`
}

// Mapper provides compliance mapping functionality.
type Mapper struct {
	pool *pgxpool.Pool
}

// NewMapper creates a new compliance mapper.
func NewMapper(pool *pgxpool.Pool) *Mapper {
	return &Mapper{pool: pool}
}

// GetRequirements returns requirements for a framework.
func (m *Mapper) GetRequirements(framework Framework) []Requirement {
	switch framework {
	case FrameworkOWASPTop10:
		return getOWASPTop10Requirements()
	case FrameworkCWE25:
		return getCWETop25Requirements()
	case FrameworkNISTCSF:
		return getNISTCSFRequirements()
	default:
		return nil
	}
}

// MapVulnerability maps a vulnerability to compliance frameworks.
func (m *Mapper) MapVulnerability(vuln map[string]any) []FrameworkMapping {
	var mappings []FrameworkMapping

	title := getString(vuln, "title")
	description := getString(vuln, "description")
	cweID := getString(vuln, "cwe_id")

	// Check against OWASP Top 10
	for _, req := range getOWASPTop10Requirements() {
		if matchesPattern(title, description, req) {
			mappings = append(mappings, FrameworkMapping{
				Framework:     FrameworkOWASPTop10,
				RequirementID: req.ID,
				Title:         req.Title,
			})
		}
	}

	// Check CWE mapping
	if cweID != "" {
		mappings = append(mappings, FrameworkMapping{
			Framework:     FrameworkCWE25,
			RequirementID: cweID,
			Title:         fmt.Sprintf("CWE-%s", cweID),
		})
	}

	return mappings
}

// GenerateReport generates a compliance report.
func (m *Mapper) GenerateReport(ctx context.Context, missionID string, framework Framework) (*ComplianceReport, error) {
	requirements := m.GetRequirements(framework)
	if requirements == nil {
		return nil, fmt.Errorf("unknown framework: %s", framework)
	}

	// Get mission vulnerabilities
	rows, err := m.pool.Query(ctx,
		`SELECT id, title, description, severity, cwe_id, cvss_score
		 FROM vulnerabilities WHERE mission_id = $1`,
		missionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var vulns []map[string]any
	for rows.Next() {
		var id, title, description, severity, cweID string
		var cvssScore *float64
		if err := rows.Scan(&id, &title, &description, &severity, &cweID, &cvssScore); err != nil {
			continue
		}
		vulns = append(vulns, map[string]any{
			"id":          id,
			"title":       title,
			"description": description,
			"severity":    severity,
			"cwe_id":      cweID,
			"cvss_score":  cvssScore,
		})
	}

	// Map vulnerabilities to requirements
	report := &ComplianceReport{
		Framework:    framework,
		Version:      "1.0",
		TotalVulns:   len(vulns),
		Requirements: make([]RequirementResult, 0, len(requirements)),
		Summary:      make(map[string]int),
		Findings:     []Finding{},
	}

	for _, req := range requirements {
		result := RequirementResult{
			Requirement: req,
			Status:      "compliant",
		}

		// Find matching vulnerabilities
		for _, vuln := range vulns {
			if matchesPattern(getString(vuln, "title"), getString(vuln, "description"), req) {
				result.Status = "non-compliant"
				result.Vulnerabilities = append(result.Vulnerabilities, getInt(vuln, "id"))

				report.Findings = append(report.Findings, Finding{
					VulnID:      getString(vuln, "id"),
					Title:       getString(vuln, "title"),
					Severity:    getString(vuln, "severity"),
					FrameworkID: req.ID,
					Control:     req.Title,
					Status:      "open",
				})
			}
		}

		report.Requirements = append(report.Requirements, result)
		report.Summary[result.Status]++
	}

	// Calculate score
	if len(report.Requirements) > 0 {
		compliant := report.Summary["compliant"]
		report.Score = float64(compliant) / float64(len(report.Requirements)) * 100
	}

	return report, nil
}

// FrameworkMapping represents a mapping to a framework requirement.
type FrameworkMapping struct {
	Framework     Framework `json:"framework"`
	RequirementID string    `json:"requirement_id"`
	Title         string    `json:"title"`
}

// matchesPattern checks if a vulnerability matches a requirement pattern.
func matchesPattern(title, description string, req Requirement) bool {
	// Simple keyword matching - can be enhanced with NLP
	keywords := req.Controls
	text := strings.ToLower(title + " " + description)

	for _, kw := range keywords {
		if strings.Contains(text, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// getOWASPTop10Requirements returns OWASP Top 10 2021 requirements.
func getOWASPTop10Requirements() []Requirement {
	return []Requirement{
		{
			ID:          "A01:2021",
			Title:       "Broken Access Control",
			Description: "Restrictions on authenticated users are not properly enforced",
			Category:    "Access Control",
			Controls:    []string{"access control", "authorization", "permission", "privilege", "idor", "path traversal"},
			CWEMappings: []int{22, 285, 639, 284},
		},
		{
			ID:          "A02:2021",
			Title:       "Cryptographic Failures",
			Description: "Failures related to cryptography leading to sensitive data exposure",
			Category:    "Cryptography",
			Controls:    []string{"cryptography", "encryption", "ssl", "tls", "hash", "cipher", "certificate"},
			CWEMappings: []int{259, 327, 331},
		},
		{
			ID:          "A03:2021",
			Title:       "Injection",
			Description: "User-supplied data is not validated, filtered or sanitized",
			Category:    "Injection",
			Controls:    []string{"sql injection", "xss", "command injection", "ldap injection", "nosql injection"},
			CWEMappings: []int{79, 89, 73, 91},
		},
		{
			ID:          "A04:2021",
			Title:       "Insecure Design",
			Description: "Missing or ineffective control design",
			Category:    "Design",
			Controls:    []string{"design flaw", "architecture", "threat model"},
			CWEMappings: []int{209, 256, 501},
		},
		{
			ID:          "A05:2021",
			Title:       "Security Misconfiguration",
			Description: "Insecure default configurations, incomplete configurations, or misconfigured HTTP headers",
			Category:    "Configuration",
			Controls:    []string{"misconfiguration", "default password", "error handling", "stack trace", "debug"},
			CWEMappings: []int{16, 611, 215},
		},
		{
			ID:          "A06:2021",
			Title:       "Vulnerable and Outdated Components",
			Description: "Using components with known vulnerabilities",
			Category:    "Components",
			Controls:    []string{"outdated", "vulnerable component", "dependency", "version"},
			CWEMappings: []int{1035, 937, 1036},
		},
		{
			ID:          "A07:2021",
			Title:       "Identification and Authentication Failures",
			Description: "Authentication-related attacks",
			Category:    "Authentication",
			Controls:    []string{"authentication", "session", "password", "brute force", "credential stuffing"},
			CWEMappings: []int{287, 384, 522},
		},
		{
			ID:          "A08:2021",
			Title:       "Software and Data Integrity Failures",
			Description: "Assumption of software updates and CI/CD pipeline integrity",
			Category:    "Integrity",
			Controls:    []string{"integrity", "ci/cd", "deserialization", "insecure deserialization"},
			CWEMappings: []int{494, 502, 829},
		},
		{
			ID:          "A09:2021",
			Title:       "Security Logging and Monitoring Failures",
			Description: "Insufficient logging and monitoring",
			Category:    "Logging",
			Controls:    []string{"logging", "monitoring", "audit", "alert"},
			CWEMappings: []int{778, 223, 532},
		},
		{
			ID:          "A10:2021",
			Title:       "Server-Side Request Forgery (SSRF)",
			Description: "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL",
			Category:    "SSRF",
			Controls:    []string{"ssrf", "request forgery", "url validation"},
			CWEMappings: []int{918, 611},
		},
	}
}

// getCWETop25Requirements returns CWE Top 25 requirements.
func getCWETop25Requirements() []Requirement {
	return []Requirement{
		{
			ID:          "CWE-787",
			Title:       "Out-of-bounds Write",
			Description: "Software writes data past the end, or before the beginning, of the intended buffer",
			Category:    "Memory",
			Controls:    []string{"buffer overflow", "memory corruption"},
		},
		{
			ID:          "CWE-79",
			Title:       "Cross-site Scripting (XSS)",
			Description: "Improper neutralization of input during web page generation",
			Category:    "Injection",
			Controls:    []string{"xss", "cross site scripting", "javascript injection"},
		},
		{
			ID:          "CWE-89",
			Title:       "SQL Injection",
			Description: "Improper neutralization of special elements in SQL commands",
			Category:    "Injection",
			Controls:    []string{"sql injection", "sqli", "database injection"},
		},
		// Add more CWE-25 items as needed
	}
}

// getNISTCSFRequirements returns NIST Cybersecurity Framework requirements.
func getNISTCSFRequirements() []Requirement {
	return []Requirement{
		{
			ID:          "PR.AC-1",
			Title:       "Identity Management",
			Description: "Identities and credentials are issued, managed, verified, revoked, and audited",
			Category:    "Protect",
			Controls:    []string{"identity", "authentication", "credential"},
		},
		{
			ID:          "PR.AC-4",
			Title:       "Access Permissions",
			Description: "Access permissions and authorizations are managed",
			Category:    "Protect",
			Controls:    []string{"access control", "authorization", "permission"},
		},
		{
			ID:          "DE.AE-1",
			Title:       "Anomalies and Events",
			Description: "A baseline of network operations and expected data flows is established",
			Category:    "Detect",
			Controls:    []string{"anomaly detection", "monitoring", "baseline"},
		},
		// Add more NIST CSF items as needed
	}
}

// Helper functions
func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getInt(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

// ExportReport exports compliance report in various formats.
func (m *Mapper) ExportReport(report *ComplianceReport, format string) ([]byte, error) {
	switch format {
	case "json":
		return json.MarshalIndent(report, "", "  ")
	case "summary":
		return m.generateSummary(report)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// generateSummary creates a text summary of the compliance report.
func (m *Mapper) generateSummary(report *ComplianceReport) ([]byte, error) {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# %s Compliance Report\n\n", report.Framework))
	sb.WriteString(fmt.Sprintf("**Compliance Score:** %.1f%%\n\n", report.Score))
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- Total Vulnerabilities: %d\n", report.TotalVulns))
	sb.WriteString(fmt.Sprintf("- Compliant Requirements: %d\n", report.Summary["compliant"]))
	sb.WriteString(fmt.Sprintf("- Non-Compliant: %d\n", report.Summary["non-compliant"]))
	sb.WriteString(fmt.Sprintf("- Partially Compliant: %d\n\n", report.Summary["partial"]))

	sb.WriteString("## Findings by Requirement\n\n")
	for _, req := range report.Requirements {
		status := "✅"
		if req.Status == "non-compliant" {
			status = "❌"
		} else if req.Status == "partial" {
			status = "⚠️"
		}
		sb.WriteString(fmt.Sprintf("%s **%s** - %s (%d findings)\n",
			status, req.Requirement.ID, req.Requirement.Title, len(req.Vulnerabilities)))
	}

	return []byte(sb.String()), nil
}

// ImportFramework imports a custom compliance framework.
func (m *Mapper) ImportFramework(ctx context.Context, data []byte) error {
	// TODO: Implement custom framework import
	return nil
}

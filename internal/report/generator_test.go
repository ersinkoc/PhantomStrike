package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleData() *Data {
	score := 9.8
	return &Data{
		MissionDesc: "Penetration test of example.com",
		Target: map[string]any{
			"scope": []any{"example.com", "api.example.com"},
		},
		Vulnerabilities: []Vulnerability{
			{
				ID:          "VULN-001",
				Title:       "SQL Injection in Login",
				Description: "The login endpoint is vulnerable to SQL injection.",
				Severity:    "critical",
				CVSSScore:   &score,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				Target:      "example.com",
				Evidence:    "' OR 1=1 --",
				Remediation: "Use parameterized queries.",
				CVEIDs:      []string{"CVE-2024-0001"},
				CWEID:       "CWE-89",
				FoundBy:     "sqlmap",
				CreatedAt:   "2025-01-15T10:30:00Z",
			},
			{
				ID:          "VULN-002",
				Title:       "Missing HSTS Header",
				Description: "The server does not set the HSTS header.",
				Severity:    "low",
				Target:      "example.com",
				Remediation: "Add Strict-Transport-Security header.",
				FoundBy:     "nuclei",
				CreatedAt:   "2025-01-15T11:00:00Z",
			},
		},
		Summary: Summary{
			Total:      2,
			BySeverity: map[string]int{"critical": 1, "low": 1},
		},
	}
}

func TestGenerateMarkdown(t *testing.T) {
	missionID := uuid.New()
	gen := NewGenerator(missionID, "Test Mission")
	data := sampleData()

	md := gen.GenerateMarkdown(data)
	require.NotEmpty(t, md)

	content := string(md)

	// Header checks
	assert.Contains(t, content, "# Security Assessment Report")
	assert.Contains(t, content, "**Mission:** Test Mission")
	assert.Contains(t, content, missionID.String())

	// Description
	assert.Contains(t, content, "Penetration test of example.com")

	// Summary
	assert.Contains(t, content, "Total vulnerabilities found: **2**")

	// Severity table
	assert.Contains(t, content, "CRITICAL")
	assert.Contains(t, content, "LOW")

	// Vulnerability details
	assert.Contains(t, content, "SQL Injection in Login")
	assert.Contains(t, content, "Missing HSTS Header")
	assert.Contains(t, content, "CVSS Score")
	assert.Contains(t, content, "9.8")
	assert.Contains(t, content, "CWE-89")
	assert.Contains(t, content, "CVE-2024-0001")

	// Evidence code block
	assert.Contains(t, content, "```")
	assert.Contains(t, content, "OR 1=1")

	// Remediation
	assert.Contains(t, content, "Use parameterized queries.")

	// Methodology section
	assert.Contains(t, content, "## Methodology")

	// Disclaimer
	assert.Contains(t, content, "generated automatically by PhantomStrike")
}

func TestGenerateMarkdownNoVulnerabilities(t *testing.T) {
	gen := NewGenerator(uuid.New(), "Empty Mission")
	data := &Data{
		Summary: Summary{Total: 0, BySeverity: map[string]int{}},
	}

	md := gen.GenerateMarkdown(data)
	content := string(md)

	assert.Contains(t, content, "No vulnerabilities were discovered")
}

func TestGenerateHTML(t *testing.T) {
	missionID := uuid.New()
	gen := NewGenerator(missionID, "HTML Test Mission")
	data := sampleData()

	html := gen.GenerateHTML(data)
	require.NotEmpty(t, html)

	content := string(html)

	// Structure
	assert.Contains(t, content, "<!DOCTYPE html>")
	assert.Contains(t, content, "</html>")
	assert.Contains(t, content, "<style>")

	// Header
	assert.Contains(t, content, "Security Assessment Report")
	assert.Contains(t, content, "HTML Test Mission")
	assert.Contains(t, content, missionID.String())

	// Summary
	assert.Contains(t, content, "Executive Summary")
	assert.Contains(t, content, "Total vulnerabilities found")

	// Findings
	assert.Contains(t, content, "SQL Injection in Login")
	assert.Contains(t, content, "Missing HSTS Header")
	assert.Contains(t, content, "9.8")

	// Footer
	assert.Contains(t, content, "PhantomStrike")
}

func TestGenerateJSON(t *testing.T) {
	missionID := uuid.New()
	gen := NewGenerator(missionID, "JSON Test Mission")
	data := sampleData()
	startTime := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	data.StartTime = &startTime

	result, err := gen.GenerateJSON(data)
	require.NoError(t, err)
	require.NotEmpty(t, result)

	// Validate it's well-formed JSON
	var parsed Data
	err = json.Unmarshal(result, &parsed)
	require.NoError(t, err)

	// Verify fields are set by the generator
	assert.Equal(t, missionID, parsed.MissionID)
	assert.Equal(t, "JSON Test Mission", parsed.MissionName)
	assert.False(t, parsed.GeneratedAt.IsZero())

	// Verify vulnerabilities survive the round-trip
	assert.Len(t, parsed.Vulnerabilities, 2)
	assert.Equal(t, "SQL Injection in Login", parsed.Vulnerabilities[0].Title)
	assert.Equal(t, "critical", parsed.Vulnerabilities[0].Severity)
	require.NotNil(t, parsed.Vulnerabilities[0].CVSSScore)
	assert.InDelta(t, 9.8, *parsed.Vulnerabilities[0].CVSSScore, 0.01)

	// Summary
	assert.Equal(t, 2, parsed.Summary.Total)
	assert.Equal(t, 1, parsed.Summary.BySeverity["critical"])
	assert.Equal(t, 1, parsed.Summary.BySeverity["low"])

	// Ensure pretty-printed (indented)
	assert.True(t, strings.Contains(string(result), "\n"))
}

package compliance

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetOWASPRequirements(t *testing.T) {
	reqs := getOWASPTop10Requirements()

	// Verify all 10 OWASP Top 10 items exist
	assert.Len(t, reqs, 10, "OWASP Top 10 should have exactly 10 requirements")

	expectedIDs := []string{
		"A01:2021", "A02:2021", "A03:2021", "A04:2021", "A05:2021",
		"A06:2021", "A07:2021", "A08:2021", "A09:2021", "A10:2021",
	}

	for i, expectedID := range expectedIDs {
		assert.Equal(t, expectedID, reqs[i].ID, "Requirement %d should have ID %s", i+1, expectedID)
		assert.NotEmpty(t, reqs[i].Title, "Requirement %s should have a title", expectedID)
		assert.NotEmpty(t, reqs[i].Description, "Requirement %s should have a description", expectedID)
		assert.NotEmpty(t, reqs[i].Controls, "Requirement %s should have controls", expectedID)
		assert.NotEmpty(t, reqs[i].CWEMappings, "Requirement %s should have CWE mappings", expectedID)
	}
}

func TestGetCWETop25Requirements(t *testing.T) {
	reqs := getCWETop25Requirements()
	assert.NotEmpty(t, reqs, "CWE Top 25 should have requirements")

	for _, req := range reqs {
		assert.NotEmpty(t, req.ID)
		assert.NotEmpty(t, req.Title)
		assert.NotEmpty(t, req.Controls)
	}
}

func TestGetNISTCSFRequirements(t *testing.T) {
	reqs := getNISTCSFRequirements()
	assert.NotEmpty(t, reqs, "NIST CSF should have requirements")

	for _, req := range reqs {
		assert.NotEmpty(t, req.ID)
		assert.NotEmpty(t, req.Title)
		assert.NotEmpty(t, req.Controls)
	}
}

func TestMatchesPatternPositive(t *testing.T) {
	req := Requirement{
		ID:       "A03:2021",
		Title:    "Injection",
		Controls: []string{"sql injection", "xss", "command injection"},
	}

	// Title match
	assert.True(t, matchesPattern("SQL Injection in Login", "", req))

	// Description match
	assert.True(t, matchesPattern("", "Found a command injection vulnerability", req))

	// Case insensitive
	assert.True(t, matchesPattern("XSS in search page", "", req))
}

func TestMatchesPatternNegative(t *testing.T) {
	req := Requirement{
		ID:       "A03:2021",
		Title:    "Injection",
		Controls: []string{"sql injection", "xss", "command injection"},
	}

	assert.False(t, matchesPattern("Broken access control", "Missing authorization checks", req))
	assert.False(t, matchesPattern("", "", req))
}

func TestMatchesPatternEmptyControls(t *testing.T) {
	req := Requirement{
		ID:       "TEST",
		Title:    "Test",
		Controls: []string{},
	}

	assert.False(t, matchesPattern("anything", "anything", req))
}

func TestMapVulnerabilityOWASP(t *testing.T) {
	mapper := NewMapper(nil)

	vuln := map[string]any{
		"title":       "SQL Injection in login form",
		"description": "The login form is vulnerable to SQL injection attacks",
		"cwe_id":      "",
	}

	mappings := mapper.MapVulnerability(vuln)
	assert.NotEmpty(t, mappings, "Should match at least one OWASP requirement")

	// Should match A03:2021 (Injection)
	found := false
	for _, m := range mappings {
		if m.RequirementID == "A03:2021" {
			found = true
			assert.Equal(t, FrameworkOWASPTop10, m.Framework)
			break
		}
	}
	assert.True(t, found, "Should match OWASP A03:2021 Injection")
}

func TestMapVulnerabilityWithCWE(t *testing.T) {
	mapper := NewMapper(nil)

	vuln := map[string]any{
		"title":       "Some unique vulnerability",
		"description": "A specific issue",
		"cwe_id":      "89",
	}

	mappings := mapper.MapVulnerability(vuln)

	// Should have a CWE mapping
	foundCWE := false
	for _, m := range mappings {
		if m.Framework == FrameworkCWE25 && m.RequirementID == "89" {
			foundCWE = true
			assert.Equal(t, "CWE-89", m.Title)
			break
		}
	}
	assert.True(t, foundCWE, "Should include CWE mapping")
}

func TestMapVulnerabilityNoMatch(t *testing.T) {
	mapper := NewMapper(nil)

	vuln := map[string]any{
		"title":       "Completely unrelated issue",
		"description": "Nothing security related here at all",
		"cwe_id":      "",
	}

	mappings := mapper.MapVulnerability(vuln)
	assert.Empty(t, mappings, "Should not match any framework")
}

func TestMapperGetRequirements(t *testing.T) {
	mapper := NewMapper(nil)

	tests := []struct {
		framework Framework
		expectNil bool
	}{
		{FrameworkOWASPTop10, false},
		{FrameworkCWE25, false},
		{FrameworkNISTCSF, false},
		{FrameworkGDPR, true},     // not implemented
		{FrameworkPCIDSS, true},   // not implemented
		{FrameworkISO27001, true}, // not implemented
	}

	for _, tt := range tests {
		t.Run(string(tt.framework), func(t *testing.T) {
			reqs := mapper.GetRequirements(tt.framework)
			if tt.expectNil {
				assert.Nil(t, reqs)
			} else {
				assert.NotNil(t, reqs)
				assert.NotEmpty(t, reqs)
			}
		})
	}
}

func TestGetString(t *testing.T) {
	m := map[string]any{
		"name":  "test",
		"count": 42,
	}

	assert.Equal(t, "test", getString(m, "name"))
	assert.Equal(t, "", getString(m, "count"))    // not a string
	assert.Equal(t, "", getString(m, "nonexist")) // missing key
}

func TestGetInt(t *testing.T) {
	m := map[string]any{
		"int_val":     42,
		"int64_val":   int64(100),
		"float64_val": float64(3.14),
		"str_val":     "hello",
	}

	assert.Equal(t, 42, getInt(m, "int_val"))
	assert.Equal(t, 100, getInt(m, "int64_val"))
	assert.Equal(t, 3, getInt(m, "float64_val"))
	assert.Equal(t, 0, getInt(m, "str_val"))     // wrong type
	assert.Equal(t, 0, getInt(m, "nonexistent")) // missing key
}

func TestExportReportJSON(t *testing.T) {
	mapper := NewMapper(nil)
	report := &ComplianceReport{
		Framework:  FrameworkOWASPTop10,
		Version:    "1.0",
		TotalVulns: 5,
		Score:      80.0,
		Summary:    map[string]int{"compliant": 8, "non-compliant": 2},
		Findings:   []Finding{},
	}

	data, err := mapper.ExportReport(report, "json")
	assert.NoError(t, err)
	assert.Contains(t, string(data), "owasp-top-10")
	assert.Contains(t, string(data), "80")
}

func TestExportReportSummary(t *testing.T) {
	mapper := NewMapper(nil)
	report := &ComplianceReport{
		Framework:  FrameworkOWASPTop10,
		Version:    "1.0",
		TotalVulns: 3,
		Score:      70.0,
		Summary:    map[string]int{"compliant": 7, "non-compliant": 3},
		Requirements: []RequirementResult{
			{
				Requirement: Requirement{ID: "A01:2021", Title: "Broken Access Control"},
				Status:      "compliant",
			},
			{
				Requirement:     Requirement{ID: "A03:2021", Title: "Injection"},
				Status:          "non-compliant",
				Vulnerabilities: []int{1, 2},
			},
		},
		Findings: []Finding{},
	}

	data, err := mapper.ExportReport(report, "summary")
	assert.NoError(t, err)
	text := string(data)
	assert.Contains(t, text, "Compliance Report")
	assert.Contains(t, text, "70.0%")
	assert.Contains(t, text, "A01:2021")
	assert.Contains(t, text, "A03:2021")
}

func TestExportReportUnsupportedFormat(t *testing.T) {
	mapper := NewMapper(nil)
	report := &ComplianceReport{}

	_, err := mapper.ExportReport(report, "xml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format")
}

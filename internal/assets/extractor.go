package assets

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ToolAssetExtractor extracts assets from tool outputs.
type ToolAssetExtractor struct {
	patterns map[AssetType]*regexp.Regexp
}

// NewToolAssetExtractor creates a new tool asset extractor.
func NewToolAssetExtractor() *ToolAssetExtractor {
	return &ToolAssetExtractor{
		patterns: map[AssetType]*regexp.Regexp{
			AssetTypeDomain:    compilePattern(`(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}`),
			AssetTypeIP:        compilePattern(`\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
			AssetTypeEndpoint:  compilePattern(`https?://[^\s<>"{}|\\^\[\]]+`),
			AssetTypePort:      compilePattern(`:(\d{1,5})\b`),
			AssetTypeService:   compilePattern(`\b(?:ssh|http|https|ftp|smtp|dns|mysql|postgresql|redis|mongodb|elasticsearch)\b`),
		},
	}
}

func compilePattern(pattern string) *regexp.Regexp {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	return re
}

// ExtractResult represents extracted asset data.
type ExtractResult struct {
	Type   AssetType
	Value  string
	Source string
	Data   map[string]interface{}
}

// ExtractFromToolOutput extracts assets from tool output.
func (e *ToolAssetExtractor) ExtractFromToolOutput(output []byte, toolName string) []ExtractResult {
	var results []ExtractResult
	outputStr := string(output)

	// Extract domains
	if re := e.patterns[AssetTypeDomain]; re != nil {
		matches := re.FindAllString(outputStr, -1)
		seen := make(map[string]bool)
		for _, match := range matches {
			match = strings.ToLower(match)
			if seen[match] {
				continue
			}
			seen[match] = true

			// Determine if subdomain or domain
			assetType := AssetTypeDomain
			if strings.Count(match, ".") > 1 {
				assetType = AssetTypeSubdomain
			}

			results = append(results, ExtractResult{
				Type:   assetType,
				Value:  match,
				Source: toolName,
			})
		}
	}

	// Extract IPs
	if re := e.patterns[AssetTypeIP]; re != nil {
		matches := re.FindAllString(outputStr, -1)
		seen := make(map[string]bool)
		for _, match := range matches {
			if seen[match] {
				continue
			}
			seen[match] = true
			results = append(results, ExtractResult{
				Type:   AssetTypeIP,
				Value:  match,
				Source: toolName,
			})
		}
	}

	// Extract URLs/endpoints
	if re := e.patterns[AssetTypeEndpoint]; re != nil {
		matches := re.FindAllString(outputStr, -1)
		seen := make(map[string]bool)
		for _, match := range matches {
			if seen[match] {
				continue
			}
			seen[match] = true
			results = append(results, ExtractResult{
				Type:   AssetTypeEndpoint,
				Value:  match,
				Source: toolName,
			})
		}
	}

	return results
}

// ExtractFromJSON extracts assets from structured JSON output.
func (e *ToolAssetExtractor) ExtractFromJSON(data []byte, toolName string, paths map[string]AssetType) []ExtractResult {
	var results []ExtractResult

	// Parse JSON
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return results
	}

	// Extract based on configured paths
	for path, assetType := range paths {
		value := extractPath(doc, path)
		if value != "" {
			results = append(results, ExtractResult{
				Type:   assetType,
				Value:  value,
				Source: toolName,
			})
		}
	}

	return results
}

// extractPath extracts a value from a nested JSON object using dot notation.
func extractPath(doc map[string]interface{}, path string) string {
	parts := strings.Split(path, ".")
	current := doc

	for i, part := range parts {
		if i == len(parts)-1 {
			// Final part - return value
			if val, ok := current[part]; ok {
				switch v := val.(type) {
				case string:
					return v
				case float64:
					// Format float without trailing zeros
					s := fmt.Sprintf("%v", v)
					if strings.HasSuffix(s, ".00") {
						s = strings.TrimSuffix(s, ".00")
					}
					return s
				}
				return ""
			}
			return ""
		}

		// Navigate deeper
		if next, ok := current[part].(map[string]interface{}); ok {
			current = next
		} else if arr, ok := current[part].([]interface{}); ok && len(arr) > 0 {
			// Handle arrays - try first element if it's an object
			if first, ok := arr[0].(map[string]interface{}); ok {
				current = first
			} else {
				return ""
			}
		} else {
			return ""
		}
	}

	return ""
}

// AssetExtractorConfig holds configuration for different tools.
var AssetExtractorConfig = map[string]map[string]AssetType{
	"amass": {
		"name": AssetTypeDomain,
		"ips":  AssetTypeIP,
	},
	"nmap": {
		"host": AssetTypeIP,
		"ports.port": AssetTypePort,
	},
	"subfinder": {
		"host": AssetTypeSubdomain,
	},
	"naabu": {
		"ip":   AssetTypeIP,
		"port": AssetTypePort,
	},
	"httpx": {
		"url":      AssetTypeEndpoint,
		"host":     AssetTypeDomain,
		"webserver": AssetTypeTechnology,
	},
	"tlsx": {
		"host": AssetTypeDomain,
	},
}

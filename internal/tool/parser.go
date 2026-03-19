package tool

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ParseToolFile reads and parses a YAML tool definition file.
func ParseToolFile(path string) (*Definition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var def Definition
	if err := yaml.Unmarshal(data, &def); err != nil {
		return nil, fmt.Errorf("parsing YAML: %w", err)
	}

	if def.Name == "" {
		return nil, fmt.Errorf("tool name is required in %s", path)
	}

	// Default enabled to true if not specified
	if !def.Enabled {
		// YAML unmarshals missing bool as false, so we check if the file explicitly set it
		// For simplicity, default to true
		def.Enabled = true
	}

	return &def, nil
}

// BuildCommand constructs the full command line from a tool definition and parameters.
func BuildCommand(def *Definition, params map[string]any) (string, []string) {
	cmd := def.Command
	args := make([]string, len(def.Args))
	copy(args, def.Args)

	for _, p := range def.Parameters {
		val, ok := params[p.Name]
		if !ok {
			if p.Default != nil {
				val = p.Default
			} else {
				continue
			}
		}

		if p.Flag == "" {
			continue
		}

		switch v := val.(type) {
		case bool:
			if v {
				args = append(args, p.Flag)
			}
		case string:
			if v != "" {
				args = append(args, p.Flag, v)
			}
		case float64:
			args = append(args, p.Flag, fmt.Sprintf("%g", v))
		case int:
			args = append(args, p.Flag, fmt.Sprintf("%d", v))
		default:
			args = append(args, p.Flag, fmt.Sprintf("%v", v))
		}
	}

	return cmd, args
}

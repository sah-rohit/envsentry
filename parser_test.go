package main

import (
	"strings"
	"testing"
)

func TestParseEnvReader(t *testing.T) {
	input := `
# Simple variable
PORT=8080 # type:int
# String variable with comment symbol inside quotes
DB_PASS="secret#password" # type:string
# Optional float variable
TIMEOUT=1.5 # type:float # optional
# Deprecated variable
OLD_URL=http://legacy # deprecated
# Enum variable
ENV_NAME=development # type:enum(development,production,staging)
# Exported variable
export DEBUG=true # type:bool
# Empty value
EMPTY_VAL=
`

	vars, err := ParseEnvReader(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error parsing reader: %v", err)
	}

	tests := []struct {
		key          string
		defaultValue string
		varType      string
		optional     bool
		deprecated   bool
		enumVals     []string
	}{
		{"PORT", "8080", "int", false, false, nil},
		{"DB_PASS", "secret#password", "string", false, false, nil},
		{"TIMEOUT", "1.5", "float", true, false, nil},
		{"OLD_URL", "http://legacy", "", false, true, nil},
		{"ENV_NAME", "development", "enum", false, false, []string{"development", "production", "staging"}},
		{"DEBUG", "true", "bool", false, false, nil},
		{"EMPTY_VAL", "", "", false, false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			v, exists := vars[tt.key]
			if !exists {
				t.Fatalf("expected key %s to exist", tt.key)
			}
			if v.DefaultValue != tt.defaultValue {
				t.Errorf("expected default value %q, got %q", tt.defaultValue, v.DefaultValue)
			}
			if v.Type != tt.varType {
				t.Errorf("expected type %q, got %q", tt.varType, v.Type)
			}
			if v.Optional != tt.optional {
				t.Errorf("expected optional %v, got %v", tt.optional, v.Optional)
			}
			if v.Deprecated != tt.deprecated {
				t.Errorf("expected deprecated %v, got %v", tt.deprecated, v.Deprecated)
			}
			if len(tt.enumVals) > 0 {
				if len(v.EnumVals) != len(tt.enumVals) {
					t.Fatalf("expected %d enum values, got %d", len(tt.enumVals), len(v.EnumVals))
				}
				for i, ev := range tt.enumVals {
					if v.EnumVals[i] != ev {
						t.Errorf("expected enum val %d to be %q, got %q", i, ev, v.EnumVals[i])
					}
				}
			}
		})
	}
}

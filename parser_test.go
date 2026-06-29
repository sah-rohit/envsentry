package main

import (
	"strings"
	"testing"
)

func TestParseEnvReader(t *testing.T) {
	input := `
# Simple variable
PORT=8080 # type:int # range(1024,65535)
# String variable with comment symbol inside quotes
DB_PASS="secret#password" # type:string # len(8,32)
# Optional float variable
TIMEOUT=1.5 # type:float # optional
# Deprecated variable
OLD_URL=http://legacy # deprecated
# Enum variable
ENV_NAME=development # type:enum(development,production,staging)
# Exported variable
export DEBUG=true # type:bool
# Regex pattern with nested parenthesis
API_KEY=sk_live_12345abcdef # type:string # regex(^[a-z]{2}_(live|test)_[a-f0-9]+$)
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
		hasRange     bool
		rangeMin     float64
		rangeMax     float64
		hasLen       bool
		lenMin       int
		lenMax       int
		hasRegex     bool
		regexPattern string
	}{
		{"PORT", "8080", "int", false, false, nil, true, 1024, 65535, false, 0, 0, false, ""},
		{"DB_PASS", "secret#password", "string", false, false, nil, false, 0, 0, true, 8, 32, false, ""},
		{"TIMEOUT", "1.5", "float", true, false, nil, false, 0, 0, false, 0, 0, false, ""},
		{"OLD_URL", "http://legacy", "", false, true, nil, false, 0, 0, false, 0, 0, false, ""},
		{"ENV_NAME", "development", "enum", false, false, []string{"development", "production", "staging"}, false, 0, 0, false, 0, 0, false, ""},
		{"DEBUG", "true", "bool", false, false, nil, false, 0, 0, false, 0, 0, false, ""},
		{"API_KEY", "sk_live_12345abcdef", "string", false, false, nil, false, 0, 0, false, 0, 0, true, "^[a-z]{2}_(live|test)_[a-f0-9]+$"},
		{"EMPTY_VAL", "", "", false, false, nil, false, 0, 0, false, 0, 0, false, ""},
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
			if v.HasRange != tt.hasRange {
				t.Errorf("expected HasRange %v, got %v", tt.hasRange, v.HasRange)
			}
			if tt.hasRange {
				if v.RangeMin != tt.rangeMin || v.RangeMax != tt.rangeMax {
					t.Errorf("expected range (%f, %f), got (%f, %f)", tt.rangeMin, tt.rangeMax, v.RangeMin, v.RangeMax)
				}
			}
			if v.HasLen != tt.hasLen {
				t.Errorf("expected HasLen %v, got %v", tt.hasLen, v.HasLen)
			}
			if tt.hasLen {
				if v.LenMin != tt.lenMin || v.LenMax != tt.lenMax {
					t.Errorf("expected length limit (%d, %d), got (%d, %d)", tt.lenMin, tt.lenMax, v.LenMin, v.LenMax)
				}
			}
			if v.HasRegex != tt.hasRegex {
				t.Errorf("expected HasRegex %v, got %v", tt.hasRegex, v.HasRegex)
			}
			if tt.hasRegex {
				if v.RegexPattern != tt.regexPattern {
					t.Errorf("expected regex pattern %q, got %q", tt.regexPattern, v.RegexPattern)
				}
			}
		})
	}
}

package main

import (
	"testing"
)

func TestValidate(t *testing.T) {
	exampleVars := map[string]*EnvVar{
		"PORT":     {Key: "PORT", Type: "int"},
		"DEBUG":    {Key: "DEBUG", Type: "bool"},
		"DB_URL":   {Key: "DB_URL", Type: "url", Optional: true},
		"EMAIL":    {Key: "EMAIL", Type: "email"},
		"OLD_KEY":  {Key: "OLD_KEY", Deprecated: true},
		"ENV_NAME": {Key: "ENV_NAME", Type: "enum", EnumVals: []string{"development", "production"}},
	}

	tests := []struct {
		name        string
		envVars     map[string]*EnvVar
		expectFail  bool
		expectWarn  bool
		checkResult func(t *testing.T, results []ValidationResult)
	}{
		{
			name: "All valid",
			envVars: map[string]*EnvVar{
				"PORT":     {Key: "PORT", DefaultValue: "8080"},
				"DEBUG":    {Key: "DEBUG", DefaultValue: "true"},
				"EMAIL":    {Key: "EMAIL", DefaultValue: "test@example.com"},
				"ENV_NAME": {Key: "ENV_NAME", DefaultValue: "production"},
			},
			expectFail: false,
			expectWarn: false,
			checkResult: func(t *testing.T, results []ValidationResult) {
				for _, r := range results {
					if r.Status == StatusFail {
						t.Errorf("unexpected failure for %s: %s", r.Key, r.Message)
					}
				}
			},
		},
		{
			name: "Missing required key PORT",
			envVars: map[string]*EnvVar{
				"DEBUG":    {Key: "DEBUG", DefaultValue: "true"},
				"EMAIL":    {Key: "EMAIL", DefaultValue: "test@example.com"},
				"ENV_NAME": {Key: "ENV_NAME", DefaultValue: "production"},
			},
			expectFail: true,
			expectWarn: false,
			checkResult: func(t *testing.T, results []ValidationResult) {
				found := false
				for _, r := range results {
					if r.Key == "PORT" && r.Status == StatusFail {
						found = true
					}
				}
				if !found {
					t.Error("expected PORT validation to fail")
				}
			},
		},
		{
			name: "Type mismatch PORT",
			envVars: map[string]*EnvVar{
				"PORT":     {Key: "PORT", DefaultValue: "not-an-int"},
				"DEBUG":    {Key: "DEBUG", DefaultValue: "true"},
				"EMAIL":    {Key: "EMAIL", DefaultValue: "test@example.com"},
				"ENV_NAME": {Key: "ENV_NAME", DefaultValue: "production"},
			},
			expectFail: true,
			expectWarn: false,
			checkResult: func(t *testing.T, results []ValidationResult) {
				found := false
				for _, r := range results {
					if r.Key == "PORT" && r.Status == StatusFail {
						found = true
					}
				}
				if !found {
					t.Error("expected PORT validation to fail due to type mismatch")
				}
			},
		},
		{
			name: "Deprecated lingering key and undocumented key",
			envVars: map[string]*EnvVar{
				"PORT":     {Key: "PORT", DefaultValue: "8080"},
				"DEBUG":    {Key: "DEBUG", DefaultValue: "true"},
				"EMAIL":    {Key: "EMAIL", DefaultValue: "test@example.com"},
				"ENV_NAME": {Key: "ENV_NAME", DefaultValue: "production"},
				"OLD_KEY":  {Key: "OLD_KEY", DefaultValue: "lingering-value"},
				"EXTRA":    {Key: "EXTRA", DefaultValue: "extra-value"},
			},
			expectFail: false,
			expectWarn: true,
			checkResult: func(t *testing.T, results []ValidationResult) {
				foundOldKey := false
				foundExtra := false
				for _, r := range results {
					if r.Key == "OLD_KEY" && r.Status == StatusWarn {
						foundOldKey = true
					}
					if r.Key == "EXTRA" && r.Status == StatusWarn {
						foundExtra = true
					}
				}
				if !foundOldKey {
					t.Error("expected OLD_KEY to be warned as deprecated")
				}
				if !foundExtra {
					t.Error("expected EXTRA to be warned as undocumented")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := Validate(exampleVars, tt.envVars)
			hasFail := false
			hasWarn := false
			for _, r := range results {
				if r.Status == StatusFail {
					hasFail = true
				}
				if r.Status == StatusWarn {
					hasWarn = true
				}
			}
			if hasFail != tt.expectFail {
				t.Errorf("expected fail status %v, got %v", tt.expectFail, hasFail)
			}
			if hasWarn != tt.expectWarn {
				t.Errorf("expected warn status %v, got %v", tt.expectWarn, hasWarn)
			}
			tt.checkResult(t, results)
		})
	}
}

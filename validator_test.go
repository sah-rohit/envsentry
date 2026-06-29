package main

import (
	"testing"
)

func TestValidateAdvanced(t *testing.T) {
	exampleVars := map[string]*EnvVar{
		"PORT":          {Key: "PORT", Type: "int", HasRange: true, RangeMin: 1000, RangeMax: 9000},
		"DB_URL":         {Key: "DB_URL", Type: "url", Optional: true},
		"EMAIL":          {Key: "EMAIL", Type: "email"},
		"OLD_KEY":        {Key: "OLD_KEY", Deprecated: true},
		"PASS":           {Key: "PASS", Type: "string", HasLen: true, LenMin: 8, LenMax: 16},
		"API_KEY":        {Key: "API_KEY", Type: "string", HasRegex: true, RegexPattern: "^sk_[0-9a-f]{6}$"},
		"CUSTOM_UUID":    {Key: "CUSTOM_UUID", Type: "uuid"},
		"IGNORED_FAILED": {Key: "IGNORED_FAILED", Type: "int"},
	}

	cfg := &Config{
		Strict:      false,
		EnvFile:     "mock_env_test",
		IgnoredKeys: []string{"IGNORED_FAILED"},
		CustomTypes: map[string]string{
			"uuid": "^[0-9a-f]{8}$",
		},
	}

	tests := []struct {
		name        string
		envVars     map[string]*EnvVar
		expectFail  bool
		expectWarn  bool
		checkResult func(t *testing.T, results []ValidationResult)
	}{
		{
			name: "All valid case",
			envVars: map[string]*EnvVar{
				"PORT":           {Key: "PORT", DefaultValue: "8080"},
				"EMAIL":          {Key: "EMAIL", DefaultValue: "admin@example.com"},
				"PASS":           {Key: "PASS", DefaultValue: "secretpass"},
				"API_KEY":        {Key: "API_KEY", DefaultValue: "sk_abc123"},
				"CUSTOM_UUID":    {Key: "CUSTOM_UUID", DefaultValue: "abcdef12"},
				"IGNORED_FAILED": {Key: "IGNORED_FAILED", DefaultValue: "not-an-int-but-ignored"},
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
			name: "Range error on PORT",
			envVars: map[string]*EnvVar{
				"PORT":        {Key: "PORT", DefaultValue: "9999"},
				"EMAIL":       {Key: "EMAIL", DefaultValue: "admin@example.com"},
				"PASS":        {Key: "PASS", DefaultValue: "secretpass"},
				"API_KEY":     {Key: "API_KEY", DefaultValue: "sk_abc123"},
				"CUSTOM_UUID": {Key: "CUSTOM_UUID", DefaultValue: "abcdef12"},
			},
			expectFail: true,
			expectWarn: false,
			checkResult: func(t *testing.T, results []ValidationResult) {
				found := false
				for _, r := range results {
					if r.Key == "PORT" && r.Status == StatusFail {
						found = true
						if r.Suggestion == "" {
							t.Error("expected range suggestion to be populated")
						}
					}
				}
				if !found {
					t.Error("expected PORT range check to fail")
				}
			},
		},
		{
			name: "Length error on PASS",
			envVars: map[string]*EnvVar{
				"PORT":        {Key: "PORT", DefaultValue: "8080"},
				"EMAIL":       {Key: "EMAIL", DefaultValue: "admin@example.com"},
				"PASS":        {Key: "PASS", DefaultValue: "short"},
				"API_KEY":     {Key: "API_KEY", DefaultValue: "sk_abc123"},
				"CUSTOM_UUID": {Key: "CUSTOM_UUID", DefaultValue: "abcdef12"},
			},
			expectFail: true,
			expectWarn: false,
			checkResult: func(t *testing.T, results []ValidationResult) {
				found := false
				for _, r := range results {
					if r.Key == "PASS" && r.Status == StatusFail {
						found = true
						if r.Suggestion == "" {
							t.Error("expected length limit suggestion to be populated")
						}
					}
				}
				if !found {
					t.Error("expected PASS length check to fail")
				}
			},
		},
		{
			name: "Regex pattern mismatch on API_KEY",
			envVars: map[string]*EnvVar{
				"PORT":        {Key: "PORT", DefaultValue: "8080"},
				"EMAIL":       {Key: "EMAIL", DefaultValue: "admin@example.com"},
				"PASS":        {Key: "PASS", DefaultValue: "secretpass"},
				"API_KEY":     {Key: "API_KEY", DefaultValue: "invalid_key"},
				"CUSTOM_UUID": {Key: "CUSTOM_UUID", DefaultValue: "abcdef12"},
			},
			expectFail: true,
			expectWarn: false,
			checkResult: func(t *testing.T, results []ValidationResult) {
				found := false
				for _, r := range results {
					if r.Key == "API_KEY" && r.Status == StatusFail {
						found = true
					}
				}
				if !found {
					t.Error("expected API_KEY pattern check to fail")
				}
			},
		},
		{
			name: "Placeholder value guard check",
			envVars: map[string]*EnvVar{
				"PORT":        {Key: "PORT", DefaultValue: "8080"},
				"EMAIL":       {Key: "EMAIL", DefaultValue: "admin@example.com"},
				"PASS":        {Key: "PASS", DefaultValue: "TODO"},
				"API_KEY":     {Key: "API_KEY", DefaultValue: "sk_abc123"},
				"CUSTOM_UUID": {Key: "CUSTOM_UUID", DefaultValue: "abcdef12"},
			},
			expectFail: true,
			expectWarn: false,
			checkResult: func(t *testing.T, results []ValidationResult) {
				found := false
				for _, r := range results {
					if r.Key == "PASS" && r.Status == StatusFail && r.Message == "⚠️  Security Warning: Placeholder value detected" {
						found = true
					}
				}
				if !found {
					t.Error("expected placeholder check to trigger fail on 'TODO'")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := Validate(exampleVars, tt.envVars, cfg)
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

func TestMaskValue(t *testing.T) {
	tests := []struct {
		in  string
		out string
	}{
		{"123", "•••"},
		{"1234", "••••"},
		{"secret", "se••et"},
		{"StripeApiKey_12345", "St••••••••••••••45"},
	}
	for _, tt := range tests {
		got := maskValue(tt.in)
		if got != tt.out {
			t.Errorf("maskValue(%q) = %q; expected %q", tt.in, got, tt.out)
		}
	}
}

func TestEntropyAndSecrets(t *testing.T) {
	// High entropy strings should be flagged
	highEntropy := "abcdefghijklmnopqrstuvwxyz123456"
	if !isHardcodedSecret(highEntropy) {
		t.Errorf("expected high-entropy string %q to be flagged as secret", highEntropy)
	}

	// Normal text should not be flagged
	normalText := "my-simple-password"
	if isHardcodedSecret(normalText) {
		t.Errorf("expected low-entropy string %q to NOT be flagged", normalText)
	}

	// Stripe Key signature should be flagged
	stripeKey := "sk_live_123456789012345678901234"
	if !isHardcodedSecret(stripeKey) {
		t.Errorf("expected Stripe key signature %q to be flagged", stripeKey)
	}
}

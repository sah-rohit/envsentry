package main

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ValidationStatus represents the outcome of validating a single key.
type ValidationStatus string

const (
	StatusOk   ValidationStatus = "OK"
	StatusFail ValidationStatus = "FAIL"
	StatusWarn ValidationStatus = "WARN"
)

// ValidationResult contains the details of a single variable's validation.
type ValidationResult struct {
	Key        string
	Status     ValidationStatus
	Message    string
	Suggestion string
}

var (
	// Known high-entropy secret patterns
	stripeKeyRegexp = regexp.MustCompile(`[rs]k_live_[0-9a-zA-Z]{24}`)
	awsKeyRegexp    = regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|APKA|ASCA|ASIA)[A-Z0-9]{16}`)
	githubRegexp    = regexp.MustCompile(`gh[oprs]_[0-9a-zA-Z]{36,255}`)
	googleRegexp    = regexp.MustCompile(`AIzaSy[0-9a-zA-Z-_]{33}`)
)

// Validate compares envVars against the schema defined in exampleVars using config options.
func Validate(exampleVars, envVars map[string]*EnvVar, cfg *Config) []ValidationResult {
	var results []ValidationResult

	if cfg == nil {
		cfg = DefaultConfig()
	}

	// 1. Check Gitignore Leak Prevention (only warning on actual env files)
	if isIgnored, err := isGitignored(cfg.EnvFile); err == nil && !isIgnored {
		results = append(results, ValidationResult{
			Key:        ".gitignore",
			Status:     StatusFail,
			Message:    "🚨 CRITICAL SECURITY RISK: Active env file is NOT ignored in git!",
			Suggestion: fmt.Sprintf("Add %q to your '.gitignore' file immediately to prevent committing active keys to source control.", filepath.Base(cfg.EnvFile)),
		})
	}

	// Build lookup maps for O(1) checks
	ignoredKeysMap := make(map[string]bool)
	for _, k := range cfg.IgnoredKeys {
		ignoredKeysMap[k] = true
	}

	// 2. Validate variables defined in the example (schema)
	for key, schema := range exampleVars {
		// Skip validation if key is ignored in configuration
		if ignoredKeysMap[key] {
			continue
		}

		// Security Check: Scan .env.example value for hardcoded secrets
		if isHardcodedSecret(schema.DefaultValue) {
			results = append(results, ValidationResult{
				Key:        key,
				Status:     StatusFail,
				Message:    "🚨 CRITICAL SECURITY ALERT: Hardcoded secret detected in schema file template",
				Suggestion: fmt.Sprintf("Remove the actual secret from your %q file at key %s. Use an empty value placeholder instead.", filepath.Base(cfg.ExampleFile), key),
			})
			continue
		}

		envVal, exists := envVars[key]

		if !exists {
			if schema.Optional || schema.Deprecated {
				continue
			}
			results = append(results, ValidationResult{
				Key:        key,
				Status:     StatusFail,
				Message:    "Missing required environment variable",
				Suggestion: fmt.Sprintf("Add %s to your env file, or append '# optional' in %s to make it optional.", key, filepath.Base(cfg.ExampleFile)),
			})
			continue
		}

		val := envVal.DefaultValue

		// Security Check: Check for active placeholders in production/strict context
		if isPlaceholderValue(val) {
			results = append(results, ValidationResult{
				Key:        key,
				Status:     StatusFail,
				Message:    "⚠️  Security Warning: Placeholder value detected",
				Suggestion: fmt.Sprintf("Replace placeholder value %q for %s with a real secure credential before deploying.", maskValue(val), key),
			})
			continue
		}

		// Key exists in .env
		if schema.Deprecated {
			results = append(results, ValidationResult{
				Key:        key,
				Status:     StatusWarn,
				Message:    "Deprecated variable still lingering in environment file",
				Suggestion: fmt.Sprintf("Remove %s from your env file as it is deprecated in the schema.", key),
			})
		}

		// Type checking
		if schema.Type != "" {
			if err := validateType(val, schema, cfg); err != nil {
				results = append(results, ValidationResult{
					Key:        key,
					Status:     StatusFail,
					Message:    fmt.Sprintf("Type mismatch: expected %s, got %q", schema.Type, maskValue(val)),
					Suggestion: getTypeSuggestion(key, schema),
				})
				continue
			}
		}

		// Range check
		if schema.HasRange {
			numVal, err := strconv.ParseFloat(val, 64)
			if err != nil || numVal < schema.RangeMin || numVal > schema.RangeMax {
				results = append(results, ValidationResult{
					Key:        key,
					Status:     StatusFail,
					Message:    fmt.Sprintf("Value %q is out of range [%.2f, %.2f]", maskValue(val), schema.RangeMin, schema.RangeMax),
					Suggestion: fmt.Sprintf("Set %s to a numeric value between %.2f and %.2f.", key, schema.RangeMin, schema.RangeMax),
				})
				continue
			}
		}

		// Length check
		if schema.HasLen {
			length := len(val)
			if length < schema.LenMin || length > schema.LenMax {
				results = append(results, ValidationResult{
					Key:        key,
					Status:     StatusFail,
					Message:    fmt.Sprintf("Value length (%d) is out of bounds [%d, %d]", length, schema.LenMin, schema.LenMax),
					Suggestion: fmt.Sprintf("Provide a value for %s between %d and %d characters long (current length: %d).", key, schema.LenMin, schema.LenMax, length),
				})
				continue
			}
		}

		// Regex check
		if schema.HasRegex {
			matched, err := regexp.MatchString(schema.RegexPattern, val)
			if err != nil || !matched {
				results = append(results, ValidationResult{
					Key:        key,
					Status:     StatusFail,
					Message:    fmt.Sprintf("Value %q does not match pattern %s", maskValue(val), schema.RegexPattern),
					Suggestion: fmt.Sprintf("Ensure value for %s matches regex pattern: %s", key, schema.RegexPattern),
				})
				continue
			}
		}

		// Executable custom validator script hook check
		if hookCmd, ok := cfg.GetHookCommand(key); ok {
			if err := runValidatorHook(hookCmd, val); err != nil {
				results = append(results, ValidationResult{
					Key:        key,
					Status:     StatusFail,
					Message:    fmt.Sprintf("Validation script hook failed: %v", err),
					Suggestion: fmt.Sprintf("Check your validation script hook %q to see why value %q failed validation.", hookCmd, maskValue(val)),
				})
				continue
			}
		}

		// If no deprecation warning and checks passed, it's OK
		if !schema.Deprecated {
			results = append(results, ValidationResult{
				Key:    key,
				Status: StatusOk,
			})
		}
	}

	// 3. Detect extra (undocumented) variables in envVars that are not in exampleVars
	for key := range envVars {
		if ignoredKeysMap[key] {
			continue
		}
		if _, exists := exampleVars[key]; !exists {
			results = append(results, ValidationResult{
				Key:        key,
				Status:     StatusWarn,
				Message:    "Undocumented variable (not present in schema file)",
				Suggestion: fmt.Sprintf("Document %s inside your schema %s, or add it to 'ignored_keys' in envsentry.yaml if it shouldn't be validated.", key, filepath.Base(cfg.ExampleFile)),
			})
		}
	}

	return results
}

func validateType(val string, schema *EnvVar, cfg *Config) error {
	switch schema.Type {
	case "int":
		_, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("expected integer, got %q", val)
		}
	case "float":
		_, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return fmt.Errorf("expected float, got %q", val)
		}
	case "bool":
		valLower := strings.ToLower(val)
		allowedBools := map[string]bool{
			"true": true, "false": true,
			"1": true, "0": true,
			"yes": true, "no": true,
			"y": true, "n": true,
			"t": true, "f": true,
			"on": true, "off": true,
		}
		if !allowedBools[valLower] {
			return fmt.Errorf("expected boolean, got %q", val)
		}
	case "email":
		_, err := mail.ParseAddress(val)
		if err != nil {
			return fmt.Errorf("expected valid email address, got %q", val)
		}
	case "url":
		u, err := url.ParseRequestURI(val)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("expected absolute URL, got %q", val)
		}
	case "enum":
		found := false
		for _, enumVal := range schema.EnumVals {
			if val == enumVal {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("expected one of %s, got %q", strings.Join(schema.EnumVals, ", "), val)
		}
	default:
		// Check custom YAML types defined in config
		if regexStr, exists := cfg.CustomTypes[schema.Type]; exists {
			matched, err := regexp.MatchString(regexStr, val)
			if err != nil || !matched {
				return fmt.Errorf("expected custom type %q formatting, got %q", schema.Type, val)
			}
			return nil
		}
	}
	return nil
}

func getTypeSuggestion(key string, schema *EnvVar) string {
	switch schema.Type {
	case "int":
		return fmt.Sprintf("Assign a valid integer value to %s (e.g., 3000).", key)
	case "float":
		return fmt.Sprintf("Assign a valid decimal number value to %s (e.g., 1.5).", key)
	case "bool":
		return fmt.Sprintf("Assign a boolean value to %s (e.g., true, false, 1, 0, yes, no).", key)
	case "email":
		return fmt.Sprintf("Assign a valid email address format to %s (e.g., admin@example.com).", key)
	case "url":
		return fmt.Sprintf("Assign a valid URL with scheme to %s (e.g., https://api.myserver.com).", key)
	case "enum":
		return fmt.Sprintf("Assign one of the permitted options: [%s] to %s.", strings.Join(schema.EnumVals, ", "), key)
	default:
		return fmt.Sprintf("Verify that value of %s conforms to custom type %q specs.", key, schema.Type)
	}
}

// runValidatorHook executes the configured validator command, passing the variable value as an argument.
func runValidatorHook(runCmd string, val string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmdParts := strings.Fields(runCmd)
	if len(cmdParts) == 0 {
		return fmt.Errorf("empty validator script run instruction")
	}

	execCmd := cmdParts[0]
	execArgs := append(cmdParts[1:], val)

	cmd := exec.CommandContext(ctx, execCmd, execArgs...)
	return cmd.Run()
}

// maskValue obfuscates sensitive values to prevent terminal logging leakage.
func maskValue(val string) string {
	if len(val) <= 4 {
		return strings.Repeat("•", len(val))
	}
	return val[:2] + strings.Repeat("•", len(val)-4) + val[len(val)-2:]
}

// calculateEntropy evaluates Shannon entropy to recognize hardcoded secrets.
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	charCounts := make(map[rune]int)
	for _, r := range s {
		charCounts[r]++
	}
	var entropy float64
	for _, count := range charCounts {
		p := float64(count) / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// isHardcodedSecret flags patterns matching known keys or high-entropy configurations.
func isHardcodedSecret(val string) bool {
	val = strings.TrimSpace(val)
	if val == "" {
		return false
	}
	// Check regex patterns
	if stripeKeyRegexp.MatchString(val) || awsKeyRegexp.MatchString(val) || githubRegexp.MatchString(val) || googleRegexp.MatchString(val) {
		return true
	}
	// Shannon entropy check for other passwords/tokens (e.g. length > 16, entropy > 4.2)
	if len(val) > 16 && calculateEntropy(val) > 4.2 {
		return true
	}
	return false
}

// isPlaceholderValue warns if default variables are left unmodified.
func isPlaceholderValue(val string) bool {
	valLower := strings.ToLower(strings.TrimSpace(val))
	placeholders := map[string]bool{
		"todo":        true,
		"changeme":    true,
		"placeholder": true,
		"123456":      true,
		"admin":       true,
		"password":    true,
	}
	return placeholders[valLower]
}

// isGitignored verifies if the environment variables file is ignored from git tracking.
func isGitignored(envFile string) (bool, error) {
	if envFile == "" || strings.Contains(envFile, "mock") || strings.Contains(envFile, "test") || strings.Contains(envFile, "temp") {
		return true, nil
	}

	dir, err := os.Getwd()
	if err != nil {
		return true, nil // default safe
	}

	gitignorePath := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(gitignorePath); os.IsNotExist(err) {
		return false, nil
	}

	file, err := os.Open(gitignorePath)
	if err != nil {
		return true, nil // default safe
	}
	defer file.Close()

	basename := filepath.Base(envFile)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Remove trailing slash
		line = strings.TrimSuffix(line, "/")

		// Standard matching rules
		if line == basename || line == ".env" || line == ".env*" || line == "*" || strings.Contains(basename, line) {
			return true, nil
		}
	}
	return false, nil
}

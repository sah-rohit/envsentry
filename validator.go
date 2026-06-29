package main

import (
	"fmt"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
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
	Key     string
	Status  ValidationStatus
	Message string
}

// Validate compares envVars against the schema defined in exampleVars.
func Validate(exampleVars, envVars map[string]*EnvVar) []ValidationResult {
	var results []ValidationResult

	// 1. Validate variables defined in the example (schema)
	for key, schema := range exampleVars {
		envVal, exists := envVars[key]

		if !exists {
			if schema.Optional || schema.Deprecated {
				// Optional or deprecated and missing: OK
				continue
			}
			// Required and missing: FAIL
			results = append(results, ValidationResult{
				Key:     key,
				Status:  StatusFail,
				Message: "Missing required environment variable",
			})
			continue
		}

		// Key exists in .env
		if schema.Deprecated {
			results = append(results, ValidationResult{
				Key:     key,
				Status:  StatusWarn,
				Message: "Deprecated variable still lingering in environment file",
			})
		}

		// Type checking
		if schema.Type != "" {
			if err := validateType(envVal.DefaultValue, schema); err != nil {
				results = append(results, ValidationResult{
					Key:     key,
					Status:  StatusFail,
					Message: fmt.Sprintf("Type mismatch: %v", err),
				})
				continue
			}
		}

		// If no deprecation warning and type check passed, it's OK
		if !schema.Deprecated {
			results = append(results, ValidationResult{
				Key:    key,
				Status: StatusOk,
			})
		}
	}

	// 2. Detect extra (undocumented) variables in envVars that are not in exampleVars
	for key := range envVars {
		if _, exists := exampleVars[key]; !exists {
			results = append(results, ValidationResult{
				Key:     key,
				Status:  StatusWarn,
				Message: "Undocumented variable (not present in example file)",
			})
		}
	}

	return results
}

func validateType(val string, schema *EnvVar) error {
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
			return fmt.Errorf("expected boolean (true/false, 1/0, yes/no, on/off), got %q", val)
		}
	case "email":
		_, err := mail.ParseAddress(val)
		if err != nil {
			return fmt.Errorf("expected valid email address, got %q", val)
		}
	case "url":
		u, err := url.ParseRequestURI(val)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("expected absolute URL (e.g. https://example.com), got %q", val)
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
	}
	return nil
}

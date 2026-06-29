package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanProjectMultiLanguage(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envsentry-test-scan-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write mock Go file
	goContent := `
package main
import (
    "os"
    "strconv"
)
func main() {
    port, _ := strconv.Atoi(os.Getenv("GO_PORT"))
    val := os.Getenv("GO_DB")
}
`
	err = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(goContent), 0644)
	if err != nil {
		t.Fatalf("failed to write Go file: %v", err)
	}

	// Write mock Docker Compose file
	dockerComposeContent := `
version: '3'
services:
  web:
    image: nginx
    ports:
      - "${COMPOSE_PORT}:80"
    environment:
      - DB_HOST=${COMPOSE_DB_HOST}
`
	err = os.WriteFile(filepath.Join(tmpDir, "docker-compose.yml"), []byte(dockerComposeContent), 0644)
	if err != nil {
		t.Fatalf("failed to write compose file: %v", err)
	}

	// Write mock GitHub Action workflow file
	workflowDir := filepath.Join(tmpDir, ".github", "workflows")
	err = os.MkdirAll(workflowDir, 0755)
	if err != nil {
		t.Fatalf("failed to create workflow dir: %v", err)
	}

	workflowContent := `
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Setup
        env:
          API_KEY: ${{ env.GITHUB_ACTION_API_KEY }}
          DEBUG: ${{ env.GITHUB_ACTION_DEBUG }}
        run: echo "Run tests"
`
	err = os.WriteFile(filepath.Join(workflowDir, "ci.yml"), []byte(workflowContent), 0644)
	if err != nil {
		t.Fatalf("failed to write workflow file: %v", err)
	}

	// Scan project
	cfg := &Config{
		Languages: []string{"go"},
	}

	excludes := []string{}
	varsMap, err := ScanProjectWithTypes(tmpDir, excludes, cfg)
	if err != nil {
		t.Fatalf("ScanProjectWithTypes failed: %v", err)
	}

	expectedVars := map[string]string{
		"GO_DB":                 "string",
		"GO_PORT":               "int", // Inferred from strconv.Atoi(os.Getenv("GO_PORT"))
		"COMPOSE_PORT":          "string",
		"COMPOSE_DB_HOST":       "string",
		"GITHUB_ACTION_API_KEY": "string",
		"GITHUB_ACTION_DEBUG":   "string",
	}

	for k, expectedType := range expectedVars {
		gotType, ok := varsMap[k]
		if !ok {
			t.Errorf("expected key %q to be scanned but it was missing", k)
		} else if gotType != expectedType {
			t.Errorf("expected key %q to have type %q, got %q", k, expectedType, gotType)
		}
	}
}

func TestGenerateExampleFilePreserves(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envsentry-test-gen-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	examplePath := filepath.Join(tmpDir, ".env.example")

	scannedKeys := []string{"PORT", "DATABASE_URL"}
	newCount, err := GenerateExampleFile(examplePath, scannedKeys)
	if err != nil {
		t.Fatalf("GenerateExampleFile failed: %v", err)
	}
	if newCount != 2 {
		t.Errorf("expected 2 new keys, got %d", newCount)
	}

	vars, err := ParseEnvFile(examplePath)
	if err != nil {
		t.Fatalf("ParseEnvFile failed: %v", err)
	}
	if _, ok := vars["PORT"]; !ok {
		t.Error("expected PORT in generated file")
	}
}

func TestMergeInferredTypes(t *testing.T) {
	tests := []struct {
		existing string
		newType  string
		expected string
	}{
		{"", "int", "int"},
		{"string", "bool", "bool"},
		{"int", "string", "int"},
		{"bool", "int", "bool"},
		{"string", "string", "string"},
	}

	for _, tt := range tests {
		got := mergeInferredTypes(tt.existing, tt.newType)
		if got != tt.expected {
			t.Errorf("mergeInferredTypes(%q, %q) = %q; expected %q", tt.existing, tt.newType, got, tt.expected)
		}
	}
}

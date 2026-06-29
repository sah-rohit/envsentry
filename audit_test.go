package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStaticSecurityAudit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "envsentry-audit-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write mock credentials file
	codeContent := `
const stripeKey = "sk_live_123456789012345678901234";
const port = 8080;
`
	err = os.WriteFile(filepath.Join(tmpDir, "index.js"), []byte(codeContent), 0644)
	if err != nil {
		t.Fatalf("failed to write js file: %v", err)
	}

	// Write mock PEM file
	err = os.WriteFile(filepath.Join(tmpDir, "cert.pem"), []byte("-----BEGIN RSA PRIVATE KEY-----"), 0644)
	if err != nil {
		t.Fatalf("failed to write pem file: %v", err)
	}

	// Write mock SQL backup file
	err = os.WriteFile(filepath.Join(tmpDir, "backup.sql"), []byte("CREATE TABLE users;"), 0644)
	if err != nil {
		t.Fatalf("failed to write sql file: %v", err)
	}

	cfg := DefaultConfig()
	findings, err := RunAudit(tmpDir, cfg)
	if err != nil {
		t.Fatalf("RunAudit failed: %v", err)
	}

	hasStripeFinding := false
	hasPemFinding := false
	hasSqlFinding := false

	for _, f := range findings {
		if f.Category == "Credentials Exposure" && f.Severity == "CRITICAL" {
			hasStripeFinding = true
		}
		if f.Category == "Insecure Config" && f.Severity == "CRITICAL" && filepath.Base(f.File) == "cert.pem" {
			hasPemFinding = true
		}
		if f.Category == "Insecure Config" && f.Severity == "WARNING" && filepath.Base(f.File) == "backup.sql" {
			hasSqlFinding = true
		}
	}

	if !hasStripeFinding {
		t.Error("expected credentials exposure finding for stripe key")
	}
	if !hasPemFinding {
		t.Error("expected pem file security risk finding")
	}
	if !hasSqlFinding {
		t.Error("expected database sql backup file warning finding")
	}
}

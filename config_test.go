package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLoadConfigFromYaml(t *testing.T) {
	yamlStr := `
env_file: ".env.production"
example_file: ".env.production.example"
strict: true
exclude:
  - "node_modules"
  - "custom_exclude"
ignored_keys:
  - "INTERNAL_VAR"
custom_types:
  uuid: "^[0-9a-f]{8}$"
hooks:
  - key: "PORT"
    run: "./validate_port.sh"
languages:
  - "python"
  - "go"
`

	cfg := DefaultConfig()
	decoder := yaml.NewDecoder(strings.NewReader(yamlStr))
	err := decoder.Decode(cfg)
	if err != nil {
		t.Fatalf("failed to decode YAML config: %v", err)
	}

	if cfg.EnvFile != ".env.production" {
		t.Errorf("expected EnvFile to be '.env.production', got %q", cfg.EnvFile)
	}
	if cfg.ExampleFile != ".env.production.example" {
		t.Errorf("expected ExampleFile to be '.env.production.example', got %q", cfg.ExampleFile)
	}
	if !cfg.Strict {
		t.Error("expected Strict to be true")
	}
	if len(cfg.Exclude) != 2 || cfg.Exclude[1] != "custom_exclude" {
		t.Errorf("unexpected exclude list: %v", cfg.Exclude)
	}
	if len(cfg.IgnoredKeys) != 1 || cfg.IgnoredKeys[0] != "INTERNAL_VAR" {
		t.Errorf("unexpected ignored_keys: %v", cfg.IgnoredKeys)
	}
	if cfg.CustomTypes["uuid"] != "^[0-9a-f]{8}$" {
		t.Errorf("unexpected custom_types mapping: %v", cfg.CustomTypes)
	}
	runPath, ok := cfg.GetHookCommand("PORT")
	if !ok || runPath != "validate_port.sh" {
		t.Errorf("expected hook command 'validate_port.sh', got %q (exists: %v)", runPath, ok)
	}
	if len(cfg.Languages) != 2 || cfg.Languages[0] != "python" || cfg.Languages[1] != "go" {
		t.Errorf("unexpected scan languages: %v", cfg.Languages)
	}
}

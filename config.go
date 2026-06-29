package main

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// HookConfig defines a custom script hook configuration.
type HookConfig struct {
	Key string `yaml:"key"`
	Run string `yaml:"run"`
}

// Config represents project-level configuration options.
type Config struct {
	EnvFile     string            `yaml:"env_file"`
	ExampleFile string            `yaml:"example_file"`
	Strict      bool              `yaml:"strict"`
	Exclude     []string          `yaml:"exclude"`
	IgnoredKeys []string          `yaml:"ignored_keys"`
	CustomTypes map[string]string `yaml:"custom_types"`
	Hooks       []HookConfig      `yaml:"hooks"`
	Languages   []string          `yaml:"languages"`
}

// DefaultConfig returns the fallback options.
func DefaultConfig() *Config {
	return &Config{
		EnvFile:     ".env",
		ExampleFile: ".env.example",
		Strict:      false,
		Exclude:     []string{"node_modules", ".git", "venv", "__pycache__", "dist", "build"},
		IgnoredKeys: []string{},
		CustomTypes: make(map[string]string),
		Hooks:       []HookConfig{},
		Languages:   []string{"javascript", "typescript", "python"},
	}
}

// LoadConfig reads and decodes a config file.
func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	cfg := DefaultConfig()
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// FindAndLoadConfig searches for envsentry.yaml or .envsentry.yaml in the current directory.
func FindAndLoadConfig() (*Config, error) {
	paths := []string{"envsentry.yaml", ".envsentry.yaml", "envsentry.yml", ".envsentry.yml"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return LoadConfig(p)
		}
	}
	// If none found, return absolute defaults
	return DefaultConfig(), nil
}

// GetHookCommand retrieves the custom script path registered for a specific key.
func (c *Config) GetHookCommand(key string) (string, bool) {
	for _, h := range c.Hooks {
		if h.Key == key {
			return filepath.Clean(h.Run), true
		}
	}
	return "", false
}

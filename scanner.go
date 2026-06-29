package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// LanguageScanner defines a pluggable scanner for a specific programming language or file type.
type LanguageScanner struct {
	Name       string
	Extensions []string
	Regexes    []*regexp.Regexp
	// SpecRegexes maps type name (like "int", "bool") to inference regexes
	TypeRegexes map[string][]*regexp.Regexp
}

// Global registry of all supported scanners.
var ScannerRegistry = []LanguageScanner{
	{
		Name:       "javascript",
		Extensions: []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
		Regexes: []*regexp.Regexp{
			regexp.MustCompile(`\bprocess\.env\.([a-zA-Z_][a-zA-Z0-9_]*)\b`),
			regexp.MustCompile(`\bprocess\.env\[['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\]`),
		},
		TypeRegexes: map[string][]*regexp.Regexp{
			"int": {
				regexp.MustCompile(`\b(?:parseInt|Number)\(\s*process\.env\.([a-zA-Z_][a-zA-Z0-9_]*)\b`),
				regexp.MustCompile(`\b(?:parseInt|Number)\(\s*process\.env\[['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\]`),
			},
			"bool": {
				regexp.MustCompile(`\bprocess\.env\.([a-zA-Z_][a-zA-Z0-9_]*)\s*===?\s*['"](?:true|false)['"]`),
				regexp.MustCompile(`\bprocess\.env\[['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\]\s*===?\s*['"](?:true|false)['"]`),
			},
		},
	},
	{
		Name:       "typescript",
		Extensions: []string{".ts", ".tsx"},
		Regexes: []*regexp.Regexp{
			regexp.MustCompile(`\bprocess\.env\.([a-zA-Z_][a-zA-Z0-9_]*)\b`),
			regexp.MustCompile(`\bprocess\.env\[['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\]`),
		},
		TypeRegexes: map[string][]*regexp.Regexp{
			"int": {
				regexp.MustCompile(`\b(?:parseInt|Number)\(\s*process\.env\.([a-zA-Z_][a-zA-Z0-9_]*)\b`),
				regexp.MustCompile(`\b(?:parseInt|Number)\(\s*process\.env\[['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\]`),
			},
			"bool": {
				regexp.MustCompile(`\bprocess\.env\.([a-zA-Z_][a-zA-Z0-9_]*)\s*===?\s*['"](?:true|false)['"]`),
				regexp.MustCompile(`\bprocess\.env\[['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\]\s*===?\s*['"](?:true|false)['"]`),
			},
		},
	},
	{
		Name:       "python",
		Extensions: []string{".py"},
		Regexes: []*regexp.Regexp{
			regexp.MustCompile(`\bos\.environ\[['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\]`),
			regexp.MustCompile(`\bos\.environ\.get\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`),
			regexp.MustCompile(`\bos\.getenv\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`),
			regexp.MustCompile(`\bgetenv\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`),
		},
		TypeRegexes: map[string][]*regexp.Regexp{
			"int": {
				regexp.MustCompile(`\bint\(\s*os\.getenv\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`),
				regexp.MustCompile(`\bint\(\s*os\.environ\.get\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`),
				regexp.MustCompile(`\bint\(\s*os\.environ\[['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`),
			},
			"bool": {
				regexp.MustCompile(`\bos\.getenv\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)\s*==\s*['"]?(?:True|False)['"]?`),
				regexp.MustCompile(`\bos\.environ\.get\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)\s*==\s*['"]?(?:True|False)['"]?`),
			},
		},
	},
	{
		Name:       "go",
		Extensions: []string{".go"},
		Regexes: []*regexp.Regexp{
			regexp.MustCompile(`\bos\.(?:Getenv|LookupEnv)\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)`),
		},
		TypeRegexes: map[string][]*regexp.Regexp{
			"int": {
				regexp.MustCompile(`\bstrconv\.Atoi\(\s*os\.Getenv\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`),
			},
		},
	},
	{
		Name:       "rust",
		Extensions: []string{".rs"},
		Regexes: []*regexp.Regexp{
			regexp.MustCompile(`\b(?:std::)?env::var\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)`),
		},
		TypeRegexes: map[string][]*regexp.Regexp{
			"int": {
				regexp.MustCompile(`\benv::var\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)\.unwrap\(\)\.parse::<i32>`),
			},
		},
	},
	{
		Name:       "php",
		Extensions: []string{".php"},
		Regexes: []*regexp.Regexp{
			regexp.MustCompile(`\$_ENV\[['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\]`),
			regexp.MustCompile(`\bgetenv\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)`),
		},
	},
	{
		Name:       "java",
		Extensions: []string{".java"},
		Regexes: []*regexp.Regexp{
			regexp.MustCompile(`\bSystem\.getenv\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)`),
		},
		TypeRegexes: map[string][]*regexp.Regexp{
			"int": {
				regexp.MustCompile(`\bInteger\.parseInt\(\s*System\.getenv\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`),
			},
		},
	},
	{
		Name:       "csharp",
		Extensions: []string{".cs"},
		Regexes: []*regexp.Regexp{
			regexp.MustCompile(`\bEnvironment\.GetEnvironmentVariable\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)`),
		},
		TypeRegexes: map[string][]*regexp.Regexp{
			"int": {
				regexp.MustCompile(`\bint\.Parse\(\s*Environment\.GetEnvironmentVariable\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]`),
			},
		},
	},
	{
		Name:       "docker-compose",
		Extensions: []string{".yml", ".yaml"},
		Regexes: []*regexp.Regexp{
			regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`),
		},
	},
	{
		Name:       "github-actions",
		Extensions: []string{".yml", ".yaml"},
		Regexes: []*regexp.Regexp{
			regexp.MustCompile(`\$\{\{\s*env\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`),
		},
	},
}

// ScannedVar represents a variable found during scanning, along with its inferred type.
type ScannedVar struct {
	Key          string
	InferredType string
}

// ScanProject walks through the directory, scans files matching configured languages, and returns unique keys.
func ScanProject(root string, excludes []string, cfg *Config) ([]string, error) {
	varsMap, err := ScanProjectWithTypes(root, excludes, cfg)
	if err != nil {
		return nil, err
	}
	var keys []string
	for k := range varsMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// ScanProjectWithTypes walks the directory and returns a map of key -> InferredType.
func ScanProjectWithTypes(root string, excludes []string, cfg *Config) (map[string]string, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	keysMap := make(map[string]string)

	excludeMap := make(map[string]bool)
	for _, e := range excludes {
		excludeMap[strings.TrimSpace(e)] = true
	}

	// Filter scanner registry by enabled languages in config
	var activeScanners []LanguageScanner
	if len(cfg.Languages) > 0 {
		langMap := make(map[string]bool)
		for _, l := range cfg.Languages {
			langMap[strings.ToLower(strings.TrimSpace(l))] = true
		}
		// Always active compose and actions scanner if parsing yaml
		langMap["docker-compose"] = true
		langMap["github-actions"] = true

		for _, s := range ScannerRegistry {
			if langMap[s.Name] {
				activeScanners = append(activeScanners, s)
			}
		}
	} else {
		activeScanners = ScannerRegistry
	}

	// Extension lookup map
	scannerByExt := make(map[string]LanguageScanner)
	for _, scanner := range activeScanners {
		// docker-compose and github-actions handle yml/yaml files specifically
		if scanner.Name != "docker-compose" && scanner.Name != "github-actions" {
			for _, ext := range scanner.Extensions {
				scannerByExt[ext] = scanner
			}
		}
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			name := d.Name()
			if excludeMap[name] || (strings.HasPrefix(name, ".") && name != ".github") {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		filename := strings.ToLower(filepath.Base(path))

		var matchingScanner *LanguageScanner

		// Determine if YAML file is Docker Compose or GitHub Action
		if ext == ".yml" || ext == ".yaml" {
			if strings.Contains(filepath.ToSlash(path), ".github/workflows") {
				// GitHub Actions
				for _, s := range activeScanners {
					if s.Name == "github-actions" {
						matchingScanner = &s
						break
					}
				}
			} else if strings.Contains(filename, "docker-compose") {
				// Docker Compose
				for _, s := range activeScanners {
					if s.Name == "docker-compose" {
						matchingScanner = &s
						break
					}
				}
			}
		} else {
			if scanner, exists := scannerByExt[ext]; exists {
				matchingScanner = &scanner
			}
		}

		if matchingScanner != nil {
			fileVars, err := scanFileWithTypes(path, *matchingScanner)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to scan file %s: %v\n", path, err)
				return nil
			}
			for _, sv := range fileVars {
				if sv.Key != "" {
					existingType := keysMap[sv.Key]
					keysMap[sv.Key] = mergeInferredTypes(existingType, sv.InferredType)
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return keysMap, nil
}

func mergeInferredTypes(existing, newType string) string {
	if existing == "int" || existing == "bool" {
		return existing
	}
	if newType == "int" || newType == "bool" {
		return newType
	}
	if existing != "" {
		return existing
	}
	if newType != "" {
		return newType
	}
	return "string"
}

func scanFileWithTypes(path string, scanner LanguageScanner) ([]ScannedVar, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var variables []ScannedVar
	fileScanner := bufio.NewScanner(file)
	const maxCapacity = 1024 * 1024
	buf := make([]byte, 0, 64*1024)
	fileScanner.Buffer(buf, maxCapacity)

	for fileScanner.Scan() {
		line := fileScanner.Text()

		// Track which keys are matched to prevent duplicated scanning
		matchedKeys := make(map[string]bool)

		// 1. Run type inference rules
		for inferredType, regexes := range scanner.TypeRegexes {
			for _, re := range regexes {
				matches := re.FindAllStringSubmatch(line, -1)
				for _, m := range matches {
					if len(m) > 1 && m[1] != "" {
						variables = append(variables, ScannedVar{
							Key:          m[1],
							InferredType: inferredType,
						})
						matchedKeys[m[1]] = true
					}
				}
			}
		}

		// 2. Run generic matches
		for _, re := range scanner.Regexes {
			matches := re.FindAllStringSubmatch(line, -1)
			for _, m := range matches {
				if len(m) > 1 && m[1] != "" && !matchedKeys[m[1]] {
					variables = append(variables, ScannedVar{
						Key:          m[1],
						InferredType: "string",
					})
				}
			}
		}
	}

	return variables, fileScanner.Err()
}

// GenerateExampleFile creates or updates an example file with the scanned keys and inferred types.
func GenerateExampleFile(outputPath string, scannedKeys []string) (int, error) {
	// Call scan to check for types
	dir := filepath.Dir(outputPath)
	cfg := DefaultConfig()
	// Attempt to scan from parent dir
	scannedVars, err := ScanProjectWithTypes(dir, []string{}, cfg)
	if err != nil {
		scannedVars = make(map[string]string)
	}

	existingVars := make(map[string]*EnvVar)
	var orderedKeys []string

	if _, err := os.Stat(outputPath); err == nil {
		parsed, err := ParseEnvFile(outputPath)
		if err == nil {
			existingVars = parsed
			file, err := os.Open(outputPath)
			if err == nil {
				fileScanner := bufio.NewScanner(file)
				for fileScanner.Scan() {
					line := strings.TrimSpace(fileScanner.Text())
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					if strings.HasPrefix(line, "export ") {
						line = strings.TrimPrefix(line, "export ")
						line = strings.TrimSpace(line)
					}
					parts := strings.SplitN(line, "=", 2)
					if len(parts) >= 2 {
						k := strings.TrimSpace(parts[0])
						orderedKeys = append(orderedKeys, k)
					}
				}
				file.Close()
			}
		}
	}

	newKeysCount := 0
	scannedKeysMap := make(map[string]bool)
	for _, k := range scannedKeys {
		scannedKeysMap[k] = true
		if _, exists := existingVars[k]; !exists {
			orderedKeys = append(orderedKeys, k)
			
			// Build type comment based on inferred type
			infType := scannedVars[k]
			if infType == "" {
				infType = "string"
			}
			existingVars[k] = &EnvVar{
				Key:     k,
				Type:    infType,
				Comment: fmt.Sprintf("# type:%s", infType),
			}
			newKeysCount++
		}
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	writer.WriteString("# Generated by envsentry\n# Define types using trailing comments, e.g. PORT=8080 # type:int\n\n")

	for _, key := range orderedKeys {
		v := existingVars[key]
		line := fmt.Sprintf("%s=%s", v.Key, v.DefaultValue)
		if v.Comment != "" {
			line = fmt.Sprintf("%s %s", line, v.Comment)
		} else {
			if _, exists := scannedKeysMap[key]; exists && v.DefaultValue == "" {
				line = fmt.Sprintf("%s= # type:string", v.Key)
			}
		}
		_, err = writer.WriteString(line + "\n")
		if err != nil {
			return 0, err
		}
	}

	err = writer.Flush()
	if err != nil {
		return 0, err
	}

	return newKeysCount, nil
}

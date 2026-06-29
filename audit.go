package main

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// AuditFinding represents a security risk identified during directory auditing.
type AuditFinding struct {
	File        string
	Severity    string // "CRITICAL", "WARNING", "INFO"
	Category    string // "Credentials Exposure", "File Permissions", "Insecure Config"
	Description string
	Suggestion  string
}

// RunAudit scans the specified directory for vulnerabilities, credential leaks, and permissions issues.
func RunAudit(dir string, cfg *Config) ([]AuditFinding, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	var findings []AuditFinding

	excludeMap := make(map[string]bool)
	for _, e := range cfg.Exclude {
		excludeMap[strings.TrimSpace(e)] = true
	}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
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

		info, err := d.Info()
		if err != nil {
			return nil
		}

		filename := strings.ToLower(d.Name())
		ext := strings.ToLower(filepath.Ext(path))

		// 1. Audit File Permissions (Unix only)
		if runtime.GOOS != "windows" {
			mode := info.Mode()
			perm := mode.Perm()
			isSensitiveFile := filename == ".env" || strings.HasPrefix(filename, ".env.") || ext == ".pem" || ext == ".key" || filename == "id_rsa"
			if isSensitiveFile && (perm&0077 != 0) {
				findings = append(findings, AuditFinding{
					File:        path,
					Severity:    "CRITICAL",
					Category:    "File Permissions",
					Description: fmt.Sprintf("File has insecure permissions: %04o (group/world readable/writable)", perm),
					Suggestion:  fmt.Sprintf("Restrict access permissions using 'chmod 600 %s' or 'chmod 644 %s'.", path, path),
				})
			}
		}

		// 2. Audit Insecure File Types
		if ext == ".pem" || ext == ".key" || filename == "id_rsa" || ext == ".p12" {
			findings = append(findings, AuditFinding{
				File:        path,
				Severity:    "CRITICAL",
				Category:    "Insecure Config",
				Description: "Exposed private key or cryptographic certificate file stored in workspace directory",
				Suggestion:  "Move private key files outside the code repository and reference them via absolute paths or secure key vaults.",
			})
		} else if ext == ".sql" || ext == ".dump" || ext == ".db" || ext == ".sqlite" {
			findings = append(findings, AuditFinding{
				File:        path,
				Severity:    "WARNING",
				Category:    "Insecure Config",
				Description: "Database dump or SQLite database file stored in workspace directory",
				Suggestion:  "Ensure database backup dumps are ignored from source control and deleted from local working directories.",
			})
		} else if ext == ".log" {
			findings = append(findings, AuditFinding{
				File:        path,
				Severity:    "WARNING",
				Category:    "Insecure Config",
				Description: "Raw application log file stored in workspace directory",
				Suggestion:  "Add '*.log' to your .gitignore file to prevent checking active debug files into source repositories.",
			})
		} else if filename == "docker-compose.override.yml" || filename == "docker-compose.override.yaml" {
			findings = append(findings, AuditFinding{
				File:        path,
				Severity:    "INFO",
				Category:    "Insecure Config",
				Description: "Docker Compose override file detected",
				Suggestion:  "Ensure 'docker-compose.override.yml' is ignored from Git if it contains local environment secrets.",
			})
		}

		// 3. Audit Content for Exposed Credentials
		textExtensions := map[string]bool{
			".txt": true, ".js": true, ".ts": true, ".py": true, ".json": true,
			".yml": true, ".yaml": true, ".conf": true, ".ini": true, ".sh": true,
			".bat": true, ".md": true, ".env": true, ".go": true, ".rs": true,
			".php": true, ".cs": true, ".java": true,
		}

		if textExtensions[ext] || filename == ".env" || strings.HasPrefix(filename, ".env.") {
			// Limit scanned file size to < 1MB to keep execution lightning-fast
			if info.Size() < 1024*1024 {
				fileFindings, err := scanFileForSecrets(path)
				if err == nil {
					findings = append(findings, fileFindings...)
				}
			}
		}

		return nil
	})

	return findings, err
}

func scanFileForSecrets(path string) ([]AuditFinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []AuditFinding
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip comments and imports to avoid false positives
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "import ") {
			continue
		}

		// Check for provider key signatures
		var matchFound bool
		var matchedKeyType string

		if stripeKeyRegexp.MatchString(line) {
			matchFound = true
			matchedKeyType = "Stripe API Key"
		} else if awsKeyRegexp.MatchString(line) {
			matchFound = true
			matchedKeyType = "AWS Access Key ID / Secret"
		} else if githubRegexp.MatchString(line) {
			matchFound = true
			matchedKeyType = "GitHub Token"
		} else if googleRegexp.MatchString(line) {
			matchFound = true
			matchedKeyType = "Google API Key"
		}

		if matchFound {
			findings = append(findings, AuditFinding{
				File:        fmt.Sprintf("%s:%d", path, lineNum),
				Severity:    "CRITICAL",
				Category:    "Credentials Exposure",
				Description: fmt.Sprintf("Hardcoded secret (%s) exposed in plain text", matchedKeyType),
				Suggestion:  "Extract this secret immediately. Place it inside a gitignored '.env' file and use process environment accessors.",
			})
			continue
		}

		// Check Shannon entropy for long random strings (tokens/passwords)
		words := strings.Fields(line)
		for _, w := range words {
			// Clean delimiters (quotes, semicolons)
			w = strings.Trim(w, `"'=;,()[]{} `)
			if len(w) > 20 && calculateEntropy(w) > 4.2 {
				// Prevent matching common long strings like URLs or standard paths
				if !strings.HasPrefix(w, "http://") && !strings.HasPrefix(w, "https://") && !strings.Contains(w, "/") && !strings.Contains(w, "\\") {
					findings = append(findings, AuditFinding{
						File:        fmt.Sprintf("%s:%d", path, lineNum),
						Severity:    "CRITICAL",
						Category:    "Credentials Exposure",
						Description: "Potential high-entropy hardcoded credential token/password detected",
						Suggestion:  "Verify if this string represents a secure token or private password. If so, move it into your gitignored environment variables.",
					})
					break // limit to one entropy finding per line
				}
			}
		}
	}

	return findings, scanner.Err()
}

// PrintAuditReport displays the consolidated static scan report.
func PrintAuditReport(findings []AuditFinding) {
	numCritical := 0
	numWarning := 0
	numInfo := 0

	fmt.Printf("\n%s🛡️  EnvSentry Static Security Audit Report%s\n", colorBold+colorCyan, colorReset)
	fmt.Println(strings.Repeat("─", 80))

	if len(findings) == 0 {
		fmt.Printf("\n%s✔  Congratulations! No security findings or credential exposures were detected.%s\n\n", colorGreen+colorBold, colorReset)
		return
	}

	// Group findings by clean filepath
	type FileFindings struct {
		CleanPath string
		List      []AuditFinding
	}
	var fileList []FileFindings
	fileMap := make(map[string]int) // maps path to index in fileList

	for _, f := range findings {
		// Update stats
		switch f.Severity {
		case "CRITICAL":
			numCritical++
		case "WARNING":
			numWarning++
		case "INFO":
			numInfo++
		}

		// Clean path by stripping line number (e.g. "path/to/file.js:12" -> "path/to/file.js")
		cleanPath := f.File
		if idx := strings.LastIndex(f.File, ":"); idx != -1 {
			// Make sure it looks like a line number count
			if _, err := strconv.Atoi(f.File[idx+1:]); err == nil {
				cleanPath = f.File[:idx]
			}
		}

		idx, exists := fileMap[cleanPath]
		if !exists {
			fileList = append(fileList, FileFindings{CleanPath: cleanPath})
			idx = len(fileList) - 1
			fileMap[cleanPath] = idx
		}
		fileList[idx].List = append(fileList[idx].List, f)
	}

	// Print tree view
	fmt.Printf("%s📂 Workspace Root%s\n", colorBold, colorReset)
	for i, ff := range fileList {
		isLastFile := i == len(fileList)-1
		var filePrefix string
		if isLastFile {
			filePrefix = "└── "
		} else {
			filePrefix = "├── "
		}

		// Determine file emoji icon based on extension/name
		basename := filepath.Base(ff.CleanPath)
		ext := strings.ToLower(filepath.Ext(ff.CleanPath))
		icon := "📄"
		if ext == ".pem" || ext == ".key" || basename == "id_rsa" {
			icon = "🔑"
		} else if ext == ".sql" || ext == ".db" || ext == ".sqlite" {
			icon = "💾"
		} else if basename == ".env" || strings.HasPrefix(basename, ".env.") {
			icon = "🔒"
		}

		fmt.Printf("%s%s %s\n", filePrefix, icon, ff.CleanPath)

		// Print nested findings
		for j, f := range ff.List {
			var branchPrefix string
			if isLastFile {
				branchPrefix = "    "
			} else {
				branchPrefix = "│   "
			}

			isLastFinding := j == len(ff.List)-1
			var findingPrefix string
			if isLastFinding {
				findingPrefix = "└── "
			} else {
				findingPrefix = "├── "
			}

			var severityLabel string
			switch f.Severity {
			case "CRITICAL":
				severityLabel = fmt.Sprintf("%s🚨 CRIT%s", colorRed+colorBold, colorReset)
			case "WARNING":
				severityLabel = fmt.Sprintf("%s⚠️  WARN%s", colorYellow+colorBold, colorReset)
			case "INFO":
				severityLabel = fmt.Sprintf("%sℹ️  INFO%s", colorBlue+colorBold, colorReset)
			}

			// Parse line number if exists
			lineStr := ""
			if idx := strings.LastIndex(f.File, ":"); idx != -1 {
				if _, err := strconv.Atoi(f.File[idx+1:]); err == nil {
					lineStr = "L" + f.File[idx+1:] + " "
				}
			}

			fmt.Printf("%s%s[%s] [%s] %s%s\n", branchPrefix, findingPrefix, severityLabel, f.Category, lineStr, f.Description)
			fmt.Printf("%s    %sRemediation: %s%s\n", branchPrefix, colorCyan, f.Suggestion, colorReset)
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%sAudit Summary:%s\n", colorBold, colorReset)
	fmt.Printf("  🚨 Critical Risks: %s%d%s\n", colorRed+colorBold, numCritical, colorReset)
	fmt.Printf("  ⚠️  Warnings:       %s%d%s\n", colorYellow+colorBold, numWarning, colorReset)
	fmt.Printf("  ℹ️  Information:    %s%d%s\n", colorBlue+colorBold, numInfo, colorReset)
	fmt.Println()
}

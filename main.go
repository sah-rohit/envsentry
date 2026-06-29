package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

// ANSI color escape codes
var (
	colorReset  = ""
	colorRed    = ""
	colorGreen  = ""
	colorYellow = ""
	colorBlue   = ""
	colorCyan   = ""
	colorBold   = ""
)

func init() {
	if os.Getenv("NO_COLOR") == "" {
		colorReset = "\033[0m"
		colorRed = "\033[31m"
		colorGreen = "\033[32m"
		colorYellow = "\033[33m"
		colorBlue = "\033[34m"
		colorCyan = "\033[36m"
		colorBold = "\033[1m"

		if runtime.GOOS == "windows" {
			kernel32 := syscall.NewLazyDLL("kernel32.dll")
			setConsoleMode := kernel32.NewProc("SetConsoleMode")
			stdout, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
			if err == nil {
				var mode uint32
				err = syscall.GetConsoleMode(stdout, &mode)
				if err == nil {
					// 0x0004 is ENABLE_VIRTUAL_TERMINAL_PROCESSING
					_, _, _ = setConsoleMode.Call(uintptr(stdout), uintptr(mode|0x0004))
				}
			}
		}
	}
}

func printHelp() {
	fmt.Printf("%s🛡️  envsentry - DevOps/Security Environment Variable Validator & Scanner%s\n", colorBold+colorCyan, colorReset)
	fmt.Println("Usage:")
	fmt.Println("  envsentry <command> [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  validate   Validates your .env file against a schema definition in .env.example")
	fmt.Println("  generate   Recursively scans JS, TS, Python, etc. code to auto-generate or merge .env.example")
	fmt.Println("  audit      Runs a static security audit on directories to find leaked keys and permission risks")
	fmt.Println("  version    Prints EnvSentry version")
	fmt.Println()
	fmt.Println("Use \"envsentry <command> --help\" for more info about a command.")
}

func main() {
	// Load configuration defaults on startup
	cfg, err := FindAndLoadConfig()
	if err != nil {
		fmt.Printf("%s⚠️  Warning loading envsentry.yaml: %v%s\n", colorYellow, err, colorReset)
		cfg = DefaultConfig()
	}

	// If arguments are passed, bypass interactive menu
	if len(os.Args) >= 2 {
		command := os.Args[1]
		switch command {
		case "validate":
			runValidate(os.Args[2:], cfg)
		case "generate", "scan":
			runGenerate(os.Args[2:], cfg)
		case "audit":
			runAuditSubcommand(os.Args[2:], cfg)
		case "version":
			fmt.Println("envsentry v1.1.0")
		case "help", "-h", "--help":
			printHelp()
		default:
			fmt.Printf("%s✖  Error: unknown command %q%s\n\n", colorRed+colorBold, command, colorReset)
			printHelp()
			os.Exit(1)
		}
		return
	}

	// Run interactive selector when executed with no arguments
	runInteractiveMenu(cfg)
}

func clearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func printDashboard(cfg *Config) {
	clearScreen()
	configLoaded := "Default configuration"
	if _, err := os.Stat("envsentry.yaml"); err == nil {
		configLoaded = "Loaded envsentry.yaml"
	} else if _, err := os.Stat(".envsentry.yaml"); err == nil {
		configLoaded = "Loaded .envsentry.yaml"
	}

	logo := fmt.Sprintf(`%s ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │  EnvSentry v1.1.0                                                                      │
 │                                                                                        │
 │  ███████╗███╗   ██╗██╗   ██╗███████╗███████╗███╗   ██╗████████╗██████╗  ██╗   ██╗      │
 │  ██╔════╝████╗  ██║██║   ██║██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗ ╚██╗ ██╔╝      │
 │  █████╗  ██╔██╗ ██║██║   ██║███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝  ╚████╔╝       │
 │  ██╔══╝  ██║╚██╗██║╚██╗ ██╔╝╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗   ╚██╔╝        │
 │  ███████╗██║ ╚████║ ╚████╔╝ ███████║███████╗██║ ╚████║   ██║   ██║  ██║    ██║         │
 │  ╚══════╝╚═╝  ╚═══╝  ╚═══╝  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝    ╚═╝         │
 │                                                                                        │
 ├──────────────────────────────────────────┬─────────────────────────────────────────────┤
 │ Security Status                          │ System Info                                 │
 │  ● Local Mode: Active                    │  ● Build: Lightweight Go                    │
 │  ● Transmission: None                    │  ● Config: %-32s │
 │  ● Privacy: Offline                      │  ● Platform: %-29s │
 └──────────────────────────────────────────┴─────────────────────────────────────────────┘%s`,
		colorBold+colorCyan,
		configLoaded,
		runtime.GOOS+"/"+runtime.GOARCH,
		colorReset,
	)
	fmt.Println(logo)
	fmt.Println()
}

func detectEnvFiles() []string {
	var files []string
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			name := entry.Name()
			if strings.HasPrefix(name, ".env") {
				files = append(files, name)
			}
		}
	}
	sort.Strings(files)
	return files
}

func cleanPath(p string) string {
	p = strings.TrimSpace(p)
	if len(p) >= 2 {
		// Strip outer double quotes (drag-and-drop artifact)
		if p[0] == '"' && p[len(p)-1] == '"' {
			p = p[1 : len(p)-1]
		} else if p[0] == '\'' && p[len(p)-1] == '\'' {
			// Strip outer single quotes
			p = p[1 : len(p)-1]
		}
	}
	return strings.TrimSpace(p)
}

func fileContentsEqual(file1, file2 string) bool {
	data1, err1 := os.ReadFile(file1)
	data2, err2 := os.ReadFile(file2)
	if err1 != nil || err2 != nil {
		return false
	}
	return string(data1) == string(data2)
}

func parseCommandLine(line string) []string {
	var args []string
	var current strings.Builder
	inDoubleQuote := false
	inSingleQuote := false

	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if inDoubleQuote {
			if r == '"' {
				inDoubleQuote = false
			} else {
				current.WriteRune(r)
			}
		} else if inSingleQuote {
			if r == '\'' {
				inSingleQuote = false
			} else {
				current.WriteRune(r)
			}
		} else {
			if r == '"' {
				inDoubleQuote = true
			} else if r == '\'' {
				inSingleQuote = true
			} else if r == ' ' || r == '\t' {
				if current.Len() > 0 {
					args = append(args, current.String())
					current.Reset()
				}
			} else {
				current.WriteRune(r)
			}
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

func printVisualProgress(numPass, numFail, numWarn int) {
	total := numPass + numFail + numWarn
	if total == 0 {
		return
	}

	drawBar := func(label string, count int, color string) string {
		const maxBars = 30
		pct := float64(count) / float64(total)
		barCount := int(pct * maxBars)
		bars := strings.Repeat("|", barCount)
		spaces := strings.Repeat(" ", maxBars-barCount)
		return fmt.Sprintf("   %-6s [%s%s%s%s] %5.1f%% (%d/%d)", label, color, bars, colorReset, spaces, pct*100, count, total)
	}

	fmt.Println()
	fmt.Println("📊  Status Breakdown:")
	fmt.Println(drawBar("PASS", numPass, colorGreen))
	fmt.Println(drawBar("FAIL", numFail, colorRed))
	fmt.Println(drawBar("WARN", numWarn, colorYellow))
}

func printActionableSuggestions(results []ValidationResult) {
	hasSuggestions := false
	for _, r := range results {
		if r.Status == StatusFail || r.Status == StatusWarn {
			hasSuggestions = true
			break
		}
	}

	if !hasSuggestions {
		return
	}

	fmt.Println()
	fmt.Printf("%s💡 Actionable Recommendations:%s\n", colorCyan+colorBold, colorReset)
	for _, r := range results {
		if (r.Status == StatusFail || r.Status == StatusWarn) && r.Suggestion != "" {
			var symbol string
			if r.Status == StatusFail {
				if strings.Contains(r.Message, "🚨") || strings.Contains(r.Message, "CRITICAL") {
					symbol = fmt.Sprintf("%s🚨 CRITICAL%s", colorRed+colorBold, colorReset)
				} else {
					symbol = fmt.Sprintf("%s✖%s", colorRed, colorReset)
				}
			} else {
				symbol = fmt.Sprintf("%s⚠️ %s", colorYellow, colorReset)
			}
			fmt.Printf("  %s  %s: %s\n", symbol, r.Key, r.Suggestion)
		}
	}
}

func runInteractiveMenu(cfg *Config) {
	reader := bufio.NewReader(os.Stdin)
	for {
		printDashboard(cfg)
		fmt.Printf("%s? What would you like to do?%s\n", colorBold, colorReset)
		fmt.Println("  [1] 🛡️  Validate environment file (.env)")
		fmt.Println("  [2] 🔍  Scan codebase & generate schema (.env.example)")
		fmt.Println("  [3] 💻  Interactive Shell (advanced command input)")
		fmt.Println("  [4] 🔒  View Security & Architecture Information")
		fmt.Println("  [5] 📖  View CLI Command Manual (w/ examples)")
		fmt.Println("  [6] 🛡️  Run Static Security Audit (Credentials & Permissions)")
		fmt.Println("  [7] 👋  Exit")
		fmt.Println()
		fmt.Printf("%s👉 Select an option (1-7): %s", colorBold+colorCyan, colorReset)

		input, err := reader.ReadString('\n')
		if err != nil {
			continue
		}
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			wizardValidate(reader, cfg)
		case "2":
			wizardGenerate(reader, cfg)
		case "3":
			runInteractiveShell(reader, cfg)
		case "4":
			wizardSecurityInfo(reader)
		case "5":
			wizardCommandManual(reader)
		case "6":
			wizardAudit(reader, cfg)
		case "7", "exit", "quit":
			fmt.Printf("\n%s👋 Exiting EnvSentry. Stay secure!%s\n", colorGreen+colorBold, colorReset)
			return
		default:
			// Just loop back
		}
	}
}

func pressEnterToContinue(reader *bufio.Reader) {
	fmt.Println()
	fmt.Printf("%sPress Enter to return to the menu... %s", colorCyan, colorReset)
	_, _ = reader.ReadString('\n')
}

func wizardValidate(reader *bufio.Reader, cfg *Config) {
	clearScreen()
	fmt.Printf("%s🛡️  EnvSentry Validation Wizard%s\n", colorBold+colorCyan, colorReset)
	fmt.Println("💡 Tip: You can drag & drop any file from File Explorer directly into this terminal window!")
	fmt.Println("Type 'back' or 'b' at any prompt to return to the dashboard menu.")
	fmt.Println()

	envFiles := detectEnvFiles()
	selectedEnv := cfg.EnvFile

	// 1. .env path selector
	if len(envFiles) > 0 {
		fmt.Println("🔍  Detected environment files in this workspace:")
		for i, f := range envFiles {
			fmt.Printf("   [%d] %s\n", i+1, f)
		}
		fmt.Println()
		fmt.Printf("📂 Select env file number, type path manually, or drag-and-drop [default: %s]: ", selectedEnv)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "back" || input == "b" {
			return
		}
		if input != "" {
			var choice int
			_, err := fmt.Sscanf(input, "%d", &choice)
			if err == nil && choice >= 1 && choice <= len(envFiles) {
				selectedEnv = envFiles[choice-1]
			} else {
				selectedEnv = cleanPath(input)
			}
		}
	} else {
		fmt.Printf("📂 Enter path to .env file (or drag-and-drop) [default: %s]: ", selectedEnv)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "back" || input == "b" {
			return
		}
		if input != "" {
			selectedEnv = cleanPath(input)
		}
	}

	// 2. .env.example path selector
	selectedSchema := cfg.ExampleFile
	fmt.Println()
	if len(envFiles) > 0 {
		fmt.Println("🔍  Detected files for schema selection:")
		for i, f := range envFiles {
			fmt.Printf("   [%d] %s\n", i+1, f)
		}
		fmt.Println()
		fmt.Printf("📂 Select schema file number, type path manually, or drag-and-drop [default: %s]: ", selectedSchema)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "back" || input == "b" {
			return
		}
		if input != "" {
			var choice int
			_, err := fmt.Sscanf(input, "%d", &choice)
			if err == nil && choice >= 1 && choice <= len(envFiles) {
				selectedSchema = envFiles[choice-1]
			} else {
				selectedSchema = cleanPath(input)
			}
		}
	} else {
		fmt.Printf("📂 Enter path to schema file (or drag-and-drop) [default: %s]: ", selectedSchema)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "back" || input == "b" {
			return
		}
		if input != "" {
			selectedSchema = cleanPath(input)
		}
	}

	// 3. Strict mode
	fmt.Println()
	strictLabel := "N"
	if cfg.Strict {
		strictLabel = "Y"
	}
	fmt.Printf("⚠️  Enable strict mode? (fails on warnings) (y/N) [default: %s]: ", strictLabel)
	strictInput, _ := reader.ReadString('\n')
	strictInput = strings.ToLower(strings.TrimSpace(strictInput))
	if strictInput == "back" || strictInput == "b" {
		return
	}
	isStrict := cfg.Strict
	if strictInput != "" {
		isStrict = strictInput == "y" || strictInput == "yes"
	}

	// Execution
	fmt.Println()
	validateInteractive(selectedEnv, selectedSchema, isStrict, cfg)

	pressEnterToContinue(reader)
}

func wizardGenerate(reader *bufio.Reader, cfg *Config) {
	clearScreen()
	fmt.Printf("%s🔍  EnvSentry Codebase Scan Wizard%s\n", colorBold+colorCyan, colorReset)
	fmt.Println("Type 'back' or 'b' at any prompt to return to the dashboard menu.")
	fmt.Println()

	// 1. codebase dir
	fmt.Printf("📂 Enter directory to scan [default: .]: ")
	scanDir, _ := reader.ReadString('\n')
	scanDir = strings.TrimSpace(scanDir)
	if scanDir == "back" || scanDir == "b" {
		return
	}
	if scanDir != "" {
		scanDir = cleanPath(scanDir)
	} else {
		scanDir = "."
	}

	// 2. output file
	selectedOutput := cfg.ExampleFile
	fmt.Printf("📂 Enter output schema file [default: %s]: ", selectedOutput)
	outputFile, _ := reader.ReadString('\n')
	outputFile = strings.TrimSpace(outputFile)
	if outputFile == "back" || outputFile == "b" {
		return
	}
	if outputFile != "" {
		outputFile = cleanPath(outputFile)
	} else {
		outputFile = selectedOutput
	}

	// 3. excludes
	defaultExcludes := strings.Join(cfg.Exclude, ",")
	fmt.Printf("🚫 Exclude directories (comma-separated) [default: %s]: ", defaultExcludes)
	excludeInput, _ := reader.ReadString('\n')
	excludeInput = strings.TrimSpace(excludeInput)
	if excludeInput == "back" || excludeInput == "b" {
		return
	}
	var excludesList []string
	if excludeInput != "" {
		excludesList = strings.Split(excludeInput, ",")
	} else {
		excludesList = cfg.Exclude
	}
	for i, e := range excludesList {
		excludesList[i] = strings.TrimSpace(e)
	}

	fmt.Printf("\n%s🔍  Scanning %s recursively for variables...%s\n", colorCyan+colorBold, scanDir, colorReset)

	scannedKeys, err := ScanProject(scanDir, excludesList, cfg)
	if err != nil {
		fmt.Printf("  %s✖%s  Error scanning project: %v\n", colorRed+colorBold, colorReset, err)
		pressEnterToContinue(reader)
		return
	}

	fmt.Printf("  %s✔%s  Discovered %d unique environment variable keys:\n", colorGreen+colorBold, colorReset, len(scannedKeys))
	for _, k := range scannedKeys {
		fmt.Printf("      ● %s\n", k)
	}

	newCount, err := GenerateExampleFile(outputFile, scannedKeys)
	if err != nil {
		fmt.Printf("  %s✖%s  Error generating example file %s: %v\n", colorRed+colorBold, colorReset, outputFile, err)
		pressEnterToContinue(reader)
		return
	}

	fmt.Println()
	if newCount > 0 {
		fmt.Printf("%s✔  Updated %s! Added %d new keys to the schema.%s\n", colorGreen+colorBold, outputFile, newCount, colorReset)
		fmt.Printf("   Please define their types in trailing comments (e.g. PORT= # type:int)\n")
	} else {
		fmt.Printf("%s✔  Updated %s! (All scanned keys were already present)%s\n", colorGreen+colorBold, outputFile, colorReset)
	}

	pressEnterToContinue(reader)
}

func wizardSecurityInfo(reader *bufio.Reader) {
	clearScreen()
	fmt.Printf("%s🔒  Security & Architecture Statement%s\n", colorBold+colorCyan, colorReset)
	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%s1. Offline Verification%s\n", colorBold, colorReset)
	fmt.Println("   EnvSentry runs entirely locally. It parses, evaluates, and verifies")
	fmt.Println("   environment variables entirely in memory on your host. Your keys or")
	fmt.Println("   values never touch the internet or get uploaded to any servers.")
	fmt.Println()
	fmt.Printf("%s2. Minimal Footprint%s\n", colorBold, colorReset)
	fmt.Println("   Go-based compilation produces a standalone binary with zero external")
	fmt.Println("   dynamic dependencies. Execution completes in under 10 milliseconds,")
	fmt.Println("   perfect for gating CI/CD pipelines without introducing performance lag.")
	fmt.Println()
	fmt.Printf("%s3. Simple Comment-Based Schema%s\n", colorBold, colorReset)
	fmt.Println("   There are no complex JSON or YAML schema syntax configurations to learn.")
	fmt.Println("   Specify metadata natively in .env.example trailing comments.")
	fmt.Println(strings.Repeat("─", 80))

	pressEnterToContinue(reader)
}

func wizardCommandManual(reader *bufio.Reader) {
	clearScreen()
	fmt.Printf("%s📖  EnvSentry Command Manual & Reference Guide%s\n", colorBold+colorCyan, colorReset)
	fmt.Println(strings.Repeat("─", 80))
	fmt.Printf("%s1. Direct CLI Execution (Script / CI-CD Mode)%s\n", colorBold, colorReset)
	fmt.Println("   • Validate env file:")
	fmt.Println("     envsentry validate [--env <path>] [--example <path>] [--strict]")
	fmt.Println("     Example: envsentry validate -e .env.prod -x .env.example --strict")
	fmt.Println()
	fmt.Println("   • Auto-scan source code and generate/merge schema:")
	fmt.Println("     envsentry generate [--dir <path>] [--output <path>] [--exclude <folders>]")
	fmt.Println("     Example: envsentry generate -d ./src -o .env.example -x \"node_modules,temp\"")
	fmt.Println()
	fmt.Println("   • Run static directory security audit:")
	fmt.Println("     envsentry audit [--dir <path>]")
	fmt.Println("     Example: envsentry audit -d ./")
	fmt.Println()
	fmt.Printf("%s2. Interactive Shell Commands%s\n", colorBold, colorReset)
	fmt.Println("   • validate [-e <path>] [-x <path>] [--strict] - Checks variables")
	fmt.Println("   • generate [-d <path>] [-o <path>]             - Gathers code properties")
	fmt.Println("   • audit [-d <path>]                            - Runs workspace security checks")
	fmt.Println("   • info                                         - View specs")
	fmt.Println("   • clear                                        - Clears terminal screen")
	fmt.Println("   • back / exit                                  - Returns to dashboard")
	fmt.Println()
	fmt.Printf("%s3. Trailing Comment Directive Specifications (.env.example)%s\n", colorBold, colorReset)
	fmt.Println("   • # type:int                  - Integer value matching checks")
	fmt.Println("   • # type:bool                 - Boolean constraints (true, false, yes, no, 1, 0)")
	fmt.Println("   • # type:url                  - URL scheme validation checks")
	fmt.Println("   • # type:email                - Valid email layout check")
	fmt.Println("   • # type:enum(x,y,z)          - Matches one of listed options")
	fmt.Println("   • # range(min,max)            - Lower/Upper bounds (e.g., range(1000,9999))")
	fmt.Println("   • # len(min,max)              - String length limits (e.g., len(8,16))")
	fmt.Println("   • # regex(pattern)            - Matches pattern formatting (supports groups)")
	fmt.Println("   • # optional                  - Prevents missing field failures")
	fmt.Println("   • # deprecated                - Warns if active in environment")
	fmt.Println(strings.Repeat("─", 80))

	pressEnterToContinue(reader)
}

func wizardAudit(reader *bufio.Reader, cfg *Config) {
	clearScreen()
	fmt.Printf("%s🛡️  EnvSentry Static Security Audit Wizard%s\n", colorBold+colorCyan, colorReset)
	fmt.Println("💡 Tip: Enter any local directory or drag-and-drop it into this terminal window.")
	fmt.Println("Type 'back' or 'b' at any prompt to return to the dashboard menu.")
	fmt.Println()

	fmt.Printf("📂 Enter directory to audit [default: .]: ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "back" || input == "b" {
		return
	}

	auditDir := "."
	if input != "" {
		auditDir = cleanPath(input)
	}

	fmt.Printf("\n🔍 Running security audit on directory: %s ...\n", auditDir)

	findings, err := RunAudit(auditDir, cfg)
	if err != nil {
		fmt.Printf("%s✖  Error running security audit: %v%s\n", colorRed+colorBold, err, colorReset)
		pressEnterToContinue(reader)
		return
	}

	PrintAuditReport(findings)

	pressEnterToContinue(reader)
}

func printSuggestions(input string) {
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" {
		return
	}
	commands := []struct {
		name string
		desc string
	}{
		{"validate", "Validate env file against schema"},
		{"generate", "Scan codebase and generate schema"},
		{"audit",    "Run static security checks on directory"},
		{"info",     "Display security specs and architecture"},
		{"clear",    "Clear the terminal screen"},
		{"back",     "Return to the dashboard menu"},
	}

	var matches []string
	for _, c := range commands {
		if strings.HasPrefix(c.name, input) {
			matches = append(matches, fmt.Sprintf("  ● %s (%s)", c.name, c.desc))
		}
	}

	if len(matches) > 0 {
		fmt.Printf("%s💡 Suggestions:%s\n", colorCyan, colorReset)
		for _, m := range matches {
			fmt.Println(m)
		}
	}
}

func runInteractiveShell(reader *bufio.Reader, cfg *Config) {
	clearScreen()
	fmt.Printf("%s💻  EnvSentry Interactive Command Shell%s\n", colorBold+colorCyan, colorReset)
	fmt.Println("Type commands below. Type 'back' or 'exit' to return to the dashboard.")
	fmt.Println("Suggestions / Shortcuts: ")
	fmt.Println("  ● type 'v' or 'validate' to validate env")
	fmt.Println("  ● type 'g' or 'generate' to scan codebase")
	fmt.Println("  ● type 'a' or 'audit' to run security audit")
	fmt.Println("  ● type 'info' to read security specs")
	fmt.Println("  ● type 'clear' to clear terminal screen")
	fmt.Println()

	for {
		fmt.Printf("%senvsentry > %s", colorBold+colorCyan, colorReset)
		input, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		input = strings.TrimSpace(input)
		parts := parseCommandLine(input)
		if len(parts) == 0 {
			fmt.Println("Available commands: [validate, generate, audit, info, clear, back]")
			continue
		}

		cmd := parts[0]
		cmdArgs := parts[1:]

		// Match shortcuts
		if cmd == "v" {
			fmt.Println("Matching shortcut 'v' -> 'validate'...")
			cmd = "validate"
		} else if cmd == "g" {
			fmt.Println("Matching shortcut 'g' -> 'generate'...")
			cmd = "generate"
		} else if cmd == "a" {
			fmt.Println("Matching shortcut 'a' -> 'audit'...")
			cmd = "audit"
		} else if cmd == "i" {
			fmt.Println("Matching shortcut 'i' -> 'info'...")
			cmd = "info"
		} else if cmd == "c" {
			cmd = "clear"
		}

		switch cmd {
		case "validate":
			runValidateInteractiveShell(cmdArgs, cfg)
		case "generate", "scan":
			runGenerateInteractiveShell(cmdArgs, cfg)
		case "audit":
			runAuditInteractiveShell(cmdArgs, cfg)
		case "info":
			fmt.Println("Local Offline Mode. Memory-only parsing. Lightweight (<10ms execution).")
		case "clear":
			clearScreen()
			fmt.Printf("%s💻  EnvSentry Interactive Command Shell%s\n", colorBold+colorCyan, colorReset)
		case "help":
			fmt.Println("Commands:")
			fmt.Println("  validate [--env <path>] [--example <path>] [--strict] - Run validation checks")
			fmt.Println("  generate [--dir <path>] [--output <path>]             - Scan codebase for envs")
			fmt.Println("  audit [--dir <path>]                                  - Runs static directory security audit")
			fmt.Println("  info                                                  - Display specifications")
			fmt.Println("  clear                                                 - Clear terminal screen")
			fmt.Println("  back / exit                                           - Return to dashboard")
		case "back", "exit", "quit":
			return
		default:
			fmt.Printf("%s✖  Unknown command: %q%s\n", colorRed, cmd, colorReset)
			printSuggestions(cmd)
		}
		fmt.Println()
	}
}

// Interactive helper that returns status instead of os.Exit
func validateInteractive(envFile, schemaFile string, isStrict bool, cfg *Config) bool {
	// Check if example file exists
	if _, err := os.Stat(schemaFile); os.IsNotExist(err) {
		fmt.Printf("%s✖  Error: Schema file %q does not exist.%s\n", colorRed+colorBold, schemaFile, colorReset)
		return false
	}

	// Check if env file exists
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		fmt.Printf("%s✖  Error: Environment file %q does not exist.%s\n", colorRed+colorBold, envFile, colorReset)
		return false
	}

	// Warn if paths are identical
	if filepath.Clean(envFile) == filepath.Clean(schemaFile) {
		fmt.Printf("%s⚠️  Warning: Environment file and Schema file are pointing to the same file path (%s).\n   You should validate your .env against a schema template (like .env.example).\n   Because the schema has no comments, all variables default to string checks and pass.%s\n\n", colorYellow, envFile, colorReset)
	} else {
		// Warn if file contents are identical (security leak check)
		if fileContentsEqual(envFile, schemaFile) {
			fmt.Printf("%s⚠️  Security Warning: The contents of %q and %q are identical!\n   This suggests you might have committed production credentials/secrets to your schema template.\n   Please ensure your schema template (.env.example) only contains placeholders (e.g. PORT=) and no actual secrets.%s\n\n", colorYellow, envFile, schemaFile, colorReset)
		}
	}

	// Parse
	exampleVars, err := ParseEnvFile(schemaFile)
	if err != nil {
		fmt.Printf("%s✖  Error parsing schema file %s: %v%s\n", colorRed+colorBold, schemaFile, err, colorReset)
		return false
	}

	envVars, err := ParseEnvFile(envFile)
	if err != nil {
		fmt.Printf("%s✖  Error parsing environment file %s: %v%s\n", colorRed+colorBold, envFile, err, colorReset)
		return false
	}

	results := Validate(exampleVars, envVars, cfg)

	fmt.Printf("🔍  Checking %s against schema %s...\n\n", envFile, schemaFile)

	fmt.Printf("  %s%-8s %-22s %-10s %-16s %-30s%s\n", colorBold, "STATUS", "VARIABLE NAME", "TYPE", "VALUE", "CHECK DETAILS", colorReset)
	fmt.Println("  " + strings.Repeat("─", 90))

	numPass := 0
	numFail := 0
	numWarn := 0

	printedKeys := make(map[string]bool)

	printRow := func(r ValidationResult) {
		if printedKeys[r.Key] {
			return
		}
		printedKeys[r.Key] = true

		varType := "string"
		if schema, exists := exampleVars[r.Key]; exists && schema.Type != "" {
			varType = schema.Type
		}

		maskedVal := "[MISSING]"
		if envVal, exists := envVars[r.Key]; exists {
			maskedVal = maskValue(envVal.DefaultValue)
		}

		var statusStr string
		var detailsStr string
		var rowColor string

		switch r.Status {
		case StatusOk:
			statusStr = "✔ PASS"
			detailsStr = "Checks passed"
			rowColor = colorGreen
			numPass++
		case StatusFail:
			statusStr = "✖ FAIL"
			detailsStr = r.Message
			rowColor = colorRed
			numFail++
		case StatusWarn:
			statusStr = "⚠ WARN"
			detailsStr = r.Message
			rowColor = colorYellow
			numWarn++
		}

		if r.Status == StatusFail && (strings.Contains(r.Message, "🚨") || strings.Contains(r.Message, "CRITICAL")) {
			statusStr = "🚨 CRIT"
			rowColor = colorRed + colorBold
		}

		fmt.Printf("  %s%-8s %-22s %-10s %-16s %-30s%s\n", 
			rowColor, statusStr, r.Key, varType, maskedVal, detailsStr, colorReset)
	}

	for _, schemaVar := range exampleVars {
		for _, r := range results {
			if r.Key == schemaVar.Key {
				printRow(r)
			}
		}
	}
	for _, r := range results {
		printRow(r)
	}

	isSuccess := numFail == 0
	if isStrict && numWarn > 0 {
		isSuccess = false
	}

	// Render breakdown bar chart
	printVisualProgress(numPass, numFail, numWarn)

	// Render suggestions for errors/warnings
	printActionableSuggestions(results)

	fmt.Println()
	if isSuccess {
		if numWarn > 0 {
			fmt.Printf("%s✔  Passed with warnings (%d valid, %d warnings)%s\n", colorYellow+colorBold, numPass, numWarn, colorReset)
		} else {
			fmt.Printf("%s✔  Passed! All %d checks successful.%s\n", colorGreen+colorBold, numPass, colorReset)
		}
	} else {
		if isStrict && numFail == 0 && numWarn > 0 {
			fmt.Printf("%s✖  Failed! Strict mode triggered by %d warnings (%d valid).%s\n", colorRed+colorBold, numWarn, numPass, colorReset)
		} else {
			fmt.Printf("%s✖  Failed! Detected %d validation failures and %d warnings.%s\n", colorRed+colorBold, numFail, numWarn, colorReset)
		}
	}

	return isSuccess
}

func runValidateInteractiveShell(args []string, cfg *Config) {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	envPath := fs.String("env", cfg.EnvFile, "Path to .env file")
	envShort := fs.String("e", cfg.EnvFile, "Path to .env file (shorthand)")
	examplePath := fs.String("example", cfg.ExampleFile, "Path to schema file")
	exampleShort := fs.String("x", cfg.ExampleFile, "Path to schema file (shorthand)")
	strict := fs.Bool("strict", cfg.Strict, "Strict mode: treat warnings as errors")
	strictShort := fs.Bool("s", cfg.Strict, "Strict mode (shorthand)")

	if err := fs.Parse(args); err != nil {
		return
	}

	finalEnv := cleanPath(*envPath)
	if *envShort != cfg.EnvFile {
		finalEnv = cleanPath(*envShort)
	}
	finalExample := cleanPath(*examplePath)
	if *exampleShort != cfg.ExampleFile {
		finalExample = cleanPath(*exampleShort)
	}
	finalStrict := *strict || *strictShort

	validateInteractive(finalEnv, finalExample, finalStrict, cfg)
}

func runGenerateInteractiveShell(args []string, cfg *Config) {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	dir := fs.String("dir", ".", "Directory to scan recursively")
	dirShort := fs.String("d", ".", "Directory to scan recursively (shorthand)")
	output := fs.String("output", cfg.ExampleFile, "Path to output schema")
	outputShort := fs.String("o", cfg.ExampleFile, "Path to output schema (shorthand)")
	exclude := fs.String("exclude", strings.Join(cfg.Exclude, ","), "Comma-separated ignore list")
	excludeShort := fs.String("x", strings.Join(cfg.Exclude, ","), "Comma-separated ignore list (shorthand)")

	if err := fs.Parse(args); err != nil {
		return
	}

	finalDir := cleanPath(*dir)
	if *dirShort != "." {
		finalDir = cleanPath(*dirShort)
	}
	finalOutput := cleanPath(*output)
	if *outputShort != cfg.ExampleFile {
		finalOutput = cleanPath(*outputShort)
	}
	finalExclude := *exclude
	if *excludeShort != strings.Join(cfg.Exclude, ",") {
		finalExclude = *excludeShort
	}

	excludesList := strings.Split(finalExclude, ",")
	for i, e := range excludesList {
		excludesList[i] = strings.TrimSpace(e)
	}

	fmt.Printf("🔍  Scanning %s recursively for variables...\n", finalDir)

	scannedKeys, err := ScanProject(finalDir, excludesList, cfg)
	if err != nil {
		fmt.Printf("  ✖  Error scanning project: %v\n", err)
		return
	}

	fmt.Printf("  ✔  Discovered %d unique environment variable keys:\n", len(scannedKeys))
	for _, k := range scannedKeys {
		fmt.Printf("      ● %s\n", k)
	}

	newCount, err := GenerateExampleFile(finalOutput, scannedKeys)
	if err != nil {
		fmt.Printf("  ✖  Error generating example file %s: %v\n", finalOutput, err)
		return
	}

	fmt.Println()
	if newCount > 0 {
		fmt.Printf("✔  Updated %s! Added %d new keys to the schema.\n", finalOutput, newCount)
	} else {
		fmt.Printf("✔  Updated %s! (All scanned keys were already present)\n", finalOutput)
	}
}

func runAuditInteractiveShell(args []string, cfg *Config) {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	dir := fs.String("dir", ".", "Directory to audit recursively")
	dirShort := fs.String("d", ".", "Directory to audit recursively (shorthand)")

	if err := fs.Parse(args); err != nil {
		return
	}

	finalDir := cleanPath(*dir)
	if *dirShort != "." {
		finalDir = cleanPath(*dirShort)
	}

	fmt.Printf("🔍  Running static security audit on: %s ...\n", finalDir)

	findings, err := RunAudit(finalDir, cfg)
	if err != nil {
		fmt.Printf("  ✖  Error running security audit: %v\n", err)
		return
	}

	PrintAuditReport(findings)
}

func runValidate(args []string, cfg *Config) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	envPath := fs.String("env", cfg.EnvFile, "Path to the actual .env file")
	envShort := fs.String("e", cfg.EnvFile, "Path to the actual .env file (shorthand)")
	examplePath := fs.String("example", cfg.ExampleFile, "Path to the schema .env.example file")
	exampleShort := fs.String("x", cfg.ExampleFile, "Path to the schema .env.example file (shorthand)")
	strict := fs.Bool("strict", cfg.Strict, "Strict mode: treat warnings as errors")
	strictShort := fs.Bool("s", cfg.Strict, "Strict mode (shorthand)")

	fs.Usage = func() {
		fmt.Println("Usage: envsentry validate [options]")
		fmt.Println("Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	finalEnv := cleanPath(*envPath)
	if *envShort != cfg.EnvFile {
		finalEnv = cleanPath(*envShort)
	}
	finalExample := cleanPath(*examplePath)
	if *exampleShort != cfg.ExampleFile {
		finalExample = cleanPath(*exampleShort)
	}
	finalStrict := *strict || *strictShort

	success := validateInteractive(finalEnv, finalExample, finalStrict, cfg)
	if success {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func runGenerate(args []string, cfg *Config) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	dir := fs.String("dir", ".", "Directory to scan recursively")
	dirShort := fs.String("d", ".", "Directory to scan recursively (shorthand)")
	output := fs.String("output", cfg.ExampleFile, "Path to output the generated .env.example")
	outputShort := fs.String("o", cfg.ExampleFile, "Path to output the generated .env.example (shorthand)")
	exclude := fs.String("exclude", strings.Join(cfg.Exclude, ","), "Comma-separated list of directories to ignore")
	excludeShort := fs.String("x", strings.Join(cfg.Exclude, ","), "Comma-separated list of directories to ignore (shorthand)")

	fs.Usage = func() {
		fmt.Println("Usage: envsentry generate [options]")
		fmt.Println("Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	finalDir := cleanPath(*dir)
	if *dirShort != "." {
		finalDir = cleanPath(*dirShort)
	}
	finalOutput := cleanPath(*output)
	if *outputShort != cfg.ExampleFile {
		finalOutput = cleanPath(*outputShort)
	}
	finalExclude := *exclude
	if *excludeShort != strings.Join(cfg.Exclude, ",") {
		finalExclude = *excludeShort
	}

	excludesList := strings.Split(finalExclude, ",")
	for i, e := range excludesList {
		excludesList[i] = strings.TrimSpace(e)
	}

	fmt.Printf("\n🔍  Scanning %s recursively for variables...\n", finalDir)

	scannedKeys, err := ScanProject(finalDir, excludesList, cfg)
	if err != nil {
		fmt.Printf("  ✖  Error scanning project: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  ✔  Discovered %d unique environment variable keys:\n", len(scannedKeys))
	for _, k := range scannedKeys {
		fmt.Printf("      ● %s\n", k)
	}

	newCount, err := GenerateExampleFile(finalOutput, scannedKeys)
	if err != nil {
		fmt.Printf("  ✖  Error generating example file %s: %v\n", finalOutput, err)
		os.Exit(1)
	}

	fmt.Println()
	if newCount > 0 {
		fmt.Printf("✔  Updated %s! Added %d new keys to the schema.\n", finalOutput, newCount)
		fmt.Printf("   Please define their types in trailing comments (e.g. PORT= # type:int)\n")
	} else {
		fmt.Printf("✔  Updated %s! (All scanned keys were already present)\n", finalOutput)
	}
}

func runAuditSubcommand(args []string, cfg *Config) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	dir := fs.String("dir", ".", "Directory to audit recursively")
	dirShort := fs.String("d", ".", "Directory to audit recursively (shorthand)")

	fs.Usage = func() {
		fmt.Println("Usage: envsentry audit [options]")
		fmt.Println("Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	finalDir := cleanPath(*dir)
	if *dirShort != "." {
		finalDir = cleanPath(*dirShort)
	}

	fmt.Printf("\n🔍  Running static security audit on directory: %s ...\n", finalDir)

	findings, err := RunAudit(finalDir, cfg)
	if err != nil {
		fmt.Printf("  ✖  Error running security audit: %v\n", err)
		os.Exit(1)
	}

	PrintAuditReport(findings)

	// If critical vulnerabilities are found, exit with non-zero code for pipeline checks
	numCritical := 0
	for _, f := range findings {
		if f.Severity == "CRITICAL" {
			numCritical++
		}
	}

	if numCritical > 0 {
		os.Exit(1)
	}
	os.Exit(0)
}

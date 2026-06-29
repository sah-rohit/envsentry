package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
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
	fmt.Println("  generate   Recursively scans JS, TS, and Python code to auto-generate or merge .env.example")
	fmt.Println("  version    Prints EnvSentry version")
	fmt.Println()
	fmt.Println("Use \"envsentry <command> --help\" for more info about a command.")
}

func main() {
	// If arguments are passed, bypass interactive menu (great for CI/CD and scripts)
	if len(os.Args) >= 2 {
		command := os.Args[1]
		switch command {
		case "validate":
			runValidate(os.Args[2:])
		case "generate", "scan":
			runGenerate(os.Args[2:])
		case "version":
			fmt.Println("envsentry v1.0.0")
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
	runInteractiveMenu()
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

func printDashboard() {
	clearScreen()
	logo := fmt.Sprintf(`%s ┌────────────────────────────────────────────────────────────────────────────────────────┐
 │  EnvSentry v1.0.0                                                                      │
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
 │  ● Transmission: None                    │  ● Execution time: <10ms                    │
 │  ● Privacy: Offline                      │  ● Platform: %-29s │
 └──────────────────────────────────────────┴─────────────────────────────────────────────┘%s`,
		colorBold+colorCyan,
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

func runInteractiveMenu() {
	reader := bufio.NewReader(os.Stdin)
	for {
		printDashboard()
		fmt.Printf("%s? What would you like to do?%s\n", colorBold, colorReset)
		fmt.Println("  [1] 🛡️  Validate environment file (.env)")
		fmt.Println("  [2] 🔍  Scan codebase & generate schema (.env.example)")
		fmt.Println("  [3] 💻  Interactive Shell (advanced command input)")
		fmt.Println("  [4] 🔒  View Security & Architecture Information")
		fmt.Println("  [5] 👋  Exit")
		fmt.Println()
		fmt.Printf("%s👉 Select an option (1-5): %s", colorBold+colorCyan, colorReset)

		input, err := reader.ReadString('\n')
		if err != nil {
			continue
		}
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			wizardValidate(reader)
		case "2":
			wizardGenerate(reader)
		case "3":
			runInteractiveShell(reader)
		case "4":
			wizardSecurityInfo(reader)
		case "5", "exit", "quit":
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

func wizardValidate(reader *bufio.Reader) {
	clearScreen()
	fmt.Printf("%s🛡️  EnvSentry Validation Wizard%s\n", colorBold+colorCyan, colorReset)
	fmt.Println("💡 Tip: You can drag & drop any file from File Explorer directly into this terminal window!")
	fmt.Println("Type 'back' or 'b' at any prompt to return to the dashboard menu.")
	fmt.Println()

	envFiles := detectEnvFiles()
	selectedEnv := ".env"

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
		fmt.Printf("📂 Enter path to .env file (or drag-and-drop) [default: .env]: ")
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
	selectedSchema := ".env.example"
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
		fmt.Printf("📂 Enter path to schema file (or drag-and-drop) [default: .env.example]: ")
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
	fmt.Printf("⚠️  Enable strict mode? (fails on warnings) (y/N): ")
	strictInput, _ := reader.ReadString('\n')
	strictInput = strings.ToLower(strings.TrimSpace(strictInput))
	if strictInput == "back" || strictInput == "b" {
		return
	}
	isStrict := strictInput == "y" || strictInput == "yes"

	// Execution
	fmt.Println()
	validateInteractive(selectedEnv, selectedSchema, isStrict)

	pressEnterToContinue(reader)
}

func wizardGenerate(reader *bufio.Reader) {
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
	fmt.Printf("📂 Enter output schema file [default: .env.example]: ")
	outputFile, _ := reader.ReadString('\n')
	outputFile = strings.TrimSpace(outputFile)
	if outputFile == "back" || outputFile == "b" {
		return
	}
	if outputFile != "" {
		outputFile = cleanPath(outputFile)
	} else {
		outputFile = ".env.example"
	}

	// 3. excludes
	fmt.Printf("🚫 Exclude directories (comma-separated) [default: node_modules,.git,venv,__pycache__,dist,build]: ")
	excludeInput, _ := reader.ReadString('\n')
	excludeInput = strings.TrimSpace(excludeInput)
	if excludeInput == "back" || excludeInput == "b" {
		return
	}
	if excludeInput == "" {
		excludeInput = "node_modules,.git,venv,__pycache__,dist,build"
	}

	excludesList := strings.Split(excludeInput, ",")
	for i, e := range excludesList {
		excludesList[i] = strings.TrimSpace(e)
	}

	fmt.Printf("\n%s🔍  Scanning %s recursively for variables...%s\n", colorCyan+colorBold, scanDir, colorReset)

	scannedKeys, err := ScanProject(scanDir, excludesList)
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

func runInteractiveShell(reader *bufio.Reader) {
	clearScreen()
	fmt.Printf("%s💻  EnvSentry Interactive Command Shell%s\n", colorBold+colorCyan, colorReset)
	fmt.Println("Type commands below. Type 'back' or 'exit' to return to the dashboard.")
	fmt.Println("Suggestions / Shortcuts: ")
	fmt.Println("  ● type 'v' or 'validate' to validate env")
	fmt.Println("  ● type 'g' or 'generate' to scan codebase")
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
			fmt.Println("Available commands: [validate, generate, info, clear, back]")
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
		} else if cmd == "i" {
			fmt.Println("Matching shortcut 'i' -> 'info'...")
			cmd = "info"
		} else if cmd == "c" {
			cmd = "clear"
		}

		switch cmd {
		case "validate":
			runValidateInteractiveShell(cmdArgs)
		case "generate", "scan":
			runGenerateInteractiveShell(cmdArgs)
		case "info":
			fmt.Println("Local Offline Mode. Memory-only parsing. Lightweight (<10ms execution).")
		case "clear":
			clearScreen()
			fmt.Printf("%s💻  EnvSentry Interactive Command Shell%s\n", colorBold+colorCyan, colorReset)
		case "help":
			fmt.Println("Commands:")
			fmt.Println("  validate [--env <path>] [--example <path>] [--strict] - Run validation checks")
			fmt.Println("  generate [--dir <path>] [--output <path>]             - Scan codebase for envs")
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
func validateInteractive(envFile, schemaFile string, isStrict bool) bool {
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

	results := Validate(exampleVars, envVars)

	fmt.Printf("🔍  Checking %s against schema %s...\n\n", envFile, schemaFile)

	numPass := 0
	numFail := 0
	numWarn := 0

	printedKeys := make(map[string]bool)

	printRow := func(r ValidationResult) {
		if printedKeys[r.Key] {
			return
		}
		printedKeys[r.Key] = true

		switch r.Status {
		case StatusOk:
			varType := "string"
			if schema, exists := exampleVars[r.Key]; exists && schema.Type != "" {
				varType = schema.Type
			}
			fmt.Printf("  %s✔%s  %s %sis valid (%s)%s\n", colorGreen+colorBold, colorReset, r.Key, colorBold, varType, colorReset)
			numPass++
		case StatusFail:
			fmt.Printf("  %s✖%s  %s %s%s%s\n", colorRed+colorBold, colorReset, r.Key, colorRed, r.Message, colorReset)
			numFail++
		case StatusWarn:
			fmt.Printf("  %s⚠%s  %s %s%s%s\n", colorYellow+colorBold, colorReset, r.Key, colorYellow, r.Message, colorReset)
			numWarn++
		}
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

func runValidateInteractiveShell(args []string) {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	envPath := fs.String("env", ".env", "Path to .env file")
	envShort := fs.String("e", ".env", "Path to .env file (shorthand)")
	examplePath := fs.String("example", ".env.example", "Path to schema file")
	exampleShort := fs.String("x", ".env.example", "Path to schema file (shorthand)")
	strict := fs.Bool("strict", false, "Strict mode: treat warnings as errors")
	strictShort := fs.Bool("s", false, "Strict mode (shorthand)")

	if err := fs.Parse(args); err != nil {
		return
	}

	finalEnv := cleanPath(*envPath)
	if *envShort != ".env" {
		finalEnv = cleanPath(*envShort)
	}
	finalExample := cleanPath(*examplePath)
	if *exampleShort != ".env.example" {
		finalExample = cleanPath(*exampleShort)
	}
	finalStrict := *strict || *strictShort

	validateInteractive(finalEnv, finalExample, finalStrict)
}

func runGenerateInteractiveShell(args []string) {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	dir := fs.String("dir", ".", "Directory to scan recursively")
	dirShort := fs.String("d", ".", "Directory to scan recursively (shorthand)")
	output := fs.String("output", ".env.example", "Path to output schema")
	outputShort := fs.String("o", ".env.example", "Path to output schema (shorthand)")
	exclude := fs.String("exclude", "node_modules,.git,venv,__pycache__,dist,build", "Comma-separated ignore list")
	excludeShort := fs.String("x", "node_modules,.git,venv,__pycache__,dist,build", "Comma-separated ignore list (shorthand)")

	if err := fs.Parse(args); err != nil {
		return
	}

	finalDir := cleanPath(*dir)
	if *dirShort != "." {
		finalDir = cleanPath(*dirShort)
	}
	finalOutput := cleanPath(*output)
	if *outputShort != ".env.example" {
		finalOutput = cleanPath(*outputShort)
	}
	finalExclude := *exclude
	if *excludeShort != "node_modules,.git,venv,__pycache__,dist,build" {
		finalExclude = *excludeShort
	}

	excludesList := strings.Split(finalExclude, ",")
	for i, e := range excludesList {
		excludesList[i] = strings.TrimSpace(e)
	}

	fmt.Printf("🔍  Scanning %s recursively for variables...\n", finalDir)

	scannedKeys, err := ScanProject(finalDir, excludesList)
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

func runValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	envPath := fs.String("env", ".env", "Path to the actual .env file")
	envShort := fs.String("e", ".env", "Path to the actual .env file (shorthand)")
	examplePath := fs.String("example", ".env.example", "Path to the schema .env.example file")
	exampleShort := fs.String("x", ".env.example", "Path to the schema .env.example file (shorthand)")
	strict := fs.Bool("strict", false, "Strict mode: treat warnings as errors")
	strictShort := fs.Bool("s", false, "Strict mode (shorthand)")

	fs.Usage = func() {
		fmt.Println("Usage: envsentry validate [options]")
		fmt.Println("Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	finalEnv := cleanPath(*envPath)
	if *envShort != ".env" {
		finalEnv = cleanPath(*envShort)
	}
	finalExample := cleanPath(*examplePath)
	if *exampleShort != ".env.example" {
		finalExample = cleanPath(*exampleShort)
	}
	finalStrict := *strict || *strictShort

	success := validateInteractive(finalEnv, finalExample, finalStrict)
	if success {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}

func runGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	dir := fs.String("dir", ".", "Directory to scan recursively")
	dirShort := fs.String("d", ".", "Directory to scan recursively (shorthand)")
	output := fs.String("output", ".env.example", "Path to output the generated .env.example")
	outputShort := fs.String("o", ".env.example", "Path to output the generated .env.example (shorthand)")
	exclude := fs.String("exclude", "node_modules,.git,venv,__pycache__,dist,build", "Comma-separated list of directories to ignore")
	excludeShort := fs.String("x", "node_modules,.git,venv,__pycache__,dist,build", "Comma-separated list of directories to ignore (shorthand)")

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
	if *outputShort != ".env.example" {
		finalOutput = cleanPath(*outputShort)
	}
	finalExclude := *exclude
	if *excludeShort != "node_modules,.git,venv,__pycache__,dist,build" {
		finalExclude = *excludeShort
	}

	excludesList := strings.Split(finalExclude, ",")
	for i, e := range excludesList {
		excludesList[i] = strings.TrimSpace(e)
	}

	fmt.Printf("\n🔍  Scanning %s recursively for variables...\n", finalDir)

	scannedKeys, err := ScanProject(finalDir, excludesList)
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

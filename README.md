# 🛡️ EnvSentry

`envsentry` is a fast, lightweight DevOps and Security CLI tool written in Go that ensures your environment variables match your schema definitions before you run your application or build your Docker images.

It prevents runtime crashes caused by missing or malformed environment variables (like `process.env.API_KEY` being undefined in production) by acting as a gateway in your CI/CD pipelines (e.g. GitHub Actions) or pre-commit hooks.

## 🚀 Features

- **Interactive CLI Dashboard**: Runs automatically when you execute the tool without arguments. Displays a premium ASCII logo and metadata box.
- **Guided Wizards**: Step-by-step setup guides to validate env files or scan project files recursively (just press Enter to accept defaults!).
- **Advanced Command Shell**: Enter the shell to type commands manually with input suggestions, quick-alias shortcuts (e.g. `v` for `validate`), and help hints.
- **Validation Engine**: Compare `.env` variables against a schema defined in `.env.example`.
- **Comment-Based Schema Definition**: Declare types, optionality, and deprecation status directly inside `.env.example` comments.
- **Type Checking Support**:
  - `int`, `float`, `bool`, `string`, `email`, `url`, `enum(...)`
- **Deprecation Warnings**: Detect lingering deprecated keys in your active `.env` files.
- **Undocumented Warnings**: Find keys present in `.env` but missing from the `.env.example` schema.
- **Auto-Scanner**: Scan Python, JS, and TS codebases recursively for variable references and automatically populate or merge your `.env.example` file.
- **CI/CD & Script Integration**: Exits with a non-zero code on failures when run with command arguments, bypassing the interactive dashboard entirely.
- **Offline & Secure**: Performs all checks locally in memory. **Zero** dynamic dependencies and **zero** network activity.

---

## 🛠️ Distribution & Installation

Because `envsentry` is compiled as a single binary with zero external runtime dependencies, it is extremely easy to use:
- **Offline & Secure**: It runs completely locally on your machine. It **never** uploads or transmits your `.env` keys or values to any server.
- **Lightweight**: The executable is tiny (~2.5 MB) and execution completes in `< 10ms`.
- **Install via Go**:
  ```bash
  go install github.com/username/envsentry@latest
  ```
- **Manual Download**: Simply download the binary from the releases and put it in your system's PATH.

---

## 📖 Usage Modes

### Mode A: Interactive Dashboard (Recommended for Developers)
Simply run the binary without arguments:
```bash
.\envsentry.exe
```
This opens the beautiful interactive menu where you can choose options:
```
 ┌────────────────────────────────────────────────────────────────────────────────────────┐
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
 │  ● Privacy: Offline                      │  ● Platform: windows/386                    │
 └──────────────────────────────────────────┴─────────────────────────────────────────────┘


? What would you like to do?
  [1] 🛡️  Validate environment file (.env)
  [2] 🔍  Scan codebase & generate schema (.env.example)
  [3] 💻  Interactive Shell (advanced command input)
  [4] 🔒  View Security & Architecture Information
  [5] 👋  Exit

👉 Select an option (1-5):
```

#### Selection Options:
1. **[1] Validate wizard**: Guides you through inputting the `.env` path, `.env.example` path, and strict flag setting (press Enter to accept default paths!).
2. **[2] Codebase Scan wizard**: Guides you through inputting the scan directory, output schema path, and folder excludes to build your `.env.example` template.
3. **[3] Command Shell**: Opens a prompt (`envsentry > `) for advanced typing.
   - Type `v` or `validate` to validate.
   - Type `g` or `generate` to scan.
   - Type `info` for system information.
   - Type `clear` to clear screen.
   - Type `back` or `exit` to return to dashboard.

---

### Mode B: Direct CLI Execution (Recommended for CI/CD and Scripts)
Pass commands directly to bypass the interactive UI.

#### 1. Auto-Scan & Generate Schema
```bash
envsentry generate --dir . --output .env.example
```
*Shorthand:*
```bash
envsentry generate -d . -o .env.example
```

#### 2. Validate Environment Files
```bash
envsentry validate --env .env --example .env.example
```
*Shorthand:*
```bash
envsentry validate -e .env -x .env.example
```

#### 3. Strict Mode Validation
Returns non-zero exit code if there are any warnings (deprecated variables or undocumented keys):
```bash
envsentry validate -e .env -x .env.example --strict
```

---

## 🛡️ CI/CD Integration

### GitHub Actions Example
Add `envsentry` to your build workflow to block deployments on invalid environment setups:

```yaml
name: Build and Validate
on: [push]

jobs:
  validate-env:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.20'
      - name: Build EnvSentry
        run: go build -o envsentry .
      - name: Validate Production Env Schema
        run: ./envsentry validate --env .env.production --example .env.example --strict
```

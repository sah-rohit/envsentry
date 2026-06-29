# 🛡️ EnvSentry

`envsentry` is a fast, lightweight DevOps and Security CLI tool written in Go that ensures your environment variables match your schema definitions before you run your application or build your Docker images.

It prevents runtime crashes caused by missing or malformed environment variables (like `process.env.API_KEY` being undefined in production) by acting as a gateway in your CI/CD pipelines (e.g. GitHub Actions) or pre-commit hooks.

## 🚀 Features

- **Interactive CLI Dashboard**: Runs automatically when you execute the tool without arguments. Displays a premium ASCII logo and metadata box.
- **Guided Wizards**: Step-by-step setup guides to validate env files, run security audits, or scan project files recursively (just press Enter to accept default paths!).
- **Advanced Command Shell**: Enter the shell to type commands manually with input suggestions, quick-alias shortcuts (e.g. `v` for `validate`), and help hints.
- **Validation Engine**: Compare `.env` variables against a schema defined in `.env.example`.
- **Comment-Based Schema Definition**: Declare types, optionality, and deprecation status directly inside `.env.example` comments.
- **Type Checking Support**:
  - `int`, `float`, `bool`, `string`, `email`, `url`, `enum(...)`, and custom regex patterns.
- **Range & Length Limits**: Support boundary verification (e.g. `range(1000,9999)` or `len(8,16)`).
- **Security Check Warnings**: Detects if your active `.env` and `.env.example` schema contain identical secrets, warning you before committing credentials to Git.
- **Static Security Audit (`audit` mode)**: Runs static checks on directories to find leaked credentials/private keys, audit Unix file permissions on sensitive files, and flag insecure configuration/log backups.
- **Deprecation Warnings**: Detect lingering deprecated keys in your active `.env` files.
- **Undocumented Warnings**: Find keys present in `.env` but missing from the `.env.example` schema.
- **Auto-Scanner**: Scan codebases (JavaScript, TypeScript, Python, Go, Rust, PHP, Java, and C#) recursively for variable references and automatically populate or merge your `.env.example` file.
- **Configuration File Support**: Use `envsentry.yaml` to specify default paths, excluded folders, and custom regex validations.
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
 │  ● Transmission: None                    │  ● Execution time: <10ms                    │
 │  ● Privacy: Offline                      │  ● Platform: windows/386                    │
 └──────────────────────────────────────────┴─────────────────────────────────────────────┘


? What would you like to do?
  [1] 🛡️  Validate environment file (.env)
  [2] 🔍  Scan codebase & generate schema (.env.example)
  [3] 💻  Interactive Shell (advanced command input)
  [4] 🔒  View Security & Architecture Information
  [5] 📖  View CLI Command Manual (w/ examples)
  [6] 🛡️  Run Static Security Audit (Credentials & Permissions)
  [7] 👋  Exit

👉 Select an option (1-7):
```

---

### Mode B: Direct CLI Execution (Recommended for CI/CD and Scripts)
Pass commands directly to bypass the interactive UI.

#### 1. Run Static Security Audit
Scans directories for leaked keys, certificate files, backup files, and insecure permissions:
```bash
envsentry audit --dir .
```
*Shorthand:*
```bash
envsentry audit -d .
```

#### 2. Auto-Scan & Generate Schema
```bash
envsentry generate --dir . --output .env.example
```

#### 3. Validate Environment Files
```bash
envsentry validate --env .env --example .env.example
```

---

## 📖 Detailed CLI Command Manual & Technical Reference

### 1. Commands & Parameter Syntax

#### Command: `audit`
Runs static auditing on target directories.
- **Parameters**:
  - `--dir`, `-d` *(string)*: Target directory to scan. Defaults to `.`.
  - Exits with a non-zero exit code if any **CRITICAL** severity vulnerabilities (such as exposed private keys, Stripe/AWS/GitHub keys, or overly permissive permissions) are identified.

#### Command: `validate`
Verifies an environment variables file against a target schema specification.
- **Parameters**:
  - `--env`, `-e` *(string)*: Path to the target active environment file.
  - `--example`, `-x` *(string)*: Path to the schema file template.
  - `--strict`, `-s` *(boolean)*: Treat any validation warning as a critical failure.

#### Command: `generate`
Recursively scans codebases and configuration configurations (Docker Compose, Github Actions) and generates schemas.

---

### 2. Trailing Comment Directive Specifications
Define validation constraints inside `.env.example`:

| Directive Syntax | Type Description | Example |
| :--- | :--- | :--- |
| `# type:int` | Value must be a valid integer. | `PORT=8080 # type:int` |
| `# type:bool` | Value must match: `true`, `false`, `1`, `0`, `yes`, `no`, `on`, `off`. | `DEBUG=true # type:bool` |
| `# type:url` | Value must be an absolute URL. | `API_URL= # type:url` |
| `# type:email` | Value must conform to email layouts. | `ADMIN_EMAIL= # type:email` |
| `# range(min,max)` | Sets lower and upper numeric boundaries. | `PORT=8080 # type:int # range(1024,65535)` |
| `# len(min,max)` | Sets string character count boundaries. | `API_KEY= # type:string # len(16,64)` |
| `# regex(pattern)` | Validates formatting against regex formatting. | `TOKEN= # type:string # regex(^[a-f0-9]{32}$)` |

---

### 3. Static Security Audit Auditing Rules
The `audit` command runs static inspection checks including:
- **Exposed Secret Verification**: Scans files (excluding `.git`, `node_modules` and other ignored directories) for Stripe keys, AWS key pairs, Google APIs, and GitHub tokens, or any high-entropy token strings.
- **Unix Permissions Check**: Assesses files containing private credentials (like SSH keys, `.env`, or `.pem` certificates). Flags any files that are group/world-readable or writable.
- **Insecure File Types Detector**: Identifies dump files (`.sql`, `.dump`), databases (`.sqlite`, `.db`), raw logs (`.log`), and compose override configurations that are not ignored.

---

## 🛡️ CI/CD Integration

### GitHub Actions Example
Add `envsentry` to check both variable schema compliance and secure directory permissions:

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
      - name: Run Directory Security Audit
        run: ./envsentry audit --dir .
      - name: Validate Env Schema
        run: ./envsentry validate --env .env --example .env.example --strict
```

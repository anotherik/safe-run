# safe-run

A supply-chain safety gate built on [`osv-scanner`](https://github.com/google/osv-scanner) and the [`OSV vulnerability database`](https://osv.dev/). It scans your resolved dependency graph via lockfiles and refuses to execute when malware or critical vulnerabilities are present. If you pass a command, it runs only after the scan passes; without a command, it performs a scan and exits.

Lockfiles are the exact, pinned dependency graph your package manager resolved. They represent what will actually be installed and executed, which is why they’re the most reliable input for supply-chain checks.

## Why It Matters

Modern compromises increasingly ride the dependency graph: typosquats, maintainer takeovers, and poisoned transitive chains. For developers, the lockfile is the executable truth, not the README. This tool puts a **hard preflight check** in front of execution so malware and critical issues are blocked before they ever run. It’s fast, repeatable, and optimized for reducing supply-chain risk in day‑to‑day development workflows.

## Requirements

- `osv-scanner` available on your PATH
- `jq` available on your PATH (required for JSON parsing/counts)
- Python 3 with the `cvss` package (to compute CVSS v3/v4 base scores)
- One or more supported lockfiles in the project directory

Install `osv-scanner`:

```bash
# macOS (Homebrew)
brew install osv-scanner

# Linux (download latest release)
curl -L -o osv-scanner https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64
chmod +x osv-scanner
sudo mv osv-scanner /usr/local/bin/

# Windows (PowerShell)
Invoke-WebRequest -Uri https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_windows_amd64.exe -OutFile osv-scanner.exe
Move-Item .\osv-scanner.exe $env:USERPROFILE\\bin\\osv-scanner.exe
```

Install `jq`:

```bash
# macOS (Homebrew)
brew install jq

# Ubuntu/Debian
sudo apt-get install -y jq
```

Install Python `cvss`:

```bash
python3 -m pip install cvss
```

## Supported lockfiles (language → package manager):

- Node.js → npm / pnpm / Yarn / Bun: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lockb`
- Python → pip / Poetry / Pipenv / uv: `requirements.txt`, `poetry.lock`, `Pipfile.lock`, `uv.lock`
- Rust → Cargo: `Cargo.lock`
- Go → Go modules: `go.mod`
- Java/Kotlin → Maven / Gradle: `pom.xml`, `build.gradle`, `build.gradle.kts`
- Ruby → Bundler: `Gemfile.lock`
- PHP → Composer: `composer.lock`
- Dart → Pub: `pubspec.lock`
- Elixir → Mix: `mix.lock`

## Usage

```bash
./safe-run.sh [command...]
```

Examples:

```bash
./safe-run.sh                 # scan only
./safe-run.sh npm start        # scan then run
./safe-run.sh ./app --flag     # scan then run
./safe-run.sh --help           # show help
```

## Safe workflow

To reduce exposure to malicious post/pre‑install scripts:

- Prefer a locked dependency graph in version control.
- You can **scan without installing** by running the script with no command.
- When you do install, disable lifecycle scripts, then scan, then run.

Scan-only (no install):

```bash
./safe-run.sh
```

Example (npm):

```bash
npm ci --ignore-scripts
./safe-run.sh npm start
```

Example (pip):

```bash
python3 -m pip install -r requirements.txt --no-deps
./safe-run.sh python3 app.py
```

This keeps the **first execution gated** by malware and vulnerability checks and limits script-based supply-chain risk.

## Exit behavior

- Exits with `1` if malware is detected
- Exits with `1` if any critical vulnerabilities are detected
- Exits with `1` if no supported lockfiles are found
- Otherwise exits with `0` after scan-only or after your command finishes

## Output behavior

- Prints all discovered lockfiles
- Displays a custom table with OSV URL, GHSA/CVE mapping, severity score, and heuristic flags (RCE/unauth)
- Shows a `DEP_TYPE` column for npm and PyPI to indicate direct vs transitive dependencies
- Summarizes counts for total vulnerabilities, malware, and critical issues
- Only proceeds to run the command if the scan is clean (no malware, no critical)

## License

Apache License 2.0. See `LICENSE`.

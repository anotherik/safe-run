#!/bin/bash
# =============================================
# Universal OSV Proactive Guard
# - Scans common lockfiles across multiple ecosystems
# - Runs osv-scanner and renders a custom table with OSV URL and GHSA/CVE mapping
# - Computes CVSS base scores from OSV vectors (prefers v4, falls back to v3)
# - Flags heuristic indicators for RCE and unauthenticated issues
# - Labels npm/PyPI dependencies as Direct or Transitive (best-effort)
# - Blocks execution if malware is detected
# - Blocks execution if any critical vulnerabilities are detected
# - Otherwise warns on non-critical vulnerabilities and allows execution
# - If no command is provided, performs scan-only and exits
# =============================================

echo "=== OSV Universal Proactive Guard ==="

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    cat <<'EOF'
Usage: safe-run.sh [command...]

Scans project lockfiles with osv-scanner and blocks execution if malware
or critical vulnerabilities are found. If a command is provided, it runs
only after the scan passes.

Options:
  -h, --help  Show this help message

Examples:
  ./safe-run.sh                 # scan only
  ./safe-run.sh npm start        # scan then run
  ./safe-run.sh ./app --flag     # scan then run
EOF
    exit 0
fi

# Common lockfiles across all major ecosystems
LOCKFILES=(
    "package-lock.json" "pnpm-lock.yaml" "yarn.lock" "bun.lockb"
    "requirements.txt" "poetry.lock" "Pipfile.lock" "uv.lock"
    "Cargo.lock" "go.mod"
    "pom.xml" "build.gradle" "build.gradle.kts"
    "Gemfile.lock" "composer.lock"
    "pubspec.lock" "mix.lock"
)

MANIFESTS=("package.json" "pyproject.toml")

# Build scan arguments
SCAN_ARGS=()
FOUND=false

for lf in "${LOCKFILES[@]}"; do
    if [ -f "$lf" ]; then
        SCAN_ARGS+=("--lockfile=$lf")
        FOUND=true
        echo "✓ Found lockfile: $lf"
    fi
done

if [ "$FOUND" = false ]; then
    FOUND_MANIFEST=false
    for mf in "${MANIFESTS[@]}"; do
        if [ -f "$mf" ]; then
            FOUND_MANIFEST=true
            echo "ℹ️  Found manifest: $mf"
        fi
    done
    if [ "$FOUND_MANIFEST" = true ]; then
        echo "❌ No supported lockfiles found. Run your package manager install to generate lockfiles."
    else
        echo "❌ No supported lockfiles found. Run your package manager install first."
    fi
    exit 1
fi

# Get JSON for accurate analysis
JSON_OUTPUT=$(osv-scanner "${SCAN_ARGS[@]}" --format json 2>/dev/null)
if [ -z "$JSON_OUTPUT" ]; then
    echo "❌ osv-scanner returned no JSON output. Please verify osv-scanner is working."
    exit 1
fi

JSON_FILE=$(mktemp)
printf '%s' "$JSON_OUTPUT" > "$JSON_FILE"
trap 'rm -f "$JSON_FILE"' EXIT

if ! command -v jq >/dev/null 2>&1; then
    echo "❌ jq is required to render the vulnerability table."
    echo "   Please install jq and re-run."
    exit 1
fi

# Show clean scan results (custom table with GHSA->CVE mapping and heuristic flags)
echo ""
echo "📋 Vulnerability Scan Results:"
python3 - "$JSON_FILE" <<'PY'
import json
import os
import re
import shutil
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)

header = ["OSV URL", "GHSA", "CVE", "ECOSYSTEM", "PACKAGE", "VERSION", "DEP_TYPE", "SEVERITY", "RCE?", "UNAUTH?"]
rows = []
missing_cvss = False

try:
    from cvss import CVSS3  # type: ignore
except Exception:
    CVSS3 = None
try:
    from cvss import CVSS4  # type: ignore
except Exception:
    CVSS4 = None

def as_str(v):
    return v if isinstance(v, str) else "-"

def trunc(s, w):
    if w <= 0:
        return ""
    if len(s) <= w:
        return s
    if w == 1:
        return "…"
    return s[: w - 1] + "…"

def load_npm_direct():
    path = os.path.join(os.getcwd(), "package.json")
    if not os.path.isfile(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return set()
    direct = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(key) or {}
        if isinstance(deps, dict):
            direct.update(deps.keys())
    return set(direct)

def normalize_pypi(name):
    return re.sub(r"[-_.]+", "-", name.strip().lower())

def load_pypi_direct():
    direct = set()
    req_path = os.path.join(os.getcwd(), "requirements.txt")
    if os.path.isfile(req_path):
        try:
            with open(req_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith(("-", "--")):
                        continue
                    name = re.split(r"[<>=!~\[\];\s]", line, 1)[0]
                    if name:
                        direct.add(normalize_pypi(name))
        except Exception:
            pass
    pyproject_path = os.path.join(os.getcwd(), "pyproject.toml")
    if os.path.isfile(pyproject_path):
        try:
            import tomllib  # Python 3.11+
            with open(pyproject_path, "rb") as f:
                data = tomllib.load(f)
            project = data.get("project") or {}
            deps = project.get("dependencies") or []
            if isinstance(deps, list):
                for dep in deps:
                    name = re.split(r"[<>=!~\[\];\s]", dep, 1)[0]
                    if name:
                        direct.add(normalize_pypi(name))
            opt = project.get("optional-dependencies") or {}
            if isinstance(opt, dict):
                for _, dep_list in opt.items():
                    if isinstance(dep_list, list):
                        for dep in dep_list:
                            name = re.split(r"[<>=!~\[\];\s]", dep, 1)[0]
                            if name:
                                direct.add(normalize_pypi(name))
        except Exception:
            pass
    return direct

npm_direct = load_npm_direct()
pypi_direct = load_pypi_direct()

def rce_unauth_flags(summary, details):
    text = f"{summary} {details}".lower()
    rce_keywords = [
        "remote code execution",
        " rce ",
    ]
    unauth_keywords = [
        "unauthenticated",
        "without authentication",
        "no authentication",
    ]
    rce = any(k in text for k in rce_keywords)
    unauth = any(k in text for k in unauth_keywords)
    return ("Y" if rce else "N", "Y" if unauth else "N")

def score_from_vector(vec, stype):
    global missing_cvss
    if vec.startswith("CVSS:4."):
        if CVSS4 is None:
            missing_cvss = True
            return None
        try:
            return float(getattr(CVSS4(vec), "base_score", None))
        except Exception:
            return None
    if vec.startswith("CVSS:3."):
        if CVSS3 is None:
            missing_cvss = True
            return None
        try:
            return float(getattr(CVSS3(vec), "base_score", None))
        except Exception:
            return None
    return None

def best_severity_score(sev_list):
    v4_scores = []
    v3_scores = []
    other_scores = []
    for s in sev_list:
        if not isinstance(s, dict):
            continue
        stype = str(s.get("type", "") or "")
        raw = str(s.get("score", "") or "")
        val = None
        if re.fullmatch(r"\d+(\.\d+)?", raw):
            val = float(raw)
        elif raw.startswith("CVSS:"):
            val = score_from_vector(raw, stype)
        if val is None:
            continue
        if "V4" in stype:
            v4_scores.append(val)
        elif "V3" in stype:
            v3_scores.append(val)
        else:
            other_scores.append(val)
    if v4_scores:
        return max(v4_scores)
    if v3_scores:
        return max(v3_scores)
    if other_scores:
        return max(other_scores)
    return None

for res in data.get("results", []) or []:
    for pkg in res.get("packages", []) or []:
        p = pkg.get("package", {}) or {}
        ecosystem = as_str(p.get("ecosystem"))
        name = as_str(p.get("name"))
        version = as_str(p.get("version"))
        for v in pkg.get("vulnerabilities", []) or []:
            vid = as_str(v.get("id"))
            osv_url = f"https://osv.dev/{vid}" if vid != "-" else "-"
            aliases = set(v.get("aliases") or [])
            if vid.startswith("GHSA-"):
                aliases.add(vid)
            if vid.startswith("CVE-"):
                aliases.add(vid)
            ghsa = ",".join(sorted(a for a in aliases if a.startswith("GHSA-"))) or "-"
            cve = ",".join(sorted(a for a in aliases if a.startswith("CVE-"))) or "-"
            sev = v.get("severity") or []
            sev_val = best_severity_score(sev)
            sev_str = f"{sev_val:.1f}".rstrip("0").rstrip(".") if sev_val is not None else ""
            if not sev_str:
                sev_str = as_str((v.get("database_specific") or {}).get("severity")) or "-"
            summary = as_str(v.get("summary", ""))
            details = as_str(v.get("details", ""))
            if ecosystem.lower() == "npm":
                dep_type = "Direct" if name in npm_direct else "Transitive"
            elif ecosystem.lower() == "pypi":
                dep_type = "Direct" if normalize_pypi(name) in pypi_direct else "Transitive"
            else:
                dep_type = "-"
            rce, unauth = rce_unauth_flags(summary, details)
            rows.append([osv_url, ghsa, cve, ecosystem, name, version, dep_type, sev_str, rce, unauth])

cols = len(header)
max_widths = [45, 32, 32, 10, 32, 12, 11, 10, 6, 7]
widths = [len(h) for h in header]

for row in rows:
    for i in range(cols):
        widths[i] = min(max_widths[i], max(widths[i], len(row[i])))

term_width = shutil.get_terminal_size((120, 20)).columns
total = sum(w + 2 for w in widths) + (cols - 1)
if total > term_width:
    overflow = total - term_width
    order = [0, 4, 1, 2, 6, 7, 3, 5, 8, 9]
    i = 0
    while overflow > 0 and i < 10000:
        col = order[i % len(order)]
        if widths[col] > 8:
            widths[col] -= 1
            overflow -= 1
        i += 1

def hline(left, mid, right):
    parts = [left]
    for i, w in enumerate(widths):
        parts.append("─" * (w + 2))
        parts.append(right if i == cols - 1 else mid)
    return "".join(parts)

def row_line(items):
    out = ["│"]
    for i, w in enumerate(widths):
        out.append(" " + trunc(items[i], w).ljust(w) + " ")
        out.append("│")
    return "".join(out)

if not rows:
    print("No vulnerabilities found.")
    sys.exit(0)

print(hline("╭", "┬", "╮"))
print(row_line(header))
print(hline("├", "┼", "┤"))
for r in rows:
    print(row_line(r))
print(hline("╰", "┴", "╯"))
if missing_cvss:
    print("Note: CVSS vectors detected but no CVSS library available for scoring.")
    print("Install the Python package 'cvss' to compute CVSS v3 and v4 base scores.")
PY
echo ""

# === Accurate counting and classification ===
VULN_COUNT=$(echo "$JSON_OUTPUT" | jq '[.results[]?.packages[]?.vulnerabilities[]?] | length')
MALWARE_COUNT=$(echo "$JSON_OUTPUT" | jq '[.results[]?.packages[]?.vulnerabilities[]? | select(.id? | startswith("MAL-"))] | length')
CRITICAL_COUNT=$(echo "$JSON_OUTPUT" | jq '[.results[]?.packages[]?.vulnerabilities[]? | select((.database_specific?.severity? // "") == "CRITICAL")] | length')

HAS_MALWARE=$([ "$MALWARE_COUNT" -gt 0 ] && echo true || echo false)
HAS_CRITICAL=$([ "$CRITICAL_COUNT" -gt 0 ] && echo true || echo false)

# === Decision logic ===
if [ "$HAS_MALWARE" = true ]; then
    echo "🚨 MALWARE DETECTED! ($MALWARE_COUNT malicious package(s))"
    echo "   Blocking application startup for safety."
    exit 1

elif [ "$HAS_CRITICAL" = true ]; then
    echo "🚨 CRITICAL VULNERABILITY DETECTED! ($CRITICAL_COUNT critical issue(s))"
    echo "   Blocking application startup. Please fix critical vulnerabilities first."
    exit 1

elif [ "$VULN_COUNT" -gt 0 ]; then
    echo "⚠️  $VULN_COUNT vulnerabilities found (no malware, no critical severity)."
    if [ "$#" -gt 0 ]; then
        echo "   The application will still start."
    else
        echo "   Scan-only mode: no command will be executed."
    fi
    echo "   Recommendation: Update the affected packages as soon as possible."
else
    echo "✅ No vulnerabilities or malware found."
fi

echo ""
if [ "$#" -gt 0 ]; then
    echo "✅ OSV check passed. Proceeding to start your application..."
    exec "$@"
else
    echo "✅ OSV check passed. No command provided."
fi

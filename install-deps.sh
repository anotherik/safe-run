#!/bin/bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ python3 is required to install cvss."
    exit 1
fi

OS_CHOICE=""
echo "Select your OS for dependency installation:"
select opt in "macOS (Homebrew)" "Ubuntu/Debian (apt)" "Fedora (dnf)" "Arch (pacman)" "Manual"; do
    case "$REPLY" in
        1) OS_CHOICE="brew"; break ;;
        2) OS_CHOICE="apt"; break ;;
        3) OS_CHOICE="dnf"; break ;;
        4) OS_CHOICE="pacman"; break ;;
        5) OS_CHOICE="manual"; break ;;
        *) echo "Invalid selection." ;;
    esac
done

install_osv_scanner() {
    if command -v osv-scanner >/dev/null 2>&1; then
        return 0
    fi

    case "$OS_CHOICE" in
        brew)
            brew install osv-scanner || {
                echo "❌ Failed to install osv-scanner with Homebrew."
                echo "   Try running as root if required."
                return 1
            }
            ;;
        apt)
            apt-get update -y || { echo "❌ apt-get failed. Try running as root."; return 1; }
            apt-get install -y curl || { echo "❌ apt-get failed. Try running as root."; return 1; }
            curl -L -o osv-scanner https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64
            chmod +x osv-scanner
            mv osv-scanner /usr/local/bin/ || {
                echo "❌ Could not move osv-scanner to /usr/local/bin."
                echo "   Try running as root."
                return 1
            }
            ;;
        dnf)
            dnf install -y curl || { echo "❌ dnf failed. Try running as root."; return 1; }
            curl -L -o osv-scanner https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64
            chmod +x osv-scanner
            mv osv-scanner /usr/local/bin/ || {
                echo "❌ Could not move osv-scanner to /usr/local/bin."
                echo "   Try running as root."
                return 1
            }
            ;;
        pacman)
            pacman -Sy --noconfirm curl || { echo "❌ pacman failed. Try running as root."; return 1; }
            curl -L -o osv-scanner https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64
            chmod +x osv-scanner
            mv osv-scanner /usr/local/bin/ || {
                echo "❌ Could not move osv-scanner to /usr/local/bin."
                echo "   Try running as root."
                return 1
            }
            ;;
        manual)
            echo "ℹ️  Please install osv-scanner manually:"
            echo "   https://github.com/google/osv-scanner"
            return 1
            ;;
    esac
}

install_jq() {
    if command -v jq >/dev/null 2>&1; then
        return 0
    fi

    case "$OS_CHOICE" in
        brew)
            brew install jq || { echo "❌ Failed to install jq with Homebrew. Try running as root."; return 1; }
            ;;
        apt)
            apt-get update -y || { echo "❌ apt-get failed. Try running as root."; return 1; }
            apt-get install -y jq || { echo "❌ apt-get failed. Try running as root."; return 1; }
            ;;
        dnf)
            dnf install -y jq || { echo "❌ dnf failed. Try running as root."; return 1; }
            ;;
        pacman)
            pacman -Sy --noconfirm jq || { echo "❌ pacman failed. Try running as root."; return 1; }
            ;;
        manual)
            echo "ℹ️  Please install jq manually:"
            echo "   https://stedolan.github.io/jq/"
            return 1
            ;;
    esac
}

install_cvss() {
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
    fi
    . .venv/bin/activate
    python3 -m pip install --upgrade pip
    python3 -m pip install cvss
    deactivate
}

echo "Installing dependencies for safe-run..."
install_osv_scanner
install_jq
install_cvss

echo "✅ Dependencies installed."

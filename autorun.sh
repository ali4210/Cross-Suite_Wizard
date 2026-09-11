#!/usr/bin/env bash

# ==============================================================================
# CROSS-SUITE PORTABLE BOOTSTRAPPER & MULTI-COMPILER LAUNCHER
# Universal Multi-Distro Linux, BSD & macOS Autonomy
# ==============================================================================

set -e

# 1. DETERMINE SCRIPT LOCATION & HOST ARCHITECTURE
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

OS_TYPE="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_TYPE="$(uname -m)"

case "$ARCH_TYPE" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l|armv6l) ARCH="arm" ;;
    i386|i686)     ARCH="386" ;;
    *)             ARCH="amd64" ;;
esac

# 2. PERMISSION AUDIT
chmod +x autorun.sh 2>/dev/null || true
find . -maxdepth 2 -type f \( -name "*.sh" -o -name "*.bash" -o -name "*.py" -o -name "Cross-Suite_Wizard*" \) -exec chmod +x {} + 2>/dev/null || true

# 3. ENVIRONMENT PATH RESOLUTION
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin:/usr/bin:/usr/local/bin:/opt/homebrew/bin:/usr/local/opt/go/bin

# 3b. SELF-HEALING GO CACHE OWNERSHIP GUARD
fix_go_cache_ownership() {
    local real_user="${SUDO_USER:-$USER}"
    [ "$real_user" = "root" ] && return 0
    [ -z "$real_user" ] && return 0

    local real_home
    real_home=$(getent passwd "$real_user" 2>/dev/null | cut -d: -f6)
    [ -z "$real_home" ] && real_home="$HOME"

    local cache_dir="$real_home/.cache/go-build"
    local mod_dir="$real_home/go"

    for d in "$cache_dir" "$mod_dir"; do
        [ -d "$d" ] || continue
        if find "$d" -maxdepth 1 -not -user "$real_user" 2>/dev/null | grep -q .; then
            echo "==>> [!] Detected foreign-owned Go cache files in $d — auto-repairing ownership..."
            if [ "$(id -u)" -eq 0 ]; then
                chown -R "$real_user:$real_user" "$d" 2>/dev/null || true
            else
                sudo chown -R "$real_user:$real_user" "$d" 2>/dev/null || true
            fi
        fi
    done
}
fix_go_cache_ownership

# 4. FUNCTION: Fallback Manual Go Toolchain Installer
install_go_manual() {
    echo "==>> Downloading official standalone Go runtime..."
    GO_VERSION="1.22.5"
    local GO_OS="$OS_TYPE"
    local GO_ARCH="$ARCH"
    local TARBALL=""

    if [ "$GO_OS" = "darwin" ]; then
        TARBALL="go${GO_VERSION}.darwin-${GO_ARCH}.tar.gz"
    else
        TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
    fi

    local URL="https://go.dev/dl/${TARBALL}"

    if command -v curl >/dev/null 2>&1; then
        curl -sL "$URL" -o /tmp/go.tar.gz
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$URL" -O /tmp/go.tar.gz
    else
        echo "==>> [!] Neither curl nor wget found. Please install Go from https://go.dev/dl/"
        exit 1
    fi

    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc 2>/dev/null || true
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc 2>/dev/null || true
    echo "==>> Go ${GO_VERSION} deployed to /usr/local/go"
}

# 5. AUTOMATED DEPENDENCY & GO COMPILER BOOTSTRAP
if ! command -v go >/dev/null 2>&1; then
    echo "==>> [!] Go compiler missing. Initializing automated installation..."
    if [ "$OS_TYPE" = "darwin" ]; then
        if command -v brew >/dev/null 2>&1; then
            brew install go curl || install_go_manual
        else
            install_go_manual
        fi
    elif command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq golang-go curl 2>/dev/null || sudo apt-get install -y -qq golang curl || install_go_manual
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y -q golang curl 2>/dev/null || install_go_manual
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y -q golang curl 2>/dev/null || install_go_manual
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm go curl 2>/dev/null || install_go_manual
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper --non-interactive install go curl 2>/dev/null || install_go_manual
    elif command -v apk >/dev/null 2>&1; then
        sudo apk add go curl 2>/dev/null || install_go_manual
    else
        install_go_manual
    fi
fi

# 6. CLI FLAG PARSER
BUILD_ALL=false
FORCE_BUILD=false
HARD_PURGE=false

for arg in "$@"; do
    case "$arg" in
        --all|-a|all|cross)
            BUILD_ALL=true
            ;;
        --hard|-H)
            HARD_PURGE=true
            FORCE_BUILD=true
            ;;
        --build|-b|-f|--force)
            FORCE_BUILD=true
            ;;
    esac
done

# 7. MULTI-PLATFORM CROSS-COMPILATION ENGINE
if [ "$BUILD_ALL" = true ]; then
    echo "==>> Initializing full universal multi-platform build..."
    mkdir -p dist

    echo "[+] Compiling Linux (x86_64 amd64)..."
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/Cross-Suite_Wizard-linux-amd64 .

    echo "[+] Compiling Linux (ARM64)..."
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dist/Cross-Suite_Wizard-linux-arm64 .

    echo "[+] Compiling macOS (Intel amd64)..."
    CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o dist/Cross-Suite_Wizard-darwin-amd64 .

    echo "[+] Compiling macOS (Apple Silicon arm64)..."
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o dist/Cross-Suite_Wizard-darwin-arm64 .

    echo "[+] Compiling Windows (x86_64 .exe)..."
    if [ -f cross-ssh.exe.manifest ]; then
        command -v rsrc >/dev/null 2>&1 || go install github.com/akavel/rsrc@latest 2>/dev/null || true
        rsrc -manifest cross-ssh.exe.manifest -o cross-ssh.syso 2>/dev/null || true
    fi
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/Cross-Suite_Wizard-windows-amd64.exe .
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o Cross-Suite_Wizard.exe .
    rm -f cross-ssh.syso

    chmod +x dist/* Cross-Suite_Wizard.exe 2>/dev/null || true
    echo "==>> Universal binaries ready in ./dist/"
    exit 0
fi

# 8. NATIVE HOST AUTO-RECOMPILE PIPELINE
TARGET_BIN="./Cross-Suite_Wizard"

NEEDS_REBUILD=false
if [ ! -f "$TARGET_BIN" ] || [ "$FORCE_BUILD" = true ]; then
    NEEDS_REBUILD=true
else
    if find . -maxdepth 3 -name "*.go" -newer "$TARGET_BIN" 2>/dev/null | grep -q .; then
        echo "==>> Code modification detected! Triggering fast auto-recompile..."
        NEEDS_REBUILD=true
    fi
fi

if [ "$NEEDS_REBUILD" = true ]; then
    if [ "$HARD_PURGE" = true ]; then
        echo "[+] Purging module and build cache..."
        go clean -cache -modcache 2>/dev/null || true
        go mod download 2>/dev/null || true
        go mod tidy 2>/dev/null || true
    fi

    echo "[+] Fast compiling Cross-Suite_Wizard (OS: $OS_TYPE, ARCH: $ARCH)..."
    BUILD_LOG=$(mktemp)
    if ! CGO_ENABLED=0 GOOS=$OS_TYPE GOARCH=$ARCH go build -ldflags="-s -w" -o "$TARGET_BIN" . 2>"$BUILD_LOG"; then
        if grep -qi "permission denied" "$BUILD_LOG"; then
            echo "==>> [!] Build failed due to a cache permission conflict. Repairing and retrying once..."
            fix_go_cache_ownership
            if ! CGO_ENABLED=0 GOOS=$OS_TYPE GOARCH=$ARCH go build -ldflags="-s -w" -o "$TARGET_BIN" . 2>"$BUILD_LOG"; then
                echo "==>> [!] Build still failing after cache repair:"
                cat "$BUILD_LOG"
                rm -f "$BUILD_LOG"
                exit 1
            fi
        else
            echo "==>> [!] Build failed:"
            cat "$BUILD_LOG"
            rm -f "$BUILD_LOG"
            exit 1
        fi
    fi
    rm -f "$BUILD_LOG"
    chmod +x "$TARGET_BIN"
fi

# 9. EXECUTION
export TERM=${TERM:-xterm-256color}
echo "==>> Launching Cross-Suite Platform ($TARGET_BIN)..."
exec "$TARGET_BIN" "$@"
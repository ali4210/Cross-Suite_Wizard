#!/usr/bin/env bash
set -e

# Universal Cross-SSH Installer
REPO="yourusername/cross-ssh"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="cross-ssh"

echo "=== Universal Cross-SSH Installer ==="

# 1. Detect Architecture & OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux) TARGET="linux-$ARCH" ;;
    darwin) TARGET="mac-$ARCH" ;;
    *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

echo "Detected System: OS=$OS | Arch=$ARCH"

# 2. Download Latest Binary from GitHub Releases
DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/cross-ssh-${TARGET}"

echo "Downloading ${BINARY_NAME}..."
curl -fsSL "$DOWNLOAD_URL" -o "/tmp/${BINARY_NAME}"
chmod +x "/tmp/${BINARY_NAME}"

# 3. Install to System Path
echo "Installing to ${INSTALL_DIR}..."
if [ -w "$INSTALL_DIR" ]; then
    mv "/tmp/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
else
    sudo mv "/tmp/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
fi

echo "Success! Installation complete."
echo "Run 'cross-ssh -help' to get started."

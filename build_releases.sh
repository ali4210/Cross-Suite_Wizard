#!/usr/bin/env bash
set -e

echo "Building production binaries for all operating systems..."
mkdir -p dist

# Linux
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/cross-ssh-linux-amd64 main.go
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o dist/cross-ssh-linux-arm64 main.go

# macOS
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o dist/cross-ssh-mac-amd64 main.go
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o dist/cross-ssh-mac-arm64 main.go

# Windows
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/cross-ssh-windows-amd64.exe main.go

# Local Binary
go build -ldflags="-s -w" -o cross-ssh main.go

# Grant Executable Rights Automatically
chmod +x cross-ssh dist/*

echo "All production binaries compiled and permissions set successfully!"
ls -lh cross-ssh dist/

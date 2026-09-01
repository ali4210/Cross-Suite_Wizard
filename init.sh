#!/usr/bin/env bash
set -e

echo "=========================================================="
echo "          CROSS-SSH ONE-CLICK REPO INITIALIZER            "
echo "=========================================================="

# 1. Automatically grant execution permissions across all repo scripts
echo "[1/5] Granting executable permissions to all workspace scripts..."
chmod +x *.sh 2>/dev/null || true

# 2. Sync dependencies
echo "[2/5] Verifying and tidying Go dependencies..."
go mod tidy

# 3. Build All Production Binaries
echo "[3/5] Compiling cross-platform binaries..."
make build

# 4. Configure Git Repo & Hooks
echo "[4/5] Initializing Git repository structure..."
if [ ! -d ".git" ]; then
    git init
    git branch -M main
fi

# 5. Create Pre-Commit Hook to Prevent Broken Builds
echo "[5/5] Installing pre-commit verification hook..."
cat << 'HOOK' > .git/hooks/pre-commit
#!/usr/bin/env bash
echo "=> Auto-verifying build before commit..."
make dev
if [ $? -ne 0 ]; then
    echo "[!] Build failed. Fix compiler errors before committing."
    exit 1
fi
HOOK
chmod +x .git/hooks/pre-commit

echo "----------------------------------------------------------"
echo "[SUCCESS] Repository initialization complete!"
echo "=> All shell scripts and binaries now have full execution permissions."
echo "=> To run locally:         ./cross-ssh"
echo "=> To rebuild everything:  make"
echo "=> To install globally:    make install"
echo "----------------------------------------------------------"
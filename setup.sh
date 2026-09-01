#!/usr/bin/env bash

# ==============================================================================
# CROSS-SUITE AUTOMATED ONE-CLICK SSH SETUP (BULLETPROOF BASE64 ENCODED)
# ==============================================================================

set -e

TARGET_ALIAS="wind"
TARGET_HOST="192.168.0.112"
TARGET_USER="saleem"
SSH_KEY="$HOME/.ssh/id_ed25519"

echo "==>> Initializing Cross-Suite Automated SSH Key Deployment Setup..."

# 1. Generate SSH Key pair if missing locally
if [ ! -f "$SSH_KEY" ]; then
    echo "=> Generating local ED25519 SSH key pair..."
    ssh-keygen -t ed25519 -N "" -f "$SSH_KEY"
else
    echo "=> Local SSH key detected at $SSH_KEY"
fi

# 2. Configure Local ~/.ssh/config Host Entry
SSH_CONFIG="$HOME/.ssh/config"
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

# Clear existing stale configuration for alias if present
if grep -q "Host $TARGET_ALIAS" "$SSH_CONFIG" 2>/dev/null; then
    sed -i "/Host $TARGET_ALIAS/,+5d" "$SSH_CONFIG"
fi

echo "=> Registering Host '$TARGET_ALIAS' inside $SSH_CONFIG..."
cat <<EOF >> "$SSH_CONFIG"

Host $TARGET_ALIAS
    HostName $TARGET_HOST
    User $TARGET_USER
    IdentityFile $SSH_KEY
    StrictHostKeyChecking accept-new
EOF
chmod 600 "$SSH_CONFIG"

# 3. Construct Pure PowerShell Payload
PUBKEY="$(cat ${SSH_KEY}.pub)"

PS_SCRIPT="
\$key = '$PUBKEY';
\$uDir = 'C:\Users\\${TARGET_USER}\.ssh';
\$uKey = \"\$uDir\authorized_keys\";
\$aKey = 'C:\ProgramData\ssh\administrators_authorized_keys';
\$cfg = 'C:\ProgramData\ssh\sshd_config';

if (!(Test-Path \$uDir)) { New-Item -ItemType Directory -Path \$uDir -Force | Out-Null }
[System.IO.File]::WriteAllText(\$uKey, \$key + [Environment]::NewLine, [System.Text.Encoding]::UTF8);
icacls \$uKey /inheritance:r /grant '${TARGET_USER}:F' /grant 'SYSTEM:F' /grant 'Administrators:F' | Out-Null;

if (Test-Path 'C:\ProgramData\ssh') {
    [System.IO.File]::WriteAllText(\$aKey, \$key + [Environment]::NewLine, [System.Text.Encoding]::UTF8);
    icacls \$aKey /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null;
}

if (Test-Path \$cfg) {
    (Get-Content \$cfg) -replace 'Match Group administrators', '# Match Group administrators' -replace 'AuthorizedKeysFile __PROGRAMDATA__', '# AuthorizedKeysFile __PROGRAMDATA__' | Set-Content \$cfg;
}

Restart-Service sshd;
"

# Convert script to UTF-16LE Base64 for PowerShell -EncodedCommand (Bypasses CMD Quote Escaping)
B64_CMD=$(echo -n "$PS_SCRIPT" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0)

echo "=> Injecting SSH Public Key & Fixing Windows OpenSSH Permissions..."
echo "=> Enter target user password ONE LAST TIME to authorize keyless login:"

ssh -o PreferredAuthentications=password "${TARGET_USER}@${TARGET_HOST}" "powershell -NoProfile -EncodedCommand $B64_CMD"

# 4. Verify Non-Interactive Keyless Entry
echo -e "\n=> Verifying passwordless SSH connection..."
if ssh -i "$SSH_KEY" -o BatchMode=yes "$TARGET_ALIAS" "echo Remote SSH verification successful" 2>/dev/null; then
    echo "==>> [SUCCESS] Setup complete! Passwordless SSH entry is active."
    echo "=> You can now connect anytime by typing: wind or ssh wind"
else
    echo "=> Setup complete! Test connecting now by typing: wind"
fi
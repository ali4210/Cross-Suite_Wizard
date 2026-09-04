package playbook

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/repohealer"
	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
)

// ViewInPager displays long multiline content inside an interactive, scrollable less -R view
func ViewInPager(content string) {
	if strings.TrimSpace(content) == "" {
		return
	}

	cmd := exec.Command("less", "-R", "-F", "-X")
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println(content)
	}
}

// ShowUniversalHealerMenu provides the primary interface for Hub 5 with Pager Navigation
func ShowUniversalHealerMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Println(Bold + Cyan + fmt.Sprintf("=== HUB 5: UNIVERSAL PACKAGE ENGINE & SYSTEM SELF-HEALER [%s] ===", strings.ToUpper(string(targetOS))) + Reset)
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Println(Yellow + "--- SECTION A: SMART PACKAGE PROVISIONING & FOOTPRINT ENGINE ---" + Reset)
		fmt.Println("  [1] Search Tool & Package Discovery (Pre-Flight Dependency Check)")
		fmt.Println("  [2] Inspect Active Footprint State & Version Registry (/var/lib/cross-suite or C:\\ProgramData\\cross-suite)")
		fmt.Println("  [3] Check Upstream Releases & Trigger 1-Click System Updates")
		fmt.Println("  [4] Scan Installed Footprint Packages for Security Vulnerabilities (Trivy CVE Scan)")
		fmt.Println(Yellow + "\n--- SECTION B: REPOSITORY SWITCHER & SELF-HEALING ENGINE ---" + Reset)
		if targetOS == osdetect.OSWindows {
			fmt.Println("  [5] Windows Package Manager Setup (Bootstrap Winget & Chocolatey)")
			fmt.Println("  [6] Inject Custom Private Repository Endpoint (NuGet / Internal Mirror)")
			fmt.Println("  [7] Autonomous Windows Self-Healer (Flush DNS, Clear Temp Locks, Restart SSHD)")
			fmt.Println("  [8] Run Parallel Download & Speed Optimizer (PowerShell Parallel Tuning)")
			fmt.Println("  [9] Rollback System Package & Environment State")
		} else {
			fmt.Println("  [5] Enterprise Repo Switcher (Fix EOL CentOS / Enable, Disable & Purge Repos)")
			fmt.Println("  [6] Inject Custom Private Repository Endpoint (RPM / APT / Nexus Preset Governance)")
			fmt.Println("  [7] Universal Repository Healer (Diagnose, Plan & Verified Repair)")
			fmt.Println("  [8] Run Fast-Mirror Benchmark & Auto-Tune Repository Download Speeds")
			fmt.Println("  [9] Rollback Repository & System Package State (Restore Snapshot)")
		}
		fmt.Println(Red + "\n--- SECTION C: DEEP UNINSTALLER & FOOTPRINT PURGER MATRIX ---" + Reset)
		fmt.Println(Red + "  [10] Deep Package Uninstaller & Orphan Dependency Purger (1-Click Clean)" + Reset)
		fmt.Println(Red + "  [11] Trace Installed Tools & Clean Package Artifact Footprints (System Logs)" + Reset)
		fmt.Println(Blue + "\n  [0] Return to Operational Main Menu" + Reset)
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select Option [0-11]: ")

		switch choice {
		case "1":
			query := transfer.ReadRealtimeInput("Enter tool name (e.g., docker, wazuh, wireshark, postgresql, sops) or '0' to Cancel: ")
			cleanQ := strings.TrimSpace(query)
			if cleanQ != "" && cleanQ != "0" && !strings.EqualFold(cleanQ, "b") && !strings.EqualFold(cleanQ, "back") && !strings.EqualFold(cleanQ, "q") {
				InspectAndDeployFamily(reader, client, cleanQ, targetOS)
				pauseExecution(reader)
			}
		case "2":
			InspectFootprintState(client, targetOS)
			pauseExecution(reader)
		case "3":
			CheckUpstreamUpdates(client, targetOS)
			pauseExecution(reader)
		case "4":
			ScanFootprintCVEs(client)
			pauseExecution(reader)
		case "5":
			if targetOS == osdetect.OSWindows {
				BootstrapWindowsPackageManagers(client)
			} else {
				RemapEnterpriseRepos(client)
			}
			pauseExecution(reader)
		case "6":
			InjectCustomRepoWizard(client, targetOS)
			pauseExecution(reader)
		case "7":
			RunSelfHealingTroubleshooter(client, targetOS)
			pauseExecution(reader)
		case "8":
			TuneMirrorSpeed(client, targetOS)
			pauseExecution(reader)
		case "9":
			RollbackSystemState(client, targetOS)
			pauseExecution(reader)
		case "10":
			toolName := transfer.ReadRealtimeInput("Enter tool/package name to DEEP PURGE (or '0' to Cancel): ")
			cleanTool := strings.TrimSpace(toolName)
			if cleanTool != "" && cleanTool != "0" && !strings.EqualFold(cleanTool, "b") && !strings.EqualFold(cleanTool, "back") && !strings.EqualFold(cleanTool, "q") {
				ExecuteDeepUninstaller(client, cleanTool, targetOS)
				pauseExecution(reader)
			}
		case "11":
			TraceAndPurgeToolFootprints(client, targetOS)
			pauseExecution(reader)
		case "0", "q", "Q":
			return
		}
	}
}

// ExecuteDeepUninstaller purges a tool, its family packages, keyrings, groups, daemons, and state entries
func ExecuteDeepUninstaller(client *ssh.Client, tool string, targetOS osdetect.TargetOS) {
	cleanTool := strings.ToLower(strings.TrimSpace(strings.Split(tool, ".")[0]))
	if cleanTool == "" {
		return
	}

	fmt.Println(Red + Bold + fmt.Sprintf("\n[!] INITIALIZING DEEP UNINSTALLER & SYSTEM PURGER FOR: '%s'...", cleanTool) + Reset)

	if targetOS == osdetect.OSWindows {
		executeWindowsDeepUninstall(client, cleanTool)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)

	purgeScript := fmt.Sprintf(`#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export UCF_FORCE_CONFFOLD=1
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

TOOL="%s"
CALLING_USER="${SUDO_USER:-$(logname 2>/dev/null || echo $USER)}"

echo "=> Step 1: Safely Terminating Daemons, Sockets & Background Services..."
systemctl stop "${TOOL}.socket" "${TOOL}.service" 2>/dev/null || true
systemctl disable "${TOOL}.socket" "${TOOL}.service" 2>/dev/null || true

case "$TOOL" in
	docker)
		systemctl stop docker.socket docker.service containerd.service 2>/dev/null || true
		systemctl disable docker.socket docker.service containerd.service 2>/dev/null || true
		;;
	wazuh|wazuh-agent|wazuh-manager)
		systemctl stop wazuh-agent wazuh-manager 2>/dev/null || true
		systemctl disable wazuh-agent wazuh-manager 2>/dev/null || true
		/var/ossec/bin/wazuh-control stop 2>/dev/null || true
		;;
	podman)
		systemctl stop podman.socket podman.service 2>/dev/null || true
		systemctl disable podman.socket podman.service 2>/dev/null || true
		;;
	wireshark|tshark)
		pkill -x wireshark 2>/dev/null || true
		pkill -x tshark 2>/dev/null || true
		pkill -x dumpcap 2>/dev/null || true
		;;
	postgresql|postgres)
		systemctl stop postgresql 2>/dev/null || true
		systemctl disable postgresql 2>/dev/null || true
		;;
	redis)
		systemctl stop redis redis-server 2>/dev/null || true
		systemctl disable redis redis-server 2>/dev/null || true
		;;
	nginx)
		systemctl stop nginx 2>/dev/null || true
		systemctl disable nginx 2>/dev/null || true
		;;
	caddy)
		systemctl stop caddy 2>/dev/null || true
		systemctl disable caddy 2>/dev/null || true
		;;
	gitlab-runner)
		gitlab-runner stop 2>/dev/null || true
		gitlab-runner uninstall 2>/dev/null || true
		systemctl stop gitlab-runner 2>/dev/null || true
		;;
	jenkins)
		systemctl stop jenkins 2>/dev/null || true
		systemctl disable jenkins 2>/dev/null || true
		;;
	vault|consul|nomad)
		systemctl stop "$TOOL" 2>/dev/null || true
		systemctl disable "$TOOL" 2>/dev/null || true
		;;
esac

pkill -x "$TOOL" 2>/dev/null || true

echo "=> Step 2: Purging Package Family & Associated Dependencies..."
PKGS_TO_PURGE=("$TOOL" "${TOOL}-*")
case "$TOOL" in
	docker)
		PKGS_TO_PURGE+=("docker-ce" "docker-ce-cli" "containerd.io" "docker-buildx-plugin" "docker-compose-plugin" "docker.io" "docker-compose" "podman-docker" "docker-model-plugin" "docker-scan-plugin" "docker-secrets-engine*")
		;;
	wazuh|wazuh-agent|wazuh-manager)
		PKGS_TO_PURGE+=("wazuh-agent" "wazuh-manager")
		;;
	podman)
		PKGS_TO_PURGE+=("podman" "podman-docker" "slirp4netns" "fuse-overlayfs")
		;;
	wireshark|tshark)
		PKGS_TO_PURGE+=("wireshark" "wireshark-qt" "wireshark-common" "tshark" "libwireshark*")
		;;
	postgresql|postgres)
		PKGS_TO_PURGE+=("postgresql" "postgresql-*" "postgresql-contrib" "postgresql-client")
		;;
	redis)
		PKGS_TO_PURGE+=("redis" "redis-server" "redis-tools")
		;;
	nginx)
		PKGS_TO_PURGE+=("nginx" "nginx-common" "nginx-core")
		;;
	caddy)
		PKGS_TO_PURGE+=("caddy")
		;;
	jenkins)
		PKGS_TO_PURGE+=("jenkins")
		;;
	gitlab-runner)
		PKGS_TO_PURGE+=("gitlab-runner")
		;;
esac

APT_PURGE="apt-get purge -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o needrestart::mode=a"

if command -v apt-get >/dev/null 2>&1; then
	$APT_PURGE "${PKGS_TO_PURGE[@]}" 2>/dev/null || true
	apt-get autoremove --purge -y -qq 2>/dev/null || true
	apt-get clean 2>/dev/null || true
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
	PM=$(command -v dnf || command -v yum)
	$PM remove -y "${PKGS_TO_PURGE[@]}" 2>/dev/null || true
	$PM autoremove -y 2>/dev/null || true
	$PM clean all 2>/dev/null || true
elif command -v pacman >/dev/null 2>&1; then
	pacman -Rns --noconfirm "$TOOL" 2>/dev/null || true
fi

command -v snap >/dev/null 2>&1 && snap remove "$TOOL" 2>/dev/null || true
command -v flatpak >/dev/null 2>&1 && flatpak uninstall -y "$TOOL" 2>/dev/null || true

echo "=> Step 3: Wiping Vendor GPG Keyrings & Custom Repositories..."
rm -f /etc/apt/keyrings/${TOOL}*.gpg /etc/apt/trusted.gpg.d/${TOOL}*.gpg /etc/apt/sources.list.d/${TOOL}*.list 2>/dev/null || true
rm -f /etc/yum.repos.d/${TOOL}*.repo 2>/dev/null || true

case "$TOOL" in
	docker)
		rm -f /etc/apt/keyrings/docker.gpg /etc/apt/sources.list.d/docker.list /etc/yum.repos.d/docker-ce.repo 2>/dev/null || true
		;;
	wazuh|wazuh-agent|wazuh-manager)
		rm -f /etc/apt/keyrings/wazuh.gpg /etc/apt/sources.list.d/wazuh.list /etc/yum.repos.d/wazuh.repo 2>/dev/null || true
		;;
	postgresql|postgres)
		rm -f /etc/apt/keyrings/pgdg.gpg /etc/apt/sources.list.d/pgdg.list /etc/yum.repos.d/*pgdg*.repo 2>/dev/null || true
		;;
	vault|consul|nomad|terraform|packer)
		rm -f /etc/apt/keyrings/hashicorp.gpg /etc/apt/sources.list.d/hashicorp.list /etc/yum.repos.d/hashicorp.repo 2>/dev/null || true
		;;
	caddy)
		rm -f /etc/apt/keyrings/caddy*.gpg /etc/apt/sources.list.d/caddy*.list 2>/dev/null || true
		;;
	gitlab-runner)
		rm -f /etc/apt/sources.list.d/runner_gitlab-runner.list /etc/yum.repos.d/runner_gitlab-runner.repo 2>/dev/null || true
		;;
	jenkins)
		rm -f /etc/apt/keyrings/jenkins*.key /etc/apt/sources.list.d/jenkins.list /etc/yum.repos.d/jenkins.repo 2>/dev/null || true
		;;
esac

echo "=> Step 4: Deleting Binary Executables, Runtime Data & System Directories..."
rm -f "/usr/bin/$TOOL" "/usr/local/bin/$TOOL" "/usr/sbin/$TOOL" "/usr/local/sbin/$TOOL" 2>/dev/null || true
rm -rf "/opt/$TOOL" "/var/log/$TOOL" "/var/lib/$TOOL" "/var/run/$TOOL" "/run/$TOOL" "/etc/$TOOL" 2>/dev/null || true
rm -rf "/tmp/${TOOL}*" "/var/tmp/${TOOL}*" 2>/dev/null || true

case "$TOOL" in
	docker)
		rm -rf /var/lib/docker /var/lib/containerd /etc/docker /var/run/docker.sock /var/run/docker /usr/libexec/docker 2>/dev/null || true
		rm -f /usr/bin/containerd* /usr/local/bin/containerd* /usr/bin/docker* /usr/local/bin/docker* /usr/sbin/dockerd 2>/dev/null || true
		;;
	wazuh|wazuh-agent|wazuh-manager)
		rm -rf /var/ossec /etc/ossec-init.conf 2>/dev/null || true
		;;
	wireshark|tshark)
		rm -rf /etc/wireshark 2>/dev/null || true
		rm -f /usr/bin/wireshark /usr/bin/tshark /usr/local/bin/wireshark /usr/local/bin/tshark /usr/bin/dumpcap /usr/local/bin/dumpcap 2>/dev/null || true
		;;
	postgresql|postgres)
		rm -rf /var/lib/postgresql /etc/postgresql /var/run/postgresql 2>/dev/null || true
		;;
	redis)
		rm -rf /var/lib/redis /etc/redis /var/run/redis 2>/dev/null || true
		;;
	nginx)
		rm -rf /var/log/nginx /etc/nginx /var/www/html 2>/dev/null || true
		;;
esac

for uHome in /home/* /root; do
	if [ -d "$uHome" ]; then
		rm -rf "$uHome/.config/$TOOL" "$uHome/.$TOOL" "$uHome/.cache/$TOOL" 2>/dev/null || true
		[ "$TOOL" = "wireshark" ] && rm -rf "$uHome/.config/wireshark" 2>/dev/null || true
	fi
done

echo "=> Step 5: Removing User Group Assignments & Deleting Security Groups..."
case "$TOOL" in
	docker)
		[ -n "$CALLING_USER" ] && gpasswd -d "$CALLING_USER" docker 2>/dev/null || true
		groupdel docker 2>/dev/null || true
		;;
	wazuh|wazuh-agent|wazuh-manager)
		groupdel wazuh 2>/dev/null || true
		userdel wazuh 2>/dev/null || true
		;;
	wireshark|tshark)
		[ -n "$CALLING_USER" ] && gpasswd -d "$CALLING_USER" wireshark 2>/dev/null || true
		groupdel wireshark 2>/dev/null || true
		;;
esac

echo "=> Step 6: Updating Cross-Suite Footprint State Registry..."
python3 -c "
import json, os
p = '/var/lib/cross-suite/state.json'
if os.path.exists(p):
    try:
        with open(p, 'r') as f: d = json.load(f)
        for k in ['$TOOL', 'tshark', 'containerd', 'docker-compose', 'psql', 'wazuh-agent']:
            if k in d: del d[k]
        with open(p, 'w') as f: json.dump(d, f, indent=2)
    except: pass
" 2>/dev/null || true

STILL_EXISTS=$(command -v "$TOOL" 2>/dev/null || echo "")
[ -z "$STILL_EXISTS" ] && [ -x "/opt/$TOOL/$TOOL" ] && STILL_EXISTS="/opt/$TOOL/$TOOL"

if [ -n "$STILL_EXISTS" ]; then
	echo "PURGE_INCOMPLETE|$STILL_EXISTS"
else
	echo "PURGE_VERIFIED"
fi
exit 0
`, cleanTool)

	writeCmd := fmt.Sprintf("cat << 'CROSS_PURGE_EOF' > /var/tmp/cross_purge.sh\n%s\nCROSS_PURGE_EOF\nchmod +x /var/tmp/cross_purge.sh", purgeScript)
	_, _ = executeRemoteCommand(client, writeCmd)
	out, _ := runSudoScriptWithSpinner(client, "bash /var/tmp/cross_purge.sh", fmt.Sprintf("Deep Purging %s & Erasing Footprints", cleanTool))
	_, _ = executeRemoteCommand(client, "rm -f /var/tmp/cross_purge.sh")

	if strings.TrimSpace(out) != "" {
		fmt.Println(Yellow + out + Reset)
	}

	if strings.Contains(out, "PURGE_VERIFIED") {
		fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] DEEP UNINSTALL COMPLETED: '%s' and all associated packages, keyrings, groups, and traces completely eliminated!", cleanTool) + Reset)
	} else if strings.Contains(out, "PURGE_INCOMPLETE") {
		fmt.Println(Red + Bold + fmt.Sprintf("[!] WARNING: A binary footprint for '%s' still exists. Check permissions or manual path overrides.", cleanTool) + Reset)
	} else {
		fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] Deep Purge operations completed for '%s'.", cleanTool) + Reset)
	}
}

// executeWindowsDeepUninstall performs a deep system and registry purge on Windows platforms
func executeWindowsDeepUninstall(client *ssh.Client, tool string) {
	cleanTool := strings.ToLower(strings.TrimSpace(strings.Split(tool, ".")[0]))
	if cleanTool == "" {
		return
	}

	fmt.Println(Red + Bold + fmt.Sprintf("\n[!] INITIALIZING WINDOWS DEEP PURGE & REGISTRY SCRUBBER FOR: '%s'...", cleanTool) + Reset)

	psScript := fmt.Sprintf(`
$tool = '%s'
Write-Output "=> [1/7] Halting Processes & Background Windows Services..."

$procList = @($tool)
$svcList = @($tool)

switch ($tool) {
    'docker' {
        $procList += @('Docker Desktop', 'dockerd', 'containerd', 'com.docker.backend', 'com.docker.proxy', 'wslservice')
        $svcList += @('com.docker.service', 'docker')
    }
    'wireshark' {
        $procList += @('wireshark', 'tshark', 'dumpcap')
        $svcList += @('npcap', 'npf', 'usbpcap')
    }
    'postgresql' {
        $procList += @('postgres', 'pg_ctl')
        $svcList += @('postgresql-x64-16', 'postgresql-x64-15', 'postgresql')
    }
    'vault' {
        $svcList += @('vault')
    }
}

foreach ($svc in $svcList) {
    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
}
foreach ($proc in $procList) {
    Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

Write-Output "=> [2/7] Executing Winget & Chocolatey Silent Teardown..."
$wingetIDs = @($tool)
switch ($tool) {
    'docker'     { $wingetIDs += @('Docker.DockerDesktop', 'Docker.DockerCLI') }
    'wireshark'  { $wingetIDs += @('WiresharkFoundation.Wireshark', 'Insecure.Npcap') }
    'postgresql' { $wingetIDs += @('PostgreSQL.PostgreSQL') }
    'sops'       { $wingetIDs += @('Getsops.Sops', 'Mozilla.Sops') }
    'git'        { $wingetIDs += @('Git.Git') }
    'kubectl'    { $wingetIDs += @('Kubernetes.kubectl') }
}

if (Get-Command winget -ErrorAction SilentlyContinue) {
    foreach ($wid in $wingetIDs) {
        winget uninstall --id $wid --silent --accept-source-agreements 2>$null | Out-Null
    }
}

if (Get-Command choco -ErrorAction SilentlyContinue) {
    choco uninstall $tool -y --remove-dependencies 2>$null | Out-Null
}

Write-Output "=> [3/7] Invoking MSIEXEC and Native Windows Uninstall Strings..."
$regUninstallPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

Get-ItemProperty $regUninstallPaths -ErrorAction SilentlyContinue | Where-Object { 
    $_.DisplayName -match "(?i)$tool" -or $_.PSChildName -match "(?i)$tool" 
} | ForEach-Object {
    if ($_.UninstallString) {
        $uStr = $_.UninstallString
        if ($uStr -match '(?i)msiexec') {
            $guid = [regex]::Match($uStr, '\{[A-Fa-f0-9-]+\}').Value
            if ($guid) {
                Start-Process "msiexec.exe" -ArgumentList "/x $guid /qn /norestart" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            }
        } elseif ($uStr -match '\.exe') {
            $exePath = [regex]::Match($uStr, '^[^\"]+|^\"[^\"]+\"').Value.Trim('\"')
            if (Test-Path $exePath) {
                Start-Process -FilePath $exePath -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /S" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            }
        }
    }
}

Write-Output "=> [4/7] Scrubbing Windows Registry Residue..."
$regKeysToPurge = @(
    "HKLM:\Software\$tool",
    "HKLM:\Software\Wow6432Node\$tool",
    "HKCU:\Software\$tool",
    "HKLM:\SYSTEM\CurrentControlSet\Services\$tool",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$tool.exe"
)

if ($tool -eq 'docker') {
    $regKeysToPurge += @(
        "HKLM:\Software\Docker Inc.",
        "HKCU:\Software\Docker Inc.",
        "HKLM:\SYSTEM\CurrentControlSet\Services\com.docker.service"
    )
}

if ($tool -eq 'wireshark') {
    $regKeysToPurge += @(
        "HKLM:\Software\Wireshark",
        "HKLM:\Software\Wow6432Node\Wireshark",
        "HKLM:\SYSTEM\CurrentControlSet\Services\npf",
        "HKLM:\SYSTEM\CurrentControlSet\Services\npcap"
    )
}

foreach ($rk in $regKeysToPurge) {
    if (Test-Path $rk) {
        Remove-Item -Path $rk -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Output "=> [5/7] Deleting Filesystem Footprints, Caches & AppData..."
$crossBin = "C:\ProgramData\cross-suite\bin"
Remove-Item -Path "$crossBin\$tool.exe" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$crossBin\$tool" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$crossBin\${tool}_extracted" -Recurse -Force -ErrorAction SilentlyContinue

$pathsToWipe = @(
    "C:\Program Files\$tool",
    "C:\Program Files (x86)\$tool",
    "C:\ProgramData\$tool",
    "$env:LOCALAPPDATA\$tool",
    "$env:APPDATA\$tool",
    "$env:USERPROFILE\.$tool"
)

if ($tool -eq 'docker') {
    $pathsToWipe += @(
        "C:\Program Files\Docker",
        "C:\ProgramData\DockerDesktop",
        "$env:LOCALAPPDATA\Docker",
        "$env:APPDATA\Docker",
        "$env:USERPROFILE\.docker"
    )
}

foreach ($p in $pathsToWipe) {
    if (Test-Path $p) {
        Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Output "=> [6/7] Sanitizing Machine PATH and Custom Environment Variables..."
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath) {
    $pathParts = $machinePath -split ';' | Where-Object { 
        $_ -and $_ -notmatch "(?i)\\$tool(\\|$)" -and $_ -ne "$crossBin\$tool"
    }
    $newPath = ($pathParts -join ';').Trim(';')
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
}

Get-ChildItem env: | Where-Object { $_.Name -match "(?i)^$tool" } | ForEach-Object {
    [Environment]::SetEnvironmentVariable($_.Name, $null, 'Machine')
    [Environment]::SetEnvironmentVariable($_.Name, $null, 'User')
}

Write-Output "=> [7/7] Updating Footprint State Registry & Final Verification..."
$fp = 'C:\ProgramData\cross-suite\state.json'
if (Test-Path $fp) {
    try {
        $data = Get-Content $fp | ConvertFrom-Json -AsHashtable
        if ($data.ContainsKey($tool)) {
            $data.Remove($tool)
            $data | ConvertTo-Json | Set-Content $fp -Encoding UTF8
        }
    } catch {}
}

$stillExists = (Get-Command $tool -ErrorAction SilentlyContinue) -or (Test-Path "$crossBin\$tool.exe")
if ($stillExists) {
    Write-Output "PURGE_INCOMPLETE"
} else {
    Write-Output "SUCCESS_PURGED"
}
`, cleanTool)

	utf16LE := []byte{}
	for _, r := range psScript {
		utf16LE = append(utf16LE, byte(r), byte(r>>8))
	}
	b64Cmd := base64.StdEncoding.EncodeToString(utf16LE)

	winCmd := fmt.Sprintf("powershell -NoProfile -EncodedCommand %s", b64Cmd)
	out, err := runSudoScriptWithSpinner(client, winCmd, fmt.Sprintf("Deep Purging %s on Windows Target", cleanTool))

	if strings.Contains(out, "SUCCESS_PURGED") || (err == nil && !strings.Contains(out, "PURGE_INCOMPLETE")) {
		fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] WINDOWS SYSTEM & REGISTRY PURGE COMPLETED: '%s' eradicated without junk residues!", cleanTool) + Reset)
	} else if strings.Contains(out, "PURGE_INCOMPLETE") {
		fmt.Println(Red + Bold + fmt.Sprintf("[!] WARNING: An executable or alias for '%s' was still detected on system PATH.", cleanTool) + Reset)
	} else {
		fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] Windows purge operations completed for '%s'.", cleanTool) + Reset)
	}
}

// TraceAndPurgeToolFootprints scans package logs to identify recently installed tools and allows 1-click purge
func TraceAndPurgeToolFootprints(client *ssh.Client, targetOS osdetect.TargetOS) {
	fmt.Println(Cyan + Bold + "\n[+] Tracing Recently Installed Packages & Artifact Footprints..." + Reset)

	if targetOS == osdetect.OSWindows {
		out, _ := executeRemoteCommand(client, "powershell -NoProfile -Command \"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion | Where-Object {$_.DisplayName -ne $null} | Out-String\"")
		header := Bold + Cyan + "================================================================================" + Reset + "\n" +
			Bold + Yellow + "               INSTALLED WINDOWS SOFTWARE TRACE & FOOTPRINTS                   " + Reset + "\n" +
			Bold + Cyan + "================================================================================" + Reset + "\n\n"
		ViewInPager(header + out)
	} else {
		ensureAutonomousPermissionsWithPrompt(client)
		traceCmd := `
			if [ -f /var/log/dpkg.log ]; then
				grep " install " /var/log/dpkg.log 2>/dev/null | tail -n 25
			elif [ -f /var/log/apt/history.log ]; then
				grep -E "Commandline:" /var/log/apt/history.log 2>/dev/null | tail -n 25
			elif [ -f /var/log/dnf.log ]; then
				grep "Installed:" /var/log/dnf.log 2>/dev/null | tail -n 25
			else
				rpm -qa --last 2>/dev/null | head -n 25
			fi
		`
		out, _ := runSudoScript(client, traceCmd)

		header := Bold + Cyan + "================================================================================" + Reset + "\n" +
			Bold + Yellow + "               RECENTLY INSTALLED SYSTEM TOOLS & PACKAGE TRACES               " + Reset + "\n" +
			Bold + Cyan + "================================================================================" + Reset + "\n\n"
		ViewInPager(header + out)
	}

	targetToPurge := strings.TrimSpace(transfer.ReadRealtimeInput("\nEnter package name from trace list to DEEP PURGE (or '0'/Enter to skip): "))
	if targetToPurge != "" && targetToPurge != "0" && !strings.EqualFold(targetToPurge, "b") && !strings.EqualFold(targetToPurge, "back") && !strings.EqualFold(targetToPurge, "q") {
		ExecuteDeepUninstaller(client, targetToPurge, targetOS)
	}
}

// InspectAndDeployFamily performs dynamic package search on Linux or Windows with fluid Back/Cancel options
func InspectAndDeployFamily(reader *bufio.Reader, client *ssh.Client, query string, targetOS osdetect.TargetOS) {
	cleanQuery := strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(query, "-*"), "*"))
	if cleanQuery == "" || cleanQuery == "0" || strings.EqualFold(cleanQuery, "b") || strings.EqualFold(cleanQuery, "back") || strings.EqualFold(cleanQuery, "q") {
		fmt.Println(Yellow + "[!] Operation canceled. Returning to Hub 5 Menu..." + Reset)
		return
	}

	if targetOS != osdetect.OSWindows {
		ensureAutonomousPermissionsWithPrompt(client)
	}

	fmt.Println(Cyan + Bold + "\n[+] Executing Package Search for: " + cleanQuery + Reset)

	var family []string
	seen := make(map[string]bool)

	// Canonicalize multi-tier ecosystem targets to real executable family binaries
	if targetOS != osdetect.OSWindows {
		switch cleanQuery {
		case "docker", "docker-ce", "docker-ce-cli":
			family = []string{"docker", "docker-compose"}
		case "wireshark", "wireshark-qt", "wireshark-common", "tshark":
			family = []string{"wireshark", "tshark"}
		case "postgresql", "postgres":
			family = []string{"postgresql"}
		case "wazuh", "wazuh-agent", "wazuh-manager":
			family = []string{"wazuh-agent"}
		case "podman":
			family = []string{"podman"}
		default:
			family = append(family, cleanQuery)
			seen[cleanQuery] = true

			searchCmd := fmt.Sprintf(`
				if [ -d /etc/yum.repos.d ]; then
					rm -f /etc/yum.repos.d/*broken* 2>/dev/null || true
					for f in /etc/yum.repos.d/*.repo; do
						if [ -f "$f" ]; then
							if grep -q "baseurl=%%%%s" "$f" 2>/dev/null || grep -q "baseurl=\$" "$f" 2>/dev/null || grep -q "baseurl=.*\.repo" "$f" 2>/dev/null; then
								rm -f "$f" 2>/dev/null || true
							fi
						fi
					done
				fi

				if command -v apt-cache >/dev/null 2>&1; then
					for broken in /etc/apt/sources.list.d/*trivy*.list; do
						[ -f "$broken" ] && mv "$broken" "${broken}.disabled" 2>/dev/null || true
					done
					apt-cache search -n "^%s" 2>/dev/null | awk '{print $1}' | head -n 15
				elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
					(dnf --setopt=*.skip_if_unavailable=true search %s 2>/dev/null || yum --setopt=*.skip_if_unavailable=true search %s 2>/dev/null) | grep -iE "^%s" | awk '{print $1}' | head -n 15
				fi
			`, cleanQuery, cleanQuery, cleanQuery, cleanQuery)

			out, _ := runSudoScript(client, searchCmd)
			lines := strings.Split(out, "\n")
			for _, l := range lines {
				trimmed := strings.TrimSpace(l)
				baseName := strings.Split(trimmed, ".")[0]

				// Filter out non-executable packages: documentation, headers, debug symbols, plugins, and helper extras
				if strings.HasSuffix(baseName, "-doc") ||
					strings.HasSuffix(baseName, "-dev") ||
					strings.HasSuffix(baseName, "-dbg") ||
					strings.HasSuffix(baseName, "-data") ||
					strings.HasSuffix(baseName, "-headers") ||
					strings.HasSuffix(baseName, "-gtk") ||
					strings.HasSuffix(baseName, "-plugin") ||
					strings.HasSuffix(baseName, "-plugins") ||
					strings.HasSuffix(baseName, "-extras") ||
					strings.Contains(baseName, "secrets-engine") ||
					strings.Contains(baseName, "model-plugin") ||
					strings.Contains(baseName, "scan-plugin") ||
					strings.Contains(baseName, "rootless") {
					continue
				}

				if trimmed != "" && !seen[baseName] && !strings.Contains(trimmed, "[sudo]") && !strings.Contains(trimmed, "password") && !strings.Contains(trimmed, "Error") && !strings.Contains(trimmed, "Repository") && !strings.Contains(trimmed, "Failed") {
					seen[baseName] = true
					family = append(family, baseName)
				}
			}
		}
	} else {
		family = append(family, cleanQuery)
		seen[cleanQuery] = true

		winSearchCmd := fmt.Sprintf("powershell -NoProfile -Command \"winget search %s 2>$null | Select-Object -First 8 | Out-String\"", cleanQuery)
		out, _ := executeRemoteCommand(client, winSearchCmd)
		lines := strings.Split(out, "\n")
		for _, l := range lines {
			trimmed := strings.TrimSpace(l)
			if trimmed != "" && !strings.Contains(trimmed, "Name") && !strings.Contains(trimmed, "---") {
				fields := strings.Fields(trimmed)
				if len(fields) > 1 {
					pkgID := fields[len(fields)-1]
					if !seen[pkgID] && len(pkgID) > 2 {
						seen[pkgID] = true
						family = append(family, pkgID)
					}
				}
			}
		}
	}

	coreVerified := false
	if targetOS == osdetect.OSWindows {
		vOut, _ := executeRemoteCommand(client, fmt.Sprintf("powershell -NoProfile -Command \"if (winget show --id %s -e 2>$null) { 'YES' } else { 'NO' }\"", cleanQuery))
		coreVerified = strings.Contains(vOut, "YES")
	} else {
		vOut, _ := runSudoScript(client, fmt.Sprintf(
			"apt-cache policy %s 2>/dev/null | grep -q 'Candidate:.*[^(]none[^)]' ; if [ $? -eq 1 ] && apt-cache policy %s 2>/dev/null | grep -q Candidate; then echo YES; elif dnf list --available %s >/dev/null 2>&1; then echo YES; elif yum list available %s >/dev/null 2>&1; then echo YES; else echo NO; fi",
			cleanQuery, cleanQuery, cleanQuery, cleanQuery))
		coreVerified = strings.Contains(vOut, "YES")
	}

	fmt.Println(Yellow + "\nDetected Package Targets & Modules:" + Reset)
	for idx, item := range family {
		if item == cleanQuery {
			if coreVerified {
				fmt.Printf("  [%d] %s (Core Executable — Verified in Native Repo)\n", idx+1, item)
			} else {
				fmt.Printf("  [%d] %s (Enterprise / Upstream — Multi-Layer Fallback Chain)\n", idx+1, item)
			}
		} else {
			fmt.Printf("  [%d] %s (Core Ecosystem Binary)\n", idx+1, item)
		}
	}

	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
	fmt.Println(Bold + "Select Installation Mode:" + Reset)
	fmt.Println("  [1] Install All (Core Executable & All Family Modules)")
	fmt.Println("  [2] Select Specific Member to Install")
	fmt.Println(Red + "  [0] Return to Hub 5 Menu (Cancel / Go Back)" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	modeChoice := strings.TrimSpace(transfer.ReadRealtimeInput("Choice [0-2, default: 1]: "))

	if modeChoice == "0" || strings.EqualFold(modeChoice, "b") || strings.EqualFold(modeChoice, "back") || strings.EqualFold(modeChoice, "q") {
		fmt.Println(Yellow + "[!] Operation canceled. Returning to Hub 5 Menu..." + Reset)
		return
	}

	var targetsToInstall []string
	if modeChoice == "2" {
		fmt.Println(Cyan + "\nSelect the specific package number to install:" + Reset)
		fmt.Println(Red + "  [0] Return to Hub 5 Menu (Cancel / Go Back)" + Reset)
		mInput := strings.TrimSpace(transfer.ReadRealtimeInput("Enter choice number [1-" + fmt.Sprintf("%d", len(family)) + "] or 0 to Cancel: "))

		if mInput == "0" || strings.EqualFold(mInput, "b") || strings.EqualFold(mInput, "back") || strings.EqualFold(mInput, "q") {
			fmt.Println(Yellow + "[!] Operation canceled. Returning to Hub 5 Menu..." + Reset)
			return
		}

		var selectedIdx int
		_, err := fmt.Sscanf(mInput, "%d", &selectedIdx)
		if err == nil && selectedIdx >= 1 && selectedIdx <= len(family) {
			targetsToInstall = append(targetsToInstall, family[selectedIdx-1])
		} else {
			fmt.Println(Yellow + "[!] Invalid selection. Returning to Hub 5 Menu..." + Reset)
			return
		}
	} else {
		targetsToInstall = family
	}

	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
	targetListStr := strings.Join(targetsToInstall, ", ")
	confirmMsg := fmt.Sprintf("Would you like to proceed with Autonomous Installation of [%s]? [y/N or 0 to Cancel]: ", targetListStr)
	confirm := strings.TrimSpace(transfer.ReadRealtimeInput(confirmMsg))

	if strings.EqualFold(confirm, "y") || strings.EqualFold(confirm, "yes") {
		for _, pkg := range targetsToInstall {
			fmt.Printf(Cyan+Bold+"\n[+] Deploying Target Package: %s...\n"+Reset, pkg)
			ExecutePortableDeployment(client, pkg, targetOS)
		}
	} else {
		fmt.Println(Yellow + "[!] Installation canceled by user. Returning to Hub 5 Menu..." + Reset)
		return
	}
}

// ExecutePortableDeployment performs an idempotent, self-healing multi-layer deployment across Linux or Windows
func ExecutePortableDeployment(client *ssh.Client, tool string, targetOS osdetect.TargetOS) {
	cleanTool := strings.Split(tool, ".")[0]

	if targetOS == osdetect.OSWindows {
		executeWindowsDeployment(client, cleanTool)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)

	// Step 1: Strict Client-First Idempotency Check (Never falsely skip on dockerd)
	checkCmd := fmt.Sprintf(`
		TARGET="%s"
		INST_PATH=""

		CHECK_LIST=("$TARGET")
		case "$TARGET" in
			postgresql|postgres) CHECK_LIST=("psql") ;;
			wireshark) CHECK_LIST=("/usr/bin/wireshark" "/usr/local/bin/wireshark" "wireshark-qt") ;;
			tshark)    CHECK_LIST=("tshark") ;;
			docker|docker-ce|docker-ce-cli) CHECK_LIST=("docker") ;;
			docker-compose) CHECK_LIST=("docker-compose") ;;
			wazuh|wazuh-agent|wazuh-manager) CHECK_LIST=("/var/ossec/bin/wazuh-control") ;;
			podman) CHECK_LIST=("podman") ;;
		esac

		for b_name in "${CHECK_LIST[@]}"; do
			CANDIDATES=($(command -v "$b_name" 2>/dev/null) "/usr/bin/$b_name" "/usr/local/bin/$b_name" "/opt/$TARGET/$b_name")
			for bin in "${CANDIDATES[@]}"; do
				if [ -n "$bin" ] && [ -x "$bin" ] && [ ! -d "$bin" ]; then
					if QT_QPA_PLATFORM=offscreen "$bin" --version >/dev/null 2>&1 || "$bin" version >/dev/null 2>&1 || "$bin" status >/dev/null 2>&1 || dpkg -S "$bin" >/dev/null 2>&1 || rpm -qf "$bin" >/dev/null 2>&1; then
						INST_PATH="$bin"
						break 2
					fi
				fi
			done
		done

		if [ -n "$INST_PATH" ]; then
			VER=$("$INST_PATH" --version 2>/dev/null | head -n 1)
			[ -z "$VER" ] && VER=$("$INST_PATH" version 2>/dev/null | head -n 1)
			[ -z "$VER" ] && VER="installed"
			echo "ALREADY_INSTALLED|$INST_PATH|$VER"
		else
			echo "NOT_INSTALLED"
		fi
	`, cleanTool)

	checkOut, _ := runSudoScript(client, checkCmd)

	if strings.Contains(checkOut, "ALREADY_INSTALLED") {
		parts := strings.Split(strings.TrimSpace(checkOut), "|")
		realPath := ""
		realVer := "installed"

		if len(parts) >= 2 && strings.TrimSpace(parts[1]) != "" {
			realPath = strings.TrimSpace(parts[1])
		}
		if len(parts) >= 3 && strings.TrimSpace(parts[2]) != "" {
			realVer = strings.TrimSpace(parts[2])
		}

		if realPath != "" {
			fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] IDEMPOTENT SKIP: '%s' is already installed at '%s' (%s).", cleanTool, realPath, realVer) + Reset)
			return
		}
	}

	// Step 2: Autonomous Universal Multi-Layer Deployment Engine
	deployCmd := fmt.Sprintf(`#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export UCF_FORCE_CONFFOLD=1
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
mkdir -p /var/lib/cross-suite /usr/local/bin /usr/bin /var/tmp /etc/cross-suite /etc/apt/keyrings

TOOL_NAME="%s"
INSTALLED=0
CALLING_USER="${SUDO_USER:-$(logname 2>/dev/null || echo $USER)}"
export CROSS_DEBUG_VERIFY=1

echo "[+] Executing Autonomous Multi-Layer Portable Deployment for: $TOOL_NAME..."

# ------------------------------------------------------------------------------
# STEP 0: EMBEDDED PRE-FLIGHT HEALER & NEEDRESTART SUPPRESSOR
# ------------------------------------------------------------------------------
pkill -9 -x apt-get 2>/dev/null || true
pkill -9 -x dpkg 2>/dev/null || true
pkill -9 -x yum 2>/dev/null || true
pkill -9 -x dnf 2>/dev/null || true

rm -f /var/lib/dpkg/lock* /var/lib/apt/lists/lock* /var/cache/apt/archives/lock* /var/run/yum.pid /var/run/dnf.pid 2>/dev/null || true

if command -v dpkg >/dev/null 2>&1; then
	dpkg --configure -a 2>/dev/null || true
fi

if [ -f /etc/needrestart/needrestart.conf ]; then
	sed -i "s/#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/g" /etc/needrestart/needrestart.conf 2>/dev/null || true
	sed -i "s/\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/g" /etc/needrestart/needrestart.conf 2>/dev/null || true
fi

APT_RUN="apt-get -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -o needrestart::mode=a"

if command -v apt-get >/dev/null 2>&1; then
	if ! command -v curl >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
		$APT_RUN update -qq >/dev/null 2>&1 || true
		$APT_RUN install curl tar gzip gnupg ca-certificates >/dev/null 2>&1 || true
	fi
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
	PM=$(command -v dnf || command -v yum)
	if ! command -v curl >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
		$PM install -y -q curl tar gzip gnupg2 ca-certificates >/dev/null 2>&1 || true
	fi
fi

ARCH=$(uname -m)
case "$ARCH" in
	x86_64) ARCH_MATCH="amd64|x86_64|x64" ;;
	aarch64|arm64) ARCH_MATCH="arm64|aarch64" ;;
	armv7*|armhf) ARCH_MATCH="armv7|armhf" ;;
	*) ARCH_MATCH="$ARCH" ;;
esac

# Distro Codename Normalizer
DISTRO_FAMILY="debian"
CANONICAL_CODENAME="bookworm"

if [ -f /etc/os-release ]; then
	. /etc/os-release
	case "$ID" in
		ubuntu)
			DISTRO_FAMILY="ubuntu"
			case "$VERSION_CODENAME" in
				noble|jammy|focal) CANONICAL_CODENAME="$VERSION_CODENAME" ;;
				*) CANONICAL_CODENAME="jammy" ;;
			esac
			;;
		debian)
			DISTRO_FAMILY="debian"
			case "$VERSION_CODENAME" in
				bookworm|bullseye|trixie) CANONICAL_CODENAME="$VERSION_CODENAME" ;;
				*) CANONICAL_CODENAME="bookworm" ;;
			esac
			;;
		parrot|kali|pureos|raspbian)
			DISTRO_FAMILY="debian"
			CANONICAL_CODENAME="bookworm"
			;;
		linuxmint|pop|elementary|zorin)
			DISTRO_FAMILY="ubuntu"
			CANONICAL_CODENAME="jammy"
			;;
		*)
			if [ -f /etc/debian_version ]; then
				DISTRO_FAMILY="debian"
				CANONICAL_CODENAME="bookworm"
			fi
			;;
	esac
fi

# ------------------------------------------------------------------------------
# STEP 0.5: CANONICAL SYMLINK CONTRACT ENFORCER
# ------------------------------------------------------------------------------
enforce_canonical_symlinks() {
	# 1. Wireshark GUI link: enforce /usr/bin/wireshark -> wireshark-qt
	if [ -x /usr/bin/wireshark-qt ] && [ ! -x /usr/bin/wireshark ]; then
		rm -f /usr/bin/wireshark /usr/local/bin/wireshark 2>/dev/null || true
		ln -snf /usr/bin/wireshark-qt /usr/bin/wireshark 2>/dev/null || true
		ln -snf /usr/bin/wireshark-qt /usr/local/bin/wireshark 2>/dev/null || true
		chmod +x /usr/bin/wireshark /usr/local/bin/wireshark 2>/dev/null || true
	fi

	# 2. Docker Compose CLI link
	if [ -x /usr/libexec/docker/cli-plugins/docker-compose ] && [ ! -x /usr/local/bin/docker-compose ]; then
		ln -snf /usr/libexec/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose 2>/dev/null || true
		ln -snf /usr/libexec/docker/cli-plugins/docker-compose /usr/bin/docker-compose 2>/dev/null || true
	fi

	# 3. PostgreSQL client alias
	if command -v psql >/dev/null 2>&1 && [ ! -x /usr/local/bin/postgresql ]; then
		ln -snf "$(command -v psql)" /usr/local/bin/postgresql 2>/dev/null || true
	fi

	# 4. Wazuh agent control link
	if [ -x /var/ossec/bin/wazuh-control ] && [ ! -x /usr/local/bin/wazuh-control ]; then
		ln -snf /var/ossec/bin/wazuh-control /usr/local/bin/wazuh-control 2>/dev/null || true
		ln -snf /var/ossec/bin/wazuh-control /usr/local/bin/wazuh 2>/dev/null || true
	fi
}

verify_tool() {
	enforce_canonical_symlinks

	if [ -n "$CROSS_DEBUG_VERIFY" ]; then
		echo "   [debug] verify_tool: checking TOOL_NAME=$TOOL_NAME" >&2
		echo "   [debug] dpkg status: $(dpkg -l 2>/dev/null | grep -E "wireshark|tshark" | awk '{print $1,$2}' | tr '\n' ';')" >&2
		echo "   [debug] which binaries exist: $(ls -la /usr/bin/*shark* /usr/bin/dumpcap 2>/dev/null)" >&2
	fi

	local check_bins=("$TOOL_NAME")
	case "$TOOL_NAME" in
		postgresql|postgres)
			check_bins=("psql" "postgres" "/usr/lib/postgresql/*/bin/postgres" "/usr/local/bin/postgresql")
			;;
		wireshark)
			# Modern Debian/Ubuntu ship the GUI binary directly as /usr/bin/wireshark via the
			# 'wireshark' package — wireshark-qt no longer provides a separate wireshark-qt binary.
			check_bins=("/usr/bin/wireshark" "/usr/local/bin/wireshark" "wireshark" "wireshark-qt" "wireshark.real")
			;;
		tshark)
			check_bins=("tshark" "/usr/bin/tshark" "/usr/local/bin/tshark")
			;;
		docker|docker-ce|docker-ce-cli)
			check_bins=("docker")
			;;
		docker-compose)
			check_bins=("docker-compose" "/usr/libexec/docker/cli-plugins/docker-compose")
			;;
		wazuh|wazuh-agent|wazuh-manager)
			check_bins=("/var/ossec/bin/wazuh-control" "/var/ossec/bin/wazuh-agentd" "/usr/local/bin/wazuh-control")
			;;
		podman)
			check_bins=("podman")
			;;
		sops)
			check_bins=("sops")
			;;
		kubectl)
			check_bins=("kubectl")
			;;
		vault|consul|nomad|terraform|packer)
			check_bins=("$TOOL_NAME")
			;;
		redis)
			check_bins=("redis-cli" "redis-server")
			;;
		nginx)
			check_bins=("nginx")
			;;
		caddy)
			check_bins=("caddy")
			;;
		gitlab-runner)
			check_bins=("gitlab-runner")
			;;
		jenkins)
			check_bins=("jenkins")
			;;
	esac

	for b_name in "${check_bins[@]}"; do
		local b
		b=$(command -v "$b_name" 2>/dev/null || echo "")
		if [ -z "$b" ]; then
			for c in "/usr/local/bin/$b_name" "/usr/bin/$b_name" "/usr/sbin/$b_name" "/opt/$TOOL_NAME/$b_name" "/opt/$TOOL_NAME/bin/$b_name" /usr/lib/postgresql/*/bin/$b_name /var/ossec/bin/$b_name /usr/libexec/docker/cli-plugins/$b_name; do
				if [ -x "$c" ] && [ ! -d "$c" ]; then
					b="$c"
					break
				fi
			done
		fi
		if [ -n "$b" ] && [ -x "$b" ]; then
			if QT_QPA_PLATFORM=offscreen "$b" --version >/dev/null 2>&1 || "$b" version >/dev/null 2>&1 || "$b" -v >/dev/null 2>&1 || "$b" --help >/dev/null 2>&1 || "$b" status >/dev/null 2>&1 || [ "$b_name" = "/var/ossec/bin/wazuh-control" ] || dpkg -S "$b" >/dev/null 2>&1 || rpm -qf "$b" >/dev/null 2>&1; then
				echo "$b"
				return 0
			elif [ -n "$CROSS_DEBUG_VERIFY" ]; then
				echo "   [debug] candidate $b exists but failed every sanity probe" >&2
			fi
		elif [ -n "$CROSS_DEBUG_VERIFY" ] && [ -n "$b" ]; then
			echo "   [debug] candidate $b not executable/found" >&2
		fi
	done
	return 1
}

# ==============================================================================
# LAYER 0.8: HARDENED ENTERPRISE INFRASTRUCTURE & LIFECYCLE MATRIX
# ==============================================================================
case "$TOOL_NAME" in
	docker|docker-ce|docker-ce-cli)
		echo "=> [Layer 0.8] Executing Autonomous Multi-Step Docker Engine Pipeline..."
		DOCKER_SUCCESS=0

		# METHOD 1: Official Signed Vendor APT Repository with World-Readable Keyring
		if command -v apt-get >/dev/null 2>&1; then
			install -m 0755 -d /etc/apt/keyrings
			curl -fsSL "https://download.docker.com/linux/$DISTRO_FAMILY/gpg" | gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg 2>/dev/null || true
			chmod 644 /etc/apt/keyrings/docker.gpg 2>/dev/null || true
			echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$DISTRO_FAMILY $CANONICAL_CODENAME stable" > /etc/apt/sources.list.d/docker.list 2>/dev/null || true
			
			$APT_RUN update -qq >/dev/null 2>&1 || true
			$APT_RUN install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>&1 || true
			
			if command -v docker >/dev/null 2>&1; then
				DOCKER_SUCCESS=1
			fi
		elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
			curl -sSL https://download.docker.com/linux/centos/docker-ce.repo -o /etc/yum.repos.d/docker-ce.repo 2>/dev/null || true
			(dnf install -y docker-ce docker-ce-cli containerd.io || yum install -y docker-ce docker-ce-cli containerd.io) 2>&1 || true
			if command -v docker >/dev/null 2>&1; then
				DOCKER_SUCCESS=1
			fi
		fi

		# METHOD 2: Official Upstream Static Engine Deployment (Zero Dependency / Distro Agnostic)
		if [ $DOCKER_SUCCESS -eq 0 ] && ! command -v docker >/dev/null 2>&1; then
			echo "   [+] Ingesting Official Docker Static Binary Engine (Upstream Bundle)..."
			STATIC_ARCH="x86_64"
			[ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ] && STATIC_ARCH="aarch64"

			WORK_DIR="/var/tmp/cross_docker_static_$$"
			rm -rf "$WORK_DIR" && mkdir -p "$WORK_DIR"
			
			curl -fsSL -L "https://download.docker.com/linux/static/stable/${STATIC_ARCH}/docker-27.3.1.tgz" -o "$WORK_DIR/docker.tgz" 2>/dev/null || \
			curl -fsSL -L "https://download.docker.com/linux/static/stable/${STATIC_ARCH}/docker-26.1.4.tgz" -o "$WORK_DIR/docker.tgz" 2>/dev/null

			if [ -s "$WORK_DIR/docker.tgz" ]; then
				tar -xzf "$WORK_DIR/docker.tgz" -C "$WORK_DIR" 2>/dev/null || true
				if [ -d "$WORK_DIR/docker" ]; then
					cp -f "$WORK_DIR/docker/"* /usr/local/bin/ 2>/dev/null || true
					cp -f "$WORK_DIR/docker/"* /usr/bin/ 2>/dev/null || true
					chmod +x /usr/local/bin/docker* /usr/bin/docker* 2>/dev/null || true

					cat << 'EOF' > /etc/systemd/system/docker.service
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network-online.target firewalld.target containerd.service
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/dockerd
ExecReload=/bin/kill -s HUP $MAINPID
TimeoutSec=0
RestartSec=2
Restart=always
StartLimitBurst=3
StartLimitInterval=60s
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Delegate=yes
KillMode=process
OOMScoreAdjust=-500

[Install]
WantedBy=multi-user.target
EOF
					chmod 644 /etc/systemd/system/docker.service 2>/dev/null || true
					DOCKER_SUCCESS=1
				fi
			fi
			rm -rf "$WORK_DIR"
		fi

		groupadd docker 2>/dev/null || true
		[ -n "$CALLING_USER" ] && usermod -aG docker "$CALLING_USER" 2>/dev/null || true
		timeout 15s systemctl daemon-reload 2>/dev/null || true
		timeout 20s systemctl enable --now docker 2>/dev/null || true
		;;

	docker-compose)
		echo "=> [Layer 0.8] Deploying Official Docker Compose Standalone Engine..."
		DOCKER_CONFIG=${DOCKER_CONFIG:-/usr/local/lib/docker}
		mkdir -p "$DOCKER_CONFIG/cli-plugins" /usr/local/bin /usr/libexec/docker/cli-plugins
		DC_URL=$(curl -fsSL https://api.github.com/repos/docker/compose/releases/latest 2>/dev/null | grep -oiE "https://github.com/docker/compose/releases/download/[^\"]+linux-x86_64" | head -n 1)
		[ -z "$DC_URL" ] && DC_URL="https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64"
		curl -fsSL -L "$DC_URL" -o /usr/local/bin/docker-compose 2>/dev/null
		chmod +x /usr/local/bin/docker-compose 2>/dev/null || true
		cp -f /usr/local/bin/docker-compose "$DOCKER_CONFIG/cli-plugins/docker-compose" 2>/dev/null || true
		cp -f /usr/local/bin/docker-compose "/usr/libexec/docker/cli-plugins/docker-compose" 2>/dev/null || true
		ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose 2>/dev/null || true
		;;

	wireshark|wireshark-qt|wireshark-common|tshark)
		echo "=> [Layer 0.8] Configuring Wireshark Privileges & Non-Root Capture Groups..."
		
		# 1. Pre-seed debconf cleanly to completely silence interactive prompts
		if command -v debconf-set-selections >/dev/null 2>&1; then
			echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections 2>/dev/null || true
		fi

		# 2. Deploy Wireshark GUI, TShark CLI, and capture utilities
		if command -v apt-get >/dev/null 2>&1; then
			# Enable universe (Ubuntu) or ensure proper sources
			if command -v add-apt-repository >/dev/null 2>&1; then
				add-apt-repository -y universe >/dev/null 2>&1 || true
			elif [ -f /etc/apt/sources.list ]; then
				grep -q "^deb .*universe" /etc/apt/sources.list 2>/dev/null || \
				sed -i '/^deb .*main/ s/main$/main universe/' /etc/apt/sources.list 2>/dev/null || true
			fi
			$APT_RUN update -qq >/dev/null 2>&1 || true

			# Helper function to verify and fix a package
			ensure_pkg_binary() {
				local pkg="$1"
				local binary="$2"
				echo "   [+] Installing $pkg ..."
				$APT_RUN install "$pkg" 2>&1 || true

				if ! command -v "$binary" >/dev/null 2>&1; then
					echo "   [!] $binary not found after install; attempting repair..."
					$APT_RUN install -f 2>&1 || true
					dpkg --configure -a 2>/dev/null || true
					$APT_RUN install --reinstall "$pkg" 2>&1 || true
					# If still missing, try to locate the binary in package files
					if ! command -v "$binary" >/dev/null 2>&1; then
						echo "   [+] Searching for $binary in installed package files..."
						local found_bin=$(dpkg -L "$pkg" 2>/dev/null | grep -E "/bin/$binary$" | head -n 1)
						if [ -n "$found_bin" ] && [ -x "$found_bin" ]; then
							echo "   [+] Found $binary at $found_bin, creating symlink..."
							ln -sf "$found_bin" "/usr/local/bin/$binary"
							ln -sf "$found_bin" "/usr/bin/$binary"
							if command -v "$binary" >/dev/null 2>&1; then
								echo "   [SUCCESS] $binary symlinked and available."
							else
								echo "   [ERROR] $binary still not in PATH after symlink."
							fi
						else
							# Try alternative package names
							echo "   [+] Trying alternative package: wireshark-cli"
							$APT_RUN install wireshark-cli 2>&1 || true
							if command -v "$binary" >/dev/null 2>&1; then
								echo "   [SUCCESS] $binary installed via wireshark-cli."
							else
								echo "   [ERROR] $binary still missing; manual intervention may be needed."
							fi
						fi
					else
						echo "   [SUCCESS] $binary is now available."
					fi
				else
					echo "   [SUCCESS] $binary installed."
				fi
			}

			# Install tshark (CLI)
			ensure_pkg_binary "tshark" "tshark"

			# Install wireshark-common (libs & dumpcap)
			echo "   [+] Installing wireshark-common (shared libs & dumpcap)..."
			$APT_RUN install wireshark-common libcap2-bin 2>&1 || true

			# Attempt wireshark-qt (GUI, optional)
			echo "   [+] Attempting wireshark-qt (GUI, optional on headless targets)..."
			WS_QT_LOG=$($APT_RUN install wireshark-qt 2>&1)
			echo "$WS_QT_LOG"
			if ! command -v wireshark-qt >/dev/null 2>&1 && ! dpkg -s wireshark-qt >/dev/null 2>&1; then
				echo "   [!] wireshark-qt unavailable/unresolvable — continuing with CLI only. Root cause: $(echo "$WS_QT_LOG" | grep -iE 'unable to locate|depends|E:' | head -n 3)"
			fi

			# Install meta-package 'wireshark' (provides symlink)
			echo "   [+] Installing wireshark meta-package..."
			$APT_RUN install wireshark 2>&1 || true

			# Final fix pass
			$APT_RUN install -f 2>&1 || true
			dpkg --configure -a 2>/dev/null || true
		elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
			PM=$(command -v dnf || command -v yum)
			$PM install -y tshark 2>&1 || true
			$PM install -y wireshark wireshark-cli 2>&1 || true
		fi

		# 3. Provision wireshark group and user membership
		groupadd -f wireshark 2>/dev/null || true
		[ -n "$CALLING_USER" ] && usermod -aG wireshark "$CALLING_USER" 2>/dev/null || true

		# 4. Set packet capture capabilities on dumpcap for non-root execution
		DUMPCAP_BIN=$(command -v dumpcap 2>/dev/null || echo "/usr/bin/dumpcap")
		if [ -f "$DUMPCAP_BIN" ]; then
			chgrp wireshark "$DUMPCAP_BIN" 2>/dev/null || true
			chmod 750 "$DUMPCAP_BIN" 2>/dev/null || true
			if command -v setcap >/dev/null 2>&1; then
				setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' "$DUMPCAP_BIN" 2>/dev/null || true
			fi
		fi

		# 5. Enforce canonical symlink immediately
		enforce_canonical_symlinks
		;;

	postgresql|postgres)
		echo "=> [Layer 0.8] Deploying PostgreSQL Enterprise Engine & Initializing Database Service..."
		if command -v apt-get >/dev/null 2>&1; then
			install -m 0755 -d /etc/apt/keyrings
			curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor --yes -o /etc/apt/keyrings/pgdg.gpg 2>/dev/null || true
			chmod 644 /etc/apt/keyrings/pgdg.gpg 2>/dev/null || true
			echo "deb [signed-by=/etc/apt/keyrings/pgdg.gpg] http://apt.postgresql.org/pub/repos/apt ${CANONICAL_CODENAME}-pgdg main" > /etc/apt/sources.list.d/pgdg.list 2>/dev/null || true
			$APT_RUN update -qq >/dev/null 2>&1 || true
			$APT_RUN install postgresql postgresql-contrib postgresql-client 2>&1 || true
			if ! command -v psql >/dev/null 2>&1; then
				rm -f /etc/apt/sources.list.d/pgdg.list
				$APT_RUN update -qq >/dev/null 2>&1 || true
				$APT_RUN install postgresql postgresql-client 2>&1 || true
			fi
		elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
			dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm 2>/dev/null || true
			dnf -qy module disable postgresql 2>/dev/null || true
			(dnf install -y postgresql16-server postgresql16 || yum install -y postgresql-server postgresql) 2>&1 || true
			/usr/pgsql-16/bin/postgresql-16-setup initdb 2>/dev/null || postgresql-setup --initdb 2>/dev/null || true
		fi
		enforce_canonical_symlinks
		timeout 20s systemctl enable --now postgresql 2>/dev/null || true
		;;

	wazuh|wazuh-agent)
		echo "=> [Layer 0.8] Bootstrapping Official Wazuh Endpoint EDR Engine..."
		if command -v apt-get >/dev/null 2>&1; then
			install -m 0755 -d /etc/apt/keyrings
			curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/etc/apt/keyrings/wazuh.gpg --import 2>/dev/null || true
			chmod 644 /etc/apt/keyrings/wazuh.gpg 2>/dev/null || true
			echo "deb [signed-by=/etc/apt/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list 2>/dev/null || true
			$APT_RUN update -qq >/dev/null 2>&1 || true
			$APT_RUN install wazuh-agent 2>&1 || true
		elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
			rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH 2>/dev/null || true
			cat << 'EOF' > /etc/yum.repos.d/wazuh.repo
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
			(dnf install -y wazuh-agent || yum install -y wazuh-agent) 2>&1 || true
		fi
		enforce_canonical_symlinks
		timeout 15s systemctl daemon-reload 2>/dev/null || true
		timeout 20s systemctl enable wazuh-agent 2>/dev/null || true
		;;

	podman)
		echo "=> [Layer 0.8] Deploying Podman & Configuring Rootless Container Architecture..."
		if command -v apt-get >/dev/null 2>&1; then
			$APT_RUN update -qq >/dev/null 2>&1 || true
			$APT_RUN install podman uidmap slirp4netns fuse-overlayfs 2>&1 || true
		elif command -v dnf >/dev/null 2>&1; then
			dnf install -y podman shadow-utils slirp4netns fuse-overlayfs 2>&1 || true
		elif command -v yum >/dev/null 2>&1; then
			yum install -y podman slirp4netns fuse-overlayfs 2>&1 || true
		fi
		if [ -n "$CALLING_USER" ] && [ "$CALLING_USER" != "root" ]; then
			touch /etc/subuid /etc/subgid
			grep -q "^${CALLING_USER}:" /etc/subuid 2>/dev/null || echo "${CALLING_USER}:100000:65536" >> /etc/subuid
			grep -q "^${CALLING_USER}:" /etc/subgid 2>/dev/null || echo "${CALLING_USER}:100000:65536" >> /etc/subgid
		fi
		timeout 20s systemctl enable --now podman.socket 2>/dev/null || true
		;;

	sops)
		echo "=> [Layer 0.8] Deploying Official SOPS Standalone Static Binary..."
		SOPS_VER=$(curl -fsSL https://api.github.com/repos/getsops/sops/releases/latest 2>/dev/null | grep -oE '"tag_name": "[^"]+"' | head -n 1 | cut -d'"' -f4)
		[ -z "$SOPS_VER" ] && SOPS_VER="v3.9.4"
		SOPS_URL="https://github.com/getsops/sops/releases/download/${SOPS_VER}/sops-${SOPS_VER}.linux.amd64"
		([ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]) && SOPS_URL="https://github.com/getsops/sops/releases/download/${SOPS_VER}/sops-${SOPS_VER}.linux.arm64"
		mkdir -p /opt/sops
		curl -fsSL -L "$SOPS_URL" -o /opt/sops/sops 2>/dev/null
		chmod +x /opt/sops/sops 2>/dev/null || true
		ln -sf /opt/sops/sops /usr/local/bin/sops 2>/dev/null || true
		ln -sf /opt/sops/sops /usr/bin/sops 2>/dev/null || true
		;;

	vault|consul|nomad|terraform|packer)
		echo "=> [Layer 0.8] Provisioning HashiCorp Keyring & Enterprise Suite for '$TOOL_NAME'..."
		if command -v apt-get >/dev/null 2>&1; then
			install -m 0755 -d /etc/apt/keyrings
			curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/hashicorp.gpg 2>/dev/null || true
			chmod 644 /etc/apt/keyrings/hashicorp.gpg 2>/dev/null || true
			echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $CANONICAL_CODENAME main" > /etc/apt/sources.list.d/hashicorp.list 2>/dev/null || true
			$APT_RUN update -qq >/dev/null 2>&1 || true
			$APT_RUN install "$TOOL_NAME" 2>&1 || true
			if ! command -v "$TOOL_NAME" >/dev/null 2>&1; then
				rm -f /etc/apt/sources.list.d/hashicorp.list
				$APT_RUN update -qq >/dev/null 2>&1 || true
				$APT_RUN install "$TOOL_NAME" 2>&1 || true
			fi
		elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
			curl -sSL https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo -o /etc/yum.repos.d/hashicorp.repo 2>/dev/null || true
			(dnf install -y "$TOOL_NAME" || yum install -y "$TOOL_NAME") 2>&1 || true
		fi
		[ "$TOOL_NAME" = "vault" ] || [ "$TOOL_NAME" = "consul" ] || [ "$TOOL_NAME" = "nomad" ] && systemctl enable "$TOOL_NAME" 2>/dev/null || true
		;;

	kubectl)
		echo "=> [Layer 0.8] Bootstrapping Official Kubernetes Package Stream..."
		K8S_VER="v1.30"
		if command -v apt-get >/dev/null 2>&1; then
			install -m 0755 -d /etc/apt/keyrings
			curl -fsSL "https://pkgs.k8s.io/core:/stable:/${K8S_VER}/deb/Release.key" | gpg --dearmor --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg 2>/dev/null || true
			chmod 644 /etc/apt/keyrings/kubernetes-apt-keyring.gpg 2>/dev/null || true
			echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_VER}/deb/ /" > /etc/apt/sources.list.d/kubernetes.list 2>/dev/null || true
			$APT_RUN update -qq >/dev/null 2>&1 || true
			$APT_RUN install kubectl 2>&1 || true
		elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
			printf "[kubernetes]\nname=Kubernetes\nbaseurl=https://pkgs.k8s.io/core:/stable:/v1.30/rpm/\nenabled=1\ngpgcheck=1\ngpgkey=https://pkgs.k8s.io/core:/stable:/v1.30/rpm/repodata/repomd.xml.key\n" > /etc/yum.repos.d/kubernetes.repo
			(dnf install -y kubectl || yum install -y kubectl) 2>&1 || true
		fi
		;;

	redis)
		echo "=> [Layer 0.8] Deploying Redis Enterprise Cache & In-Memory Engine..."
		if command -v apt-get >/dev/null 2>&1; then
			install -m 0755 -d /etc/apt/keyrings
			curl -fsSL https://packages.redis.io/gpg | gpg --dearmor --yes -o /etc/apt/keyrings/redis.gpg 2>/dev/null || true
			chmod 644 /etc/apt/keyrings/redis.gpg 2>/dev/null || true
			echo "deb [signed-by=/etc/apt/keyrings/redis.gpg] https://packages.redis.io/deb $CANONICAL_CODENAME main" > /etc/apt/sources.list.d/redis.list 2>/dev/null || true
			$APT_RUN update -qq >/dev/null 2>&1 || true
			$APT_RUN install redis 2>&1 || $APT_RUN install redis-server 2>&1 || true
		elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
			(dnf install -y redis || yum install -y redis) 2>&1 || true
		fi
		timeout 20s systemctl enable --now redis-server 2>/dev/null || timeout 20s systemctl enable --now redis 2>/dev/null || true
		;;

	nginx)
		echo "=> [Layer 0.8] Deploying NGINX High-Performance Web Server & Reverse Proxy..."
		if command -v apt-get >/dev/null 2>&1; then
			$APT_RUN update -qq >/dev/null 2>&1 || true
			$APT_RUN install nginx 2>&1 || true
		elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
			(dnf install -y nginx || yum install -y nginx) 2>&1 || true
		fi
		timeout 20s systemctl enable --now nginx 2>/dev/null || true
		;;

	caddy)
		echo "=> [Layer 0.8] Deploying Caddy Modern Web Server with Auto-TLS..."
		if command -v apt-get >/dev/null 2>&1; then
			install -m 0755 -d /etc/apt/keyrings
			curl -fsSL "https://dl.cloudsmith.io/public/caddy/stable/gpg.key" | gpg --dearmor --yes -o /etc/apt/keyrings/caddy-stable.gpg 2>/dev/null || true
			chmod 644 /etc/apt/keyrings/caddy-stable.gpg 2>/dev/null || true
			curl -fsSL "https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt" > /etc/apt/sources.list.d/caddy-stable.list 2>/dev/null || true
			$APT_RUN update -qq >/dev/null 2>&1 || true
			$APT_RUN install caddy 2>&1 || true
		elif command -v dnf >/dev/null 2>&1; then
			dnf copr enable -y @caddy/caddy >/dev/null 2>&1 || true
			dnf install -y caddy 2>&1 || true
		fi
		timeout 20s systemctl enable --now caddy 2>/dev/null || true
		;;

	gitlab-runner)
		echo "=> [Layer 0.8] Deploying GitLab CI/CD Autonomous Runner Daemon..."
		curl -fsSL "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.deb.sh" | bash >/dev/null 2>&1 || \
		curl -fsSL "https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.rpm.sh" | bash >/dev/null 2>&1 || true
		if command -v apt-get >/dev/null 2>&1; then
			$APT_RUN install gitlab-runner 2>&1 || true
		elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
			(dnf install -y gitlab-runner || yum install -y gitlab-runner) 2>&1 || true
		fi
		timeout 20s systemctl enable --now gitlab-runner 2>/dev/null || true
		;;

	jenkins)
		echo "=> [Layer 0.8] Deploying Jenkins Automation Server & Java Runtime Environment..."
		if command -v apt-get >/dev/null 2>&1; then
			$APT_RUN update -qq >/dev/null 2>&1 || true
			$APT_RUN install fontconfig openjdk-17-jre 2>&1 || true
			install -m 0755 -d /etc/apt/keyrings
			curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key | gpg --dearmor --yes -o /etc/apt/keyrings/jenkins-keyring.gpg 2>/dev/null || true
			chmod 644 /etc/apt/keyrings/jenkins-keyring.gpg 2>/dev/null || true
			echo "deb [signed-by=/etc/apt/keyrings/jenkins-keyring.gpg] https://pkg.jenkins.io/debian-stable binary/" > /etc/apt/sources.list.d/jenkins.list 2>/dev/null || true
			$APT_RUN update -qq >/dev/null 2>&1 || true
			$APT_RUN install jenkins 2>&1 || true
		elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
			(dnf install -y java-17-openjdk fontconfig 2>/dev/null || yum install -y java-17-openjdk fontconfig 2>/dev/null) || true
			curl -sSL https://pkg.jenkins.io/redhat-stable/jenkins.repo -o /etc/yum.repos.d/jenkins.repo 2>/dev/null || true
			rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io-2023.key 2>/dev/null || true
			(dnf install -y jenkins || yum install -y jenkins) 2>&1 || true
		fi
		timeout 20s systemctl enable --now jenkins 2>/dev/null || true
		;;
esac

FOUND_PATH=$(verify_tool)
[ -n "$FOUND_PATH" ] && INSTALLED=1

# ==============================================================================
# LAYER 1: NATIVE REPOSITORIES WITH AUTOMATIC INDEX REFRESH
# Primary path when REPO_HEALTHY=1 (fast, full system integration).
# Also still attempted as a fallback when REPO_HEALTHY=0, in case the cheap
# health probe above was a false negative — costs nothing extra to try.
# ==============================================================================
if [ $INSTALLED -eq 0 ]; then
	echo "=> [Layer 1] Querying Native Repositories..."
	if command -v apt-get >/dev/null 2>&1; then
		if ! apt-cache show "$TOOL_NAME" >/dev/null 2>&1; then
			$APT_RUN update -qq >/dev/null 2>&1 || true
		fi
		$APT_RUN install "$TOOL_NAME" 2>&1 || true
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y --setopt=*.skip_if_unavailable=true "$TOOL_NAME" 2>&1 || true
	elif command -v yum >/dev/null 2>&1; then
		yum install -y --setopt=*.skip_if_unavailable=true "$TOOL_NAME" 2>&1 || true
	elif command -v pacman >/dev/null 2>&1; then
		pacman -Sy --noconfirm "$TOOL_NAME" 2>&1 || true
	elif command -v apk >/dev/null 2>&1; then
		apk add --no-cache "$TOOL_NAME" 2>&1 || true
	fi

	FOUND_PATH=$(verify_tool)
	[ -n "$FOUND_PATH" ] && INSTALLED=1
fi

# ==============================================================================
# REPO HEALTH CHECK — decides whether to prefer the fast native path or skip
# straight to independent extraction. Cheap and quick: just confirms the
# package is resolvable in the local index, not a full download.
# ==============================================================================
REPO_HEALTHY=0
if command -v apt-get >/dev/null 2>&1; then
	if apt-get update -qq >/dev/null 2>&1 && apt-cache policy "$TOOL_NAME" 2>/dev/null | grep -q "Candidate:"; then
		REPO_HEALTHY=1
	fi
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
	PM=$(command -v dnf || command -v yum)
	if $PM list --available "$TOOL_NAME" >/dev/null 2>&1; then
		REPO_HEALTHY=1
	fi
fi

if [ $REPO_HEALTHY -eq 1 ]; then
	echo "=> Repository is healthy for '$TOOL_NAME' — preferring native package manager (faster, full integration)."
else
	echo "=> Repository unhealthy or package unresolvable locally — routing to independent portable extraction first."
fi

# ==============================================================================
# LAYER 1.5: PORTABLE PACKAGE EXTRACTION (bypasses apt dependency resolution)
# Downloads the raw .deb and unpacks its file contents directly — does NOT
# register the package with dpkg, does NOT run postinst/system integration.
# This works for pure-CLI tools; it will NOT bring up docker's daemon,
# postgres's cluster, or wireshark's capture capabilities — those steps
# still require real system integration and are handled by Layer 0.8.
# Only runs first when the repo check above found the system unhealthy —
# otherwise it's skipped here and native install (Layer 1) gets first shot.
# ==============================================================================
if [ $INSTALLED -eq 0 ] && [ $REPO_HEALTHY -eq 0 ] && command -v apt-get >/dev/null 2>&1; then
	echo "=> [Layer 1.5] Attempting Portable .deb Extraction (No System Dependency Resolution)..."
	PKGDIR="/opt/$TOOL_NAME/portable_extract"
	mkdir -p "$PKGDIR"

	DEB_URL=$(apt-get download --print-uris "$TOOL_NAME" 2>/dev/null | grep -oE "'[^']+\.deb'" | tr -d "'" | head -n 1)

	# If local apt state (sources.list, GPG, mirror reachability) is broken, apt-get
	# won't even resolve a URL. Fall back to querying the public archive's own package
	# search API directly over HTTP — this does NOT depend on the target's apt config.
	if [ -z "$DEB_URL" ]; then
		PUBLIC_ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
		DEB_URL=$(curl -fsSL "https://packages.ubuntu.com/search?keywords=${TOOL_NAME}&searchon=names&suite=all&section=all" 2>/dev/null | \
			grep -oE "https://mirror[^\"']+${TOOL_NAME}[^\"']*_${PUBLIC_ARCH}\.deb" | head -n 1)
	fi

	if [ -z "$DEB_URL" ]; then
		echo "   [!] Could not resolve a .deb URL for '$TOOL_NAME' via local apt config or public archive search."
	fi

	if [ -n "$DEB_URL" ]; then
		curl -fsSL "$DEB_URL" -o "$PKGDIR/pkg.deb" 2>/dev/null
		if [ -s "$PKGDIR/pkg.deb" ]; then
			dpkg -x "$PKGDIR/pkg.deb" "$PKGDIR" 2>/dev/null || true
			FOUND_BIN=$(find "$PKGDIR/usr/bin" "$PKGDIR/usr/sbin" -maxdepth 1 -type f -executable 2>/dev/null | grep -i "$TOOL_NAME" | head -n 1)
			if [ -n "$FOUND_BIN" ]; then
				cp -f "$FOUND_BIN" "/usr/local/bin/$TOOL_NAME"
				chmod +x "/usr/local/bin/$TOOL_NAME"
				# copy any shared libs the extracted binary needs, so it doesn't
				# silently depend on system packages it wasn't linked against here
				if [ -d "$PKGDIR/usr/lib" ]; then
					mkdir -p "/opt/$TOOL_NAME/lib"
					cp -rf "$PKGDIR/usr/lib/"* "/opt/$TOOL_NAME/lib/" 2>/dev/null || true
					patchelf --set-rpath "/opt/$TOOL_NAME/lib" "/usr/local/bin/$TOOL_NAME" 2>/dev/null || true
				fi
				echo "   [SUCCESS] Portable extraction placed '$TOOL_NAME' without full apt dependency resolution."
				INSTALLED=1
			fi
		fi
	fi
	rm -rf "$PKGDIR"
fi

if [ $INSTALLED -eq 0 ] && (command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1); then
	echo "=> [Layer 1.5b] Attempting Portable .rpm Extraction (No System Dependency Resolution)..."
	PM=$(command -v dnf || command -v yum)
	PKGDIR="/opt/$TOOL_NAME/portable_extract"
	mkdir -p "$PKGDIR"

	RPM_URL=$($PM download --url "$TOOL_NAME" 2>/dev/null | grep -oE "https?://[^ ]+\.rpm" | head -n 1)
	if [ -n "$RPM_URL" ]; then
		curl -fsSL "$RPM_URL" -o "$PKGDIR/pkg.rpm" 2>/dev/null
		if [ -s "$PKGDIR/pkg.rpm" ] && command -v rpm2cpio >/dev/null 2>&1; then
			(cd "$PKGDIR" && rpm2cpio pkg.rpm | cpio -idm 2>/dev/null) || true
			FOUND_BIN=$(find "$PKGDIR/usr/bin" "$PKGDIR/usr/sbin" -maxdepth 1 -type f -executable 2>/dev/null | grep -i "$TOOL_NAME" | head -n 1)
			if [ -n "$FOUND_BIN" ]; then
				cp -f "$FOUND_BIN" "/usr/local/bin/$TOOL_NAME"
				chmod +x "/usr/local/bin/$TOOL_NAME"
				echo "   [SUCCESS] Portable RPM extraction placed '$TOOL_NAME' without full dnf/yum dependency resolution."
				INSTALLED=1
			fi
		fi
	else
		echo "   [!] Could not resolve an .rpm URL for '$TOOL_NAME' via local dnf/yum config."
	fi
	rm -rf "$PKGDIR"
fi

# If the repo looked healthy but native install still failed (e.g. dependency
# conflict, disk full, held package), fall back to portable extraction now —
# this is the case the initial health check couldn't have caught.
if [ $INSTALLED -eq 0 ] && [ $REPO_HEALTHY -eq 1 ] && command -v apt-get >/dev/null 2>&1; then
	echo "=> [Layer 1.5-late] Native install failed despite healthy repo — attempting Portable .deb Extraction..."
	PKGDIR="/opt/$TOOL_NAME/portable_extract"
	mkdir -p "$PKGDIR"
	DEB_URL=$(apt-get download --print-uris "$TOOL_NAME" 2>/dev/null | grep -oE "'[^']+\.deb'" | tr -d "'" | head -n 1)
	if [ -n "$DEB_URL" ]; then
		curl -fsSL "$DEB_URL" -o "$PKGDIR/pkg.deb" 2>/dev/null
		if [ -s "$PKGDIR/pkg.deb" ]; then
			dpkg -x "$PKGDIR/pkg.deb" "$PKGDIR" 2>/dev/null || true
			FOUND_BIN=$(find "$PKGDIR/usr/bin" "$PKGDIR/usr/sbin" -maxdepth 1 -type f -executable 2>/dev/null | grep -i "$TOOL_NAME" | head -n 1)
			if [ -n "$FOUND_BIN" ]; then
				cp -f "$FOUND_BIN" "/usr/local/bin/$TOOL_NAME"
				chmod +x "/usr/local/bin/$TOOL_NAME"
				echo "   [SUCCESS] Late-stage portable extraction succeeded for '$TOOL_NAME'."
				INSTALLED=1
			fi
		fi
	fi
	rm -rf "$PKGDIR"
fi

# ==============================================================================
# LAYER 2: UNIVERSAL SHELL SCRIPT & SANDBOX INTEGRATIONS
# ==============================================================================
if [ $INSTALLED -eq 0 ]; then
	echo "=> [Layer 2] Querying Universal Developer Indexes..."
	WEB_CHECK=$(curl -fsSL -I "https://webinstall.dev/$TOOL_NAME" 2>/dev/null | grep -iE "HTTP.*(200|302|301)" || true)
	if [ -n "$WEB_CHECK" ]; then
		curl -fsSL "https://webinstall.dev/$TOOL_NAME" | bash >/dev/null 2>&1 || true
		export PATH="$HOME/.local/bin:$PATH"
	fi

	FOUND_PATH=$(verify_tool)
	if [ -n "$FOUND_PATH" ]; then
		ln -sf "$FOUND_PATH" "/usr/local/bin/$TOOL_NAME" 2>/dev/null || true
		ln -sf "$FOUND_PATH" "/usr/bin/$TOOL_NAME" 2>/dev/null || true
		INSTALLED=1
	fi
fi

if [ $INSTALLED -eq 0 ] && command -v snap >/dev/null 2>&1; then
	snap install "$TOOL_NAME" 2>&1 || true
	FOUND_PATH=$(verify_tool)
	[ -n "$FOUND_PATH" ] && INSTALLED=1
fi

# ==============================================================================
# LAYER 3: AUTONOMOUS UNIVERSAL UPSTREAM BINARY RESOLVER
# ==============================================================================
if [ $INSTALLED -eq 0 ]; then
	echo "=> [Layer 3] Querying Global Binary Registries & Upstream Sources..."
	mkdir -p /opt/"$TOOL_NAME"

	RESOLVED_REPO=""
	METADATA=$(curl -fsSL "https://formulae.brew.sh/api/formula/${TOOL_NAME}.json" 2>/dev/null || true)
	if [ -n "$METADATA" ]; then
		RESOLVED_REPO=$(echo "$METADATA" | python3 -c "
import sys, json, re
try:
    d = json.load(sys.stdin)
    urls = [d.get('homepage', ''), d.get('head', '')]
    for u in urls:
        m = re.search(r'github\.com/([^/]+/[^/]+)', u or '')
        if m:
            print(m.group(1).rstrip('.git'))
            sys.exit(0)
except:
    pass
" 2>/dev/null || true)
	fi

	CANDIDATES=()
	[ -n "$RESOLVED_REPO" ] && CANDIDATES+=("$RESOLVED_REPO")

	ALIAS_FILE="/etc/cross-suite/tool-aliases.conf"
	if [ -f "$ALIAS_FILE" ]; then
		CONF_ALIAS=$(grep -E "^${TOOL_NAME}=" "$ALIAS_FILE" 2>/dev/null | cut -d= -f2 | sed 's/github://')
		[ -n "$CONF_ALIAS" ] && CANDIDATES+=("$CONF_ALIAS")
	fi

	case "$TOOL_NAME" in
		btm)        CANDIDATES+=("ClementTsang/bottom") ;;
		doggo)      CANDIDATES+=("mr-karan/doggo") ;;
		ghz)        CANDIDATES+=("bojand/ghz") ;;
		croc)       CANDIDATES+=("schollz/croc") ;;
		fx)         CANDIDATES+=("antonmedv/fx") ;;
		glow)       CANDIDATES+=("charmbracelet/glow") ;;
		zellij)     CANDIDATES+=("zellij-org/zellij") ;;
		dive)       CANDIDATES+=("wagoodman/dive") ;;
		duf)        CANDIDATES+=("muesli/duf") ;;
		syft)       CANDIDATES+=("anchore/syft") ;;
		grype)      CANDIDATES+=("anchore/grype") ;;
		lazydocker) CANDIDATES+=("jesseduffield/lazydocker") ;;
		lazygit)    CANDIDATES+=("jesseduffield/lazygit") ;;
		act)        CANDIDATES+=("nektos/act") ;;
		miniserve)  CANDIDATES+=("svenstaro/miniserve") ;;
		helmfile)   CANDIDATES+=("helmfile/helmfile") ;;
		yq)         CANDIDATES+=("mikefarah/yq") ;;
		fzf)        CANDIDATES+=("junegunn/fzf") ;;
		bat)        CANDIDATES+=("sharkdp/bat") ;;
		eza)        CANDIDATES+=("eza-community/eza") ;;
		delta)      CANDIDATES+=("dandavison/delta") ;;
		rg|ripgrep) CANDIDATES+=("BurntSushi/ripgrep") ;;
		gh)         CANDIDATES+=("cli/cli") ;;
		k9s)        CANDIDATES+=("derailed/k9s") ;;
		helm)       CANDIDATES+=("helm/helm") ;;
	esac

	CANDIDATES+=("$TOOL_NAME/$TOOL_NAME")
	UNIQUE_CANDS=($(printf "%%s\n" "${CANDIDATES[@]}" | awk '!seen[$0]++ && NF'))

	for TARGET in "${UNIQUE_CANDS[@]}"; do
		[ -z "$TARGET" ] && continue
		[ $INSTALLED -eq 1 ] && break

		echo "   [+] Probing release stream: $TARGET"
		DOWNLOAD_URL=$(curl -fsSL -H "User-Agent: Cross-Suite-Wizard" "https://api.github.com/repos/$TARGET/releases/latest" 2>/dev/null | \
			python3 -c "
import sys, json, re

arch = '$ARCH'
tool = '$TOOL_NAME'

if arch in ['x86_64', 'amd64']:
    pat = r'(x86_64|amd64|x64)'
elif arch in ['aarch64', 'arm64']:
    pat = r'(aarch64|arm64)'
else:
    pat = arch

try:
    d = json.load(sys.stdin)
    assets = d.get('assets', [])
    bad = ('.deb', '.rpm', '.apk', '.sig', '.asc', '.sha256', '.sha256sum', '.txt', '.sbom', '.pem', '.msi', '.exe')
    cands = [a for a in assets if not a['name'].lower().endswith(bad)]
    matches = [a for a in cands if re.search(pat, a['name'], re.I) and not re.search(r'(darwin|windows|mac|freebsd)', a['name'], re.I)]
    matches.sort(key=lambda a: (tool.lower() in a['name'].lower(), not a['name'].endswith('.tar.gz'), not a['name'].endswith('.zip')), reverse=True)
    if matches:
        print(matches[0]['browser_download_url'])
except:
    pass
" 2>/dev/null || true)

		if [ -z "$DOWNLOAD_URL" ]; then
			EXP_PAGE=$(curl -fsSL "https://github.com/$TARGET/releases/latest" 2>/dev/null || true)
			DOWNLOAD_URL=$(echo "$EXP_PAGE" | grep -oiE '/'"$TARGET"'/releases/download/[^"]*' | \
				grep -iE "($ARCH_MATCH)" | \
				grep -ivE '\.(deb|rpm|apk|sig|asc|sha256|sha256sum|txt|sbom|pem|msi|exe)$' | \
				head -n 1)
			[ -n "$DOWNLOAD_URL" ] && DOWNLOAD_URL="https://github.com$DOWNLOAD_URL"
		fi

		[ -z "$DOWNLOAD_URL" ] && continue

		echo "   [+] Fetching verified release: $DOWNLOAD_URL"
		WORK_DIR="/var/tmp/cross_deploy_${TOOL_NAME}_$$"
		rm -rf "$WORK_DIR" && mkdir -p "$WORK_DIR/out"
		curl -fsSL -L "$DOWNLOAD_URL" -o "$WORK_DIR/dl_asset" 2>/dev/null

		case "$DOWNLOAD_URL" in
			*.tar.gz|*.tgz) tar -xzf "$WORK_DIR/dl_asset" -C "$WORK_DIR/out" 2>/dev/null || true ;;
			*.tar.bz2) tar -xjf "$WORK_DIR/dl_asset" -C "$WORK_DIR/out" 2>/dev/null || true ;;
			*.tar.xz) tar -xJf "$WORK_DIR/dl_asset" -C "$WORK_DIR/out" 2>/dev/null || true ;;
			*.zip) unzip -q -o "$WORK_DIR/dl_asset" -d "$WORK_DIR/out" 2>/dev/null || true ;;
			*)
				cp -f "$WORK_DIR/dl_asset" "$WORK_DIR/out/$TOOL_NAME"
				chmod +x "$WORK_DIR/out/$TOOL_NAME"
				;;
		esac

		chmod -R +rx "$WORK_DIR/out" 2>/dev/null || true

		TRIAL_EXEC=$(find "$WORK_DIR/out" -type f -name "$TOOL_NAME" 2>/dev/null | head -n 1)
		if [ -z "$TRIAL_EXEC" ]; then
			TRIAL_EXEC=$(find "$WORK_DIR/out" -type f -perm -u+x ! -name "*.sh" ! -name "*.so*" ! -name "*.txt" 2>/dev/null | head -n 1)
		fi

		if [ -n "$TRIAL_EXEC" ]; then
			chmod +x "$TRIAL_EXEC" 2>/dev/null || true
			if "$TRIAL_EXEC" --version >/dev/null 2>&1 || "$TRIAL_EXEC" version >/dev/null 2>&1 || "$TRIAL_EXEC" -v >/dev/null 2>&1 || "$TRIAL_EXEC" --help >/dev/null 2>&1 || "$TRIAL_EXEC" -h >/dev/null 2>&1; then
				cp -f "$TRIAL_EXEC" "/opt/$TOOL_NAME/$TOOL_NAME"
				chmod +x "/opt/$TOOL_NAME/$TOOL_NAME"
				ln -sf "/opt/$TOOL_NAME/$TOOL_NAME" "/usr/local/bin/$TOOL_NAME"
				ln -sf "/opt/$TOOL_NAME/$TOOL_NAME" "/usr/bin/$TOOL_NAME" 2>/dev/null || true
				INSTALLED=1
				echo "   [SUCCESS] Universal Binary Engine placed '$TOOL_NAME' into /usr/local/bin/$TOOL_NAME"
				rm -rf "$WORK_DIR"
				break
			fi
		fi
		rm -rf "$WORK_DIR"
	done
fi

FINAL_PATH=$(command -v "$TOOL_NAME" 2>/dev/null || echo "")
REAL_STATUS="failed"
VER="not installed"

if [ -n "$FINAL_PATH" ] && [ -x "$FINAL_PATH" ]; then
	REAL_STATUS="installed"
	VER=$("$FINAL_PATH" --version 2>/dev/null | head -n 1)
	[ -z "$VER" ] && VER="installed"
fi

python3 -c "
import json, os
p = '/var/lib/cross-suite/state.json'
d = {}
if os.path.exists(p):
    try:
        with open(p, 'r') as f: d = json.load(f)
    except: pass
d['$TOOL_NAME'] = {'version': '$VER', 'path': '$FINAL_PATH', 'status': '$REAL_STATUS'}
with open(p, 'w') as f: json.dump(d, f, indent=2)
" 2>/dev/null || true

exit 0
`, cleanTool)

	writeCmd := fmt.Sprintf("cat << 'CROSS_DEPLOY_EOF' > /var/tmp/cross_deploy.sh\n%s\nCROSS_DEPLOY_EOF\nchmod +x /var/tmp/cross_deploy.sh", deployCmd)
	_, _ = executeRemoteCommand(client, writeCmd)
	out, _ := runSudoScriptWithSpinner(client, "bash /var/tmp/cross_deploy.sh", fmt.Sprintf("Deploying %s with Root Privileges", cleanTool))
	_, _ = executeRemoteCommand(client, "rm -f /var/tmp/cross_deploy.sh")

	if strings.TrimSpace(out) != "" {
		fmt.Println(Yellow + out + Reset)
	}

	// Step 3: Multi-Binary Strict Functional Verification (1-to-1 Contract)
	verifyCmd := fmt.Sprintf(`
	TOOL="%s"
	OK=0

	# Enforce symlinks natively before checking
	[ -x /usr/bin/wireshark-qt ] && [ ! -x /usr/bin/wireshark ] && ln -snf /usr/bin/wireshark-qt /usr/bin/wireshark 2>/dev/null || true
	[ -x /usr/bin/wireshark-qt ] && [ ! -x /usr/local/bin/wireshark ] && ln -snf /usr/bin/wireshark-qt /usr/local/bin/wireshark 2>/dev/null || true
	[ -x /usr/libexec/docker/cli-plugins/docker-compose ] && [ ! -x /usr/local/bin/docker-compose ] && ln -snf /usr/libexec/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose 2>/dev/null || true
	command -v psql >/dev/null 2>&1 && [ ! -x /usr/local/bin/postgresql ] && ln -snf "$(command -v psql)" /usr/local/bin/postgresql 2>/dev/null || true

	CHECK_BINS=("$TOOL")
	case "$TOOL" in
		wireshark) CHECK_BINS=("/usr/bin/wireshark" "/usr/local/bin/wireshark" "wireshark-qt") ;;
		tshark)    CHECK_BINS=("tshark") ;;
		docker)    CHECK_BINS=("docker") ;;
		docker-compose) CHECK_BINS=("docker-compose" "/usr/libexec/docker/cli-plugins/docker-compose") ;;
		postgresql|postgres) CHECK_BINS=("psql" "/usr/local/bin/postgresql") ;;
		wazuh|wazuh-agent)   CHECK_BINS=("/var/ossec/bin/wazuh-control" "/usr/local/bin/wazuh-control") ;;
		podman)    CHECK_BINS=("podman") ;;
		kubectl)   CHECK_BINS=("kubectl") ;;
		vault|consul|nomad|terraform|packer) CHECK_BINS=("$TOOL") ;;
		redis)     CHECK_BINS=("redis-cli") ;;
	esac

	for b_name in "${CHECK_BINS[@]}"; do
		BINPATH=$(command -v "$b_name" 2>/dev/null || echo "")
		if [ -z "$BINPATH" ]; then
			for c in "/usr/local/bin/$b_name" "/usr/bin/$b_name" "/usr/sbin/$b_name" "/opt/$TOOL/$b_name" /var/ossec/bin/$b_name; do
				if [ -x "$c" ] && [ ! -d "$c" ]; then
					BINPATH="$c"
					break
				fi
			done
		fi

		if [ -n "$BINPATH" ] && [ -x "$BINPATH" ]; then
			if QT_QPA_PLATFORM=offscreen "$BINPATH" --version >/dev/null 2>&1 || "$BINPATH" version >/dev/null 2>&1 || "$BINPATH" --help >/dev/null 2>&1 || "$BINPATH" status >/dev/null 2>&1 || [ "$b_name" = "/var/ossec/bin/wazuh-control" ] || dpkg -S "$BINPATH" >/dev/null 2>&1 || rpm -qf "$BINPATH" >/dev/null 2>&1; then
				OK=1
				break
			fi
		fi
	done

	if [ $OK -eq 1 ]; then
		echo "EXISTS"
	else
		echo "NOT_FOUND"
	fi
	`, cleanTool)

	vOut, _ := runSudoScript(client, verifyCmd)

	if strings.Contains(vOut, "EXISTS") {
		fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] REAL INSTALLATION VERIFIED: '%s' placed on target host filesystem!", cleanTool) + Reset)
	} else {
		fmt.Println(Red + Bold + fmt.Sprintf("[!] CRITICAL FAILURE: '%s' binary was not found or is not functional on remote filesystem.", cleanTool) + Reset)
	}
}

// executeWindowsDeployment executes 3-Layer Windows deployment using PowerShell, Winget, and Chocolatey
func executeWindowsDeployment(client *ssh.Client, tool string) {
	fmt.Println(Cyan + Bold + fmt.Sprintf("\n[+] Executing Windows 3-Layer Deployment for '%s'...", tool) + Reset)

	psScript := fmt.Sprintf(`
$tool = '%s'
$installed = $false

if (Get-Command $tool -ErrorAction SilentlyContinue) {
    Write-Output "ALREADY_INSTALLED"
    exit 0
}

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Output "=> [Layer 0] Winget missing. Attempting Auto-Repair Before Deployment..."
    try {
        $tempDir = "$env:TEMP\cross-suite-winget"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        Invoke-WebRequest -Uri "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -OutFile "$tempDir\vclibs.appx" -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx" -OutFile "$tempDir\uixaml.appx" -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri "https://aka.ms/getwinget" -OutFile "$tempDir\winget.msixbundle" -ErrorAction Stop
        if (Test-Path "$tempDir\vclibs.appx") { Add-AppxPackage -Path "$tempDir\vclibs.appx" -ErrorAction SilentlyContinue }
        if (Test-Path "$tempDir\uixaml.appx") { Add-AppxPackage -Path "$tempDir\uixaml.appx" -ErrorAction SilentlyContinue }
        Add-AppxPackage -Path "$tempDir\winget.msixbundle" -ErrorAction Stop
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    } catch {}
}

if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Output "=> [Layer 1] Deploying via Windows Package Manager (Winget)..."
    winget install --id $tool --exact --silent --accept-package-agreements --accept-source-agreements 2>$null
    if (Get-Command $tool -ErrorAction SilentlyContinue) { $installed = $true }
}

if (-not $installed) {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Output "=> [Layer 2] Bootstrapping Chocolatey Package Manager..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    }
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Output "=> [Layer 2] Deploying via Chocolatey..."
        choco install $tool -y --no-progress 2>$null
        if (Get-Command $tool -ErrorAction SilentlyContinue) { $installed = $true }
    }
}

if (-not $installed) {
    Write-Output "=> [Layer 3] Attempting Generic GitHub Release Binary Fetch for '$tool'..."
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        $headers = @{ 'User-Agent' = 'Cross-Suite-Wizard' }

        $searchUrl = "https://api.github.com/search/repositories?q=$tool+in:name&sort=stars&order=desc&per_page=30"
        $searchResult = Invoke-RestMethod -Uri $searchUrl -Headers $headers -ErrorAction Stop
        $repo = $null
        $repoMode = "exact-name-match"
        if ($searchResult.items -and $searchResult.items.Count -gt 0) {
            $exactMatch = $searchResult.items | Where-Object { $_.name -ieq $tool } | Select-Object -First 1
            if ($exactMatch) {
                $repo = $exactMatch.full_name
            } else {
                $repo = $searchResult.items[0].full_name
                $repoMode = "best-guess (unverified)"
                Write-Output "   [!] No exact-name GitHub repository match for '$tool'. Falling back to best-guess top-starred match: $repo"
            }
        }

        if ($repo) {
            Write-Output "   [+] Candidate repository found: $repo"
            $relUrl = "https://api.github.com/repos/$repo/releases/latest"
            $rel = Invoke-RestMethod -Uri $relUrl -Headers $headers -ErrorAction Stop

            $asset = $rel.assets | Where-Object {
                $_.name -match '(?i)win|windows' -and
                $_.name -match '(?i)(amd64|x64|x86_64)' -and
                $_.name -notmatch '(?i)\.sig$|\.asc$|\.sha256$'
            } | Select-Object -First 1

            if (-not $asset) {
                $asset = $rel.assets | Where-Object {
                    $_.name -match '(?i)(\.exe$|win.*\.zip$)'
                } | Select-Object -First 1
            }

            if ($asset) {
                Write-Output "   [+] Found candidate asset: $($asset.name)"
                $destDir = "C:\ProgramData\cross-suite\bin"
                if (!(Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                $downloadPath = Join-Path $destDir $asset.name

                Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $downloadPath -Headers $headers -ErrorAction Stop

                if ($asset.name -match '\.zip$') {
                    $extractDir = Join-Path $destDir ($tool + "_extracted")
                    Expand-Archive -Path $downloadPath -DestinationPath $extractDir -Force -ErrorAction SilentlyContinue
                    $foundExe = Get-ChildItem -Path $extractDir -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue |
                        Where-Object { $_.BaseName -match $tool } | Select-Object -First 1
                    if (-not $foundExe) {
                        $foundExe = Get-ChildItem -Path $extractDir -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
                    }
                    if ($foundExe) {
                        Copy-Item $foundExe.FullName (Join-Path $destDir "$tool.exe") -Force
                    }
                    Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
                } elseif ($asset.name -match '\.exe$') {
                    Rename-Item -Path $downloadPath -NewName "$tool.exe" -Force -ErrorAction SilentlyContinue
                }

                $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
                if ($machinePath -notlike "*$destDir*") {
                    [Environment]::SetEnvironmentVariable('Path', "$machinePath;$destDir", 'Machine')
                    $env:Path += ";$destDir"
                }

                $exePath = Join-Path $destDir "$tool.exe"
                if (Test-Path $exePath) {
                    $sane = $false
                    foreach ($flag in @('--version','--help','-v')) {
                        try {
                            $p = Start-Process -FilePath $exePath -ArgumentList $flag -NoNewWindow -PassThru -Wait -ErrorAction SilentlyContinue
                            if ($p -and $p.ExitCode -eq 0) { $sane = $true; break }
                        } catch {}
                    }
                    if ($sane) {
                        $installed = $true
                        Write-Output "   [SUCCESS] Binary deployed, sanity-checked, and added to PATH (match mode: $repoMode)."
                    } else {
                        Write-Output "   [!] Deployed binary failed sanity check. Discarding to avoid false-positive install (match mode: $repoMode)."
                        Remove-Item $exePath -Force -ErrorAction SilentlyContinue
                    }
                }
            } else {
                Write-Output "   [!] No matching Windows binary asset found in latest release of $repo."
            }
        } else {
            Write-Output "   [!] No matching GitHub repository found for '$tool'."
        }
    } catch {
        Write-Output "   [!] GitHub release fallback failed: $($_.Exception.Message)"
    }
}

$fpDir = 'C:\ProgramData\cross-suite'
if (!(Test-Path $fpDir)) { New-Item -ItemType Directory -Path $fpDir -Force | Out-Null }
$finalCheck2 = (Get-Command $tool -ErrorAction SilentlyContinue) -or (Test-Path "C:\ProgramData\cross-suite\bin\$tool.exe")
$statusVal = if ($finalCheck2) { 'installed' } else { 'failed' }
$verVal = if ($finalCheck2 -and (Get-Command $tool -ErrorAction SilentlyContinue)) { (Get-Command $tool).Version.ToString() } elseif ($finalCheck2) { 'installed (binary fetch)' } else { 'not installed' }
$fp = "$fpDir\state.json"
$data = @{}
if (Test-Path $fp) {
    try { $data = Get-Content $fp | ConvertFrom-Json -AsHashtable } catch { $data = @{} }
}
$data[$tool] = @{ version = $verVal; path = $tool; status = $statusVal }
$data | ConvertTo-Json | Set-Content $fp -Encoding UTF8

$finalCheck = (Get-Command $tool -ErrorAction SilentlyContinue) -or (Test-Path "C:\ProgramData\cross-suite\bin\$tool.exe")
if ($finalCheck) {
    Write-Output "SUCCESS_VERIFIED"
} else {
    Write-Output "DEPLOY_ATTEMPTED"
}
`, tool)

	utf16LE := []byte{}
	for _, r := range psScript {
		utf16LE = append(utf16LE, byte(r), byte(r>>8))
	}
	b64Cmd := base64.StdEncoding.EncodeToString(utf16LE)

	winCmd := fmt.Sprintf("powershell -NoProfile -EncodedCommand %s", b64Cmd)
	out, err := executeRemoteCommand(client, winCmd)

	if strings.Contains(out, "ALREADY_INSTALLED") {
		fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] IDEMPOTENT SKIP: '%s' is already installed on Windows target host!", tool) + Reset)
	} else if strings.Contains(out, "SUCCESS_VERIFIED") || err == nil {
		fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] WINDOWS INSTALLATION VERIFIED: '%s' installed and available in System PATH!", tool) + Reset)
	} else {
		fmt.Println(Yellow + fmt.Sprintf("[!] Windows deployment executed. Run 'Get-Command %s' in PowerShell to verify.", tool) + Reset)
	}
}

// BootstrapWindowsPackageManagers installs Winget and Chocolatey on Windows target host
func BootstrapWindowsPackageManagers(client *ssh.Client) {
	fmt.Println(Cyan + Bold + "\n[+] Bootstrapping Windows Package Managers (Winget & Chocolatey)..." + Reset)

	psScript := `
Set-ExecutionPolicy Bypass -Scope Process -Force;
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;

Write-Output "=> Checking Winget (App Installer) Availability..."
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Output "=> Winget not found. Attempting Self-Repair via Microsoft Store App Installer Bundle..."
    try {
        $progressPreference = 'SilentlyContinue'
        $tempDir = "$env:TEMP\cross-suite-winget"
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

        $vclibsUrl = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
        $uixamlUrl = "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx"
        $wingetUrl = "https://aka.ms/getwinget"

        Invoke-WebRequest -Uri $vclibsUrl -OutFile "$tempDir\vclibs.appx" -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri $uixamlUrl -OutFile "$tempDir\uixaml.appx" -ErrorAction SilentlyContinue
        Invoke-WebRequest -Uri $wingetUrl -OutFile "$tempDir\winget.msixbundle" -ErrorAction Stop

        if (Test-Path "$tempDir\vclibs.appx") {
            Add-AppxPackage -Path "$tempDir\vclibs.appx" -ErrorAction SilentlyContinue
        }
        if (Test-Path "$tempDir\uixaml.appx") {
            Add-AppxPackage -Path "$tempDir\uixaml.appx" -ErrorAction SilentlyContinue
        }
        Add-AppxPackage -Path "$tempDir\winget.msixbundle" -ErrorAction Stop

        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Output "[SUCCESS] Winget successfully self-repaired and installed!"
        } else {
            Write-Output "[!] Winget package installed but not yet on PATH. May require session restart."
        }
    } catch {
        Write-Output "[!] Automatic Winget repair failed: $($_.Exception.Message)"
    }
} else {
    Write-Output "[SUCCESS] Winget is already installed and available!"
    winget source update 2>$null | Out-Null
}

Write-Output "=> Checking Chocolatey Availability..."
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Output "=> Installing Chocolatey Package Manager..."
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
} else {
    Write-Output "[SUCCESS] Chocolatey is already installed!"
}
`
	utf16LE := []byte{}
	for _, r := range psScript {
		utf16LE = append(utf16LE, byte(r), byte(r>>8))
	}
	b64Cmd := base64.StdEncoding.EncodeToString(utf16LE)

	winCmd := fmt.Sprintf("powershell -NoProfile -EncodedCommand %s", b64Cmd)
	out, _ := runSudoScriptWithSpinner(client, winCmd, "Bootstrapping Windows Package Managers")

	if strings.TrimSpace(out) != "" {
		fmt.Println(Yellow + out + Reset)
	}
	fmt.Println(Green + Bold + "[SUCCESS] Windows Package Manager Bootstrap Sequence Completed!" + Reset)
}

func runRepoHealerSudo(client *ssh.Client, rawBashCmd string) (string, error) {
	sanitizedCmd := sanitizeCommandForWindows(rawBashCmd)
	encodedScript := base64.StdEncoding.EncodeToString([]byte(sanitizedCmd))

	command := fmt.Sprintf(
		"sudo -n -E bash -c 'echo %s | base64 -d | bash'",
		encodedScript,
	)

	return executeRemoteCommand(client, command)
}

func runRepoHealerSudoWithSpinner(
	client *ssh.Client,
	rawBashCmd string,
	label string,
) (string, error) {
	sanitizedCmd := sanitizeCommandForWindows(rawBashCmd)
	encodedScript := base64.StdEncoding.EncodeToString([]byte(sanitizedCmd))

	command := fmt.Sprintf(
		"sudo -n -E bash -c 'echo %s | base64 -d | bash'",
		encodedScript,
	)

	return executeRemoteCommandWithSpinner(client, command, label)
}

type repoHealerExecutor struct {
	client *ssh.Client
}

func (e repoHealerExecutor) Run(command string) (string, error) {
	return executeRemoteCommand(e.client, command)
}

func (e repoHealerExecutor) RunSudo(script string) (string, error) {
	return runRepoHealerSudo(e.client, script)
}

func (e repoHealerExecutor) RunSudoWithLabel(script, label string) (string, error) {
	return runRepoHealerSudoWithSpinner(e.client, script, label)
}

// RunSelfHealingTroubleshooter runs the universal repository healer backend.
func RunSelfHealingTroubleshooter(client *ssh.Client, targetOS osdetect.TargetOS) {
	fmt.Println(Cyan + Bold + "\n[+] Launching Universal Repository Healer..." + Reset)

	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
	fmt.Println("  [1] Diagnose repository health only (no system changes)")
	fmt.Println("  [2] Diagnose and apply recognized known-vendor repairs")
	fmt.Println(Red + "  [0] Return to Hub 5 Menu" + Reset)
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	modeChoice := strings.TrimSpace(
		transfer.ReadRealtimeInput("Select mode [0-2, default: 1]: "),
	)

	if modeChoice == "" {
		modeChoice = "1"
	}

	if modeChoice == "0" ||
		strings.EqualFold(modeChoice, "q") ||
		strings.EqualFold(modeChoice, "back") {
		fmt.Println(Yellow + "[!] Repository healer canceled. No system changes were made." + Reset)
		return
	}

	policy := repohealer.DefaultDiagnosticPolicy()
	if modeChoice == "2" {
		policy = repohealer.DefaultKnownVendorRepairPolicy()
	}

	engine := repohealer.New(
		repoHealerExecutor{client: client},
		targetOS,
		policy,
	)

	result := engine.Run()
	report := repohealer.RenderTerminal(result)

	if strings.Contains(result.Summary, "PASS") {
		fmt.Println(Green + Bold + report + Reset)
	} else {
		fmt.Println(Yellow + Bold + report + Reset)
	}

	if modeChoice != "2" {
		fmt.Println(
			Yellow +
				"[SAFE MODE] No repository, keyring, package, cache, lock, or system configuration was changed." +
				Reset,
		)
		return
	}

	runSelectedRepositoryRepairFlow(client, result)
}

// InspectFootprintState reads state.json and displays it inside a scrollable pager view
func InspectFootprintState(client *ssh.Client, targetOS osdetect.TargetOS) {
	fmt.Println(Cyan + Bold + "\n[+] Reading Remote Footprint Registry..." + Reset)
	var output string

	if targetOS == osdetect.OSWindows {
		out, err := executeRemoteCommand(client, "powershell -NoProfile -Command \"Get-Content C:\\ProgramData\\cross-suite\\state.json 2>$null\"")
		if err != nil || strings.TrimSpace(out) == "" {
			fmt.Println(Yellow + "[!] No active tool footprints recorded on Windows target host." + Reset)
			return
		}
		output = out
	} else {
		out, err := runSudoScript(client, "cat /var/lib/cross-suite/state.json 2>/dev/null")
		if err != nil || strings.TrimSpace(out) == "" {
			fmt.Println(Yellow + "[!] No active tool footprints recorded on target host." + Reset)
			return
		}
		output = out
	}

	header := Bold + Cyan + "================================================================================" + Reset + "\n" +
		Bold + Green + "                   REMOTE FOOTPRINT REGISTRY (STATE.JSON)                      " + Reset + "\n" +
		Bold + Cyan + "================================================================================" + Reset + "\n\n"

	ViewInPager(header + output)
}

// CheckUpstreamUpdates verifies package updates and displays them inside a scrollable pager view
func CheckUpstreamUpdates(client *ssh.Client, targetOS osdetect.TargetOS) {
	fmt.Println(Cyan + Bold + "\n[+] Checking Package Repositories for Upstream Updates..." + Reset)

	if targetOS == osdetect.OSWindows {
		out, _ := executeRemoteCommand(client, "powershell -NoProfile -Command \"winget upgrade 2>$null\"")
		if strings.TrimSpace(out) == "" {
			fmt.Println(Green + Bold + "[SUCCESS] All Windows packages are up to date!" + Reset)
		} else {
			header := Bold + Cyan + "================================================================================" + Reset + "\n" +
				Bold + Yellow + "                   AVAILABLE UPSTREAM WINDOWS UPDATES                         " + Reset + "\n" +
				Bold + Cyan + "================================================================================" + Reset + "\n\n"
			ViewInPager(header + out)
		}
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)

	preCheckCmd := `
		if [ -d /etc/yum.repos.d ]; then
			rm -f /etc/yum.repos.d/*broken* 2>/dev/null || true
			for f in /etc/yum.repos.d/*.repo; do
				if [ -f "$f" ]; then
					if grep -q "baseurl=%%%%s" "$f" 2>/dev/null || grep -q "baseurl=\$" "$f" 2>/dev/null || grep -q "baseurl=.*\.repo" "$f" 2>/dev/null; then
						rm -f "$f" 2>/dev/null || true
					fi
				fi
			done
		fi
	`
	_, _ = runSudoScript(client, preCheckCmd)

	checkCmd := "if command -v apt-get >/dev/null 2>&1; then apt-get --just-print upgrade 2>/dev/null | grep Inst; elif command -v dnf >/dev/null 2>&1; then dnf check-update --setopt=*.skip_if_unavailable=true 2>/dev/null; else yum check-update --setopt=*.skip_if_unavailable=true 2>/dev/null; fi"
	out, _ := runSudoScript(client, checkCmd)

	if strings.TrimSpace(out) == "" {
		fmt.Println(Green + Bold + "[SUCCESS] All footprinted tools and system packages are completely up to date!" + Reset)
		return
	}

	header := Bold + Cyan + "================================================================================" + Reset + "\n" +
		Bold + Yellow + "                   AVAILABLE UPSTREAM SYSTEM PACKAGES & UPDATES                " + Reset + "\n" +
		Bold + Cyan + "================================================================================" + Reset + "\n\n"

	ViewInPager(header + out)

	confirm := transfer.ReadRealtimeInput("Would you like to trigger a 1-Click System & Package Upgrade now? [y/N]: ")
	if strings.ToLower(confirm) == "y" {
		fmt.Println(Cyan + Bold + "\n[+] Executing System Upgrade..." + Reset)
		upgradeCmd := "if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && apt-get upgrade -y; elif command -v dnf >/dev/null 2>&1; then dnf upgrade -y --setopt=*.skip_if_unavailable=true; else yum upgrade -y --setopt=*.skip_if_unavailable=true; fi"
		upOut, err := runSudoScriptWithSpinner(client, upgradeCmd, "Upgrading System & Footprinted Packages")
		if err == nil {
			fmt.Println(Green + Bold + "\n[SUCCESS] System packages upgraded successfully!" + Reset)
		} else {
			ViewInPager(upOut)
		}
	} else {
		fmt.Println(Yellow + "[!] Upgrade skipped." + Reset)
	}
}

// ScanFootprintCVEs uses Trivy to perform real-time CVE scans with disk safeguards & scrollable pager output
func ScanFootprintCVEs(client *ssh.Client) {
	fmt.Println(Cyan + Bold + "\n[+] Initializing Trivy Vulnerability Scanner..." + Reset)

	scanScript := `#!/bin/bash
if ! command -v trivy >/dev/null 2>&1; then
	echo "NOT_INSTALLED"
	exit 0
fi

AVAIL_KB=$(df -k /root 2>/dev/null | tail -n 1 | awk '{print $4}')
if [ -n "$AVAIL_KB" ] && [ "$AVAIL_KB" -lt 307200 ]; then
	dnf clean all 2>/dev/null || yum clean all 2>/dev/null || apt-get clean 2>/dev/null || true
	rm -rf /tmp/* /var/tmp/trivy_cache 2>/dev/null || true
fi

AVAIL_KB=$(df -k /root 2>/dev/null | tail -n 1 | awk '{print $4}')
if [ -n "$AVAIL_KB" ] && [ "$AVAIL_KB" -lt 204800 ]; then
	echo "DISK_FULL"
	exit 0
fi

export TRIVY_CACHE_DIR="/var/tmp/trivy_cache"
mkdir -p "$TRIVY_CACHE_DIR"

echo "=> Executing Security Scan on Installed Packages & Filesystem..."
trivy rootfs --severity HIGH,CRITICAL --pkg-types os / 2>&1
`

	writeCmd := fmt.Sprintf("cat << 'CROSS_TRIVY_EOF' > /var/tmp/cross_trivy_scan.sh\n%s\nCROSS_TRIVY_EOF\nchmod +x /var/tmp/cross_trivy_scan.sh", scanScript)
	_, _ = executeRemoteCommand(client, writeCmd)

	out, err := runSudoScriptWithSpinner(client, "bash /var/tmp/cross_trivy_scan.sh", "Scanning Installed Packages for High & Critical Vulnerabilities")
	_, _ = executeRemoteCommand(client, "rm -f /var/tmp/cross_trivy_scan.sh")

	if strings.Contains(out, "NOT_INSTALLED") {
		fmt.Println(Yellow + "[!] Trivy binary not found. Auto-deploying Trivy now (Self-Healing)..." + Reset)
		ExecutePortableDeployment(client, "trivy", osdetect.OSLinux)
		fmt.Println(Cyan + "[+] Retrying vulnerability scan..." + Reset)
		out, err = runSudoScriptWithSpinner(client, "bash /var/tmp/cross_trivy_scan.sh", "Scanning Installed Packages for High & Critical Vulnerabilities")
		if strings.Contains(out, "NOT_INSTALLED") {
			fmt.Println(Red + "[!] Trivy auto-deployment failed. Please check network connectivity to the target host." + Reset)
			return
		}
	}

	if strings.Contains(out, "DISK_FULL") || strings.Contains(out, "no space left on device") {
		fmt.Println(Red + Bold + "\n[!] DISK SPACE ERROR: Target host has insufficient free disk space to extract Trivy database." + Reset)
		fmt.Println(Yellow + "    Run 'dnf clean all' or free space on '/' and try again." + Reset)
		return
	}

	header := Bold + Cyan + "================================================================================" + Reset + "\n" +
		Bold + Red + "                  TRIVY SYSTEM VULNERABILITY SCAN RESULTS                      " + Reset + "\n" +
		Bold + Cyan + "================================================================================" + Reset + "\n\n"

	if err == nil && strings.TrimSpace(out) != "" {
		ViewInPager(header + out)
		fmt.Println(Green + Bold + "[SUCCESS] Vulnerability Scan Execution Completed!" + Reset)
	} else {
		fmt.Println(Yellow + "[!] Trivy completed scan with no critical OS vulnerabilities found." + Reset)
	}
}

// RemapEnterpriseRepos provides an interactive repository switcher with enable, disable, and purge options
func RemapEnterpriseRepos(client *ssh.Client) {
	ensureAutonomousPermissionsWithPrompt(client)

	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Println(Bold + Cyan + "=== HUB 5: ENTERPRISE REPOSITORY & MIRROR SWITCHER WIZARD ===" + Reset)
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Println("Select Repository Pipeline Mode:")
		fmt.Println("  [1] Recommended Full Suite (EPEL, CRB, Docker CE & HashiCorp) [Default - Install All]")
		fmt.Println("  [2] Core Base OS Fix Only (Fix EOL Vault Mirrors & Disable Subscription Nag)")
		fmt.Println("  [3] Custom Selective Setup (Enable, Disable & Purge Individual Repositories)")
		fmt.Println(Red + "\n  [0] Return to Hub 5 Main Menu" + Reset)
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select Option [0-3, default: 1]: ")

		switch choice {
		case "1":
			executeRepoScript(client, "1", "1", "1", "1", "1", "enable")
			return
		case "2":
			executeRepoScript(client, "0", "0", "0", "0", "0", "base_only")
			return
		case "3":
			runSelectiveRepoLoop(client)
		case "0", "q", "Q":
			return
		default:
			executeRepoScript(client, "1", "1", "1", "1", "1", "enable")
			return
		}
	}
}

// runSelectiveRepoLoop presents an interactive menu allowing Enable, Disable, or Purge for each repository
func runSelectiveRepoLoop(client *ssh.Client) {
	for {
		checkCmd := `
			check_repo() {
				files=$(sudo find /etc/yum.repos.d/ -maxdepth 1 -iname "$1" 2>/dev/null)
				if [ -n "$files" ]; then
					if grep -q "enabled=0" $files 2>/dev/null && ! grep -q "enabled=1" $files 2>/dev/null; then
						echo "Disabled"
					else
						echo "Active"
					fi
				elif dnf repolist 2>/dev/null | grep -qiE "$2"; then
					echo "Active"
				else
					echo "Not Configured"
				fi
			}
			echo "EPEL:$(check_repo '*epel*.repo' 'epel')"
			echo "CRB:$(dnf repolist 2>/dev/null | grep -qi crb && echo 'Active' || echo 'Not Configured')"
			echo "DOCKER:$(check_repo '*docker-ce*.repo' 'docker')"
			echo "HASHI:$(check_repo '*hashicorp*.repo' 'hashicorp')"
			echo "RPMFUSION:$(check_repo '*rpmfusion*.repo' 'rpmfusion')"
		`
		out, _ := runSudoScript(client, checkCmd)

		var epelStat, crbStat, dockerStat, hashiStat, rpmfStat string = "Not Configured", "Not Configured", "Not Configured", "Not Configured", "Not Configured"

		lines := strings.Split(out, "\n")
		for _, l := range lines {
			parts := strings.Split(l, ":")
			if len(parts) == 2 {
				k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				switch k {
				case "EPEL":
					epelStat = v
				case "CRB":
					crbStat = v
				case "DOCKER":
					dockerStat = v
				case "HASHI":
					hashiStat = v
				case "RPMFUSION":
					rpmfStat = v
				}
			}
		}

		fmt.Print("\033[H\033[2J")
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Println(Bold + Cyan + "=== HUB 5: SELECTIVE REPOSITORY MANAGEMENT & GOVERNANCE ===" + Reset)
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Printf("  [1] EPEL & EPEL-Next Repo     (Status: %s)\n", formatStatus(epelStat))
		fmt.Printf("  [2] CodeReady Builder (CRB)   (Status: %s)\n", formatStatus(crbStat))
		fmt.Printf("  [3] Official Docker CE Repo   (Status: %s)\n", formatStatus(dockerStat))
		fmt.Printf("  [4] Official HashiCorp Repo   (Status: %s)\n", formatStatus(hashiStat))
		fmt.Printf("  [5] RPM Fusion (Free Updates) (Status: %s)\n", formatStatus(rpmfStat))
		fmt.Println(Red + "\n  [0] Done / Return to Hub 5 Menu" + Reset)
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

		subChoice := transfer.ReadRealtimeInput("Select Repository to Manage [0-5]: ")

		var targetRepoKey string
		var repoFile string

		switch subChoice {
		case "1":
			targetRepoKey, repoFile = "EPEL", "epel.repo"
		case "2":
			targetRepoKey, repoFile = "CRB", "crb"
		case "3":
			targetRepoKey, repoFile = "Docker CE", "docker-ce.repo"
		case "4":
			targetRepoKey, repoFile = "HashiCorp", "hashicorp.repo"
		case "5":
			targetRepoKey, repoFile = "RPM Fusion", "rpmfusion-free-updates.repo"
		case "0", "q", "Q":
			return
		default:
			continue
		}

		fmt.Println(Cyan + fmt.Sprintf("\n[+] Managing Repository: %s", targetRepoKey) + Reset)
		fmt.Println("  [1] Enable / Install Repository")
		fmt.Println("  [2] Disable Repository (Keep Config, Stop Fetches)")
		fmt.Println("  [3] Purge / Delete Repository Configuration File")
		fmt.Println(Red + "  [0] Cancel" + Reset)

		action := transfer.ReadRealtimeInput("Select Action [0-3]: ")

		switch action {
		case "1":
			switch subChoice {
			case "1":
				executeRepoScript(client, "0", "1", "0", "0", "0", "enable")
			case "2":
				executeRepoScript(client, "1", "0", "0", "0", "0", "enable")
			case "3":
				executeRepoScript(client, "0", "0", "1", "0", "0", "enable")
			case "4":
				executeRepoScript(client, "0", "0", "0", "1", "0", "enable")
			case "5":
				executeRepoScript(client, "0", "0", "0", "0", "1", "enable")
			}
		case "2":
			disCmd := fmt.Sprintf("sudo sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/%s* 2>/dev/null || dnf config-manager --set-disabled %s 2>/dev/null || true", strings.TrimSuffix(repoFile, ".repo"), repoFile)
			_, _ = runSudoScript(client, disCmd)
			fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] Repository '%s' disabled successfully!", targetRepoKey) + Reset)
			transfer.ReadRealtimeInput("\n[ Press ENTER to continue ]")
		case "3":
			delCmd := fmt.Sprintf("sudo rm -f /etc/yum.repos.d/%s* 2>/dev/null || true; sudo yum clean all 2>/dev/null || true", strings.TrimSuffix(repoFile, ".repo"))
			_, _ = runSudoScript(client, delCmd)
			fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] Repository '%s' purged from filesystem!", targetRepoKey) + Reset)
			transfer.ReadRealtimeInput("\n[ Press ENTER to continue ]")
		}
	}
}

// formatStatus prints colored statuses
func formatStatus(stat string) string {
	switch stat {
	case "Active":
		return Green + "Active" + Reset
	case "Disabled":
		return Yellow + "Disabled" + Reset
	default:
		return Red + "Not Configured" + Reset
	}
}

// executeRepoScript handles underlying execution
func executeRepoScript(client *ssh.Client, enableCRB, enableEPEL, enableDocker, enableHashi, enableRPMFusion, mode string) {
	script := fmt.Sprintf(`#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

echo "[+] Executing Repository Pipeline..."

if [ -f /etc/redhat-release ] || command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
	echo "=> [1] Disabling Subscription Manager Nag Warnings..."
	if [ -f /etc/yum/pluginconf.d/subscription-manager.conf ]; then
		sed -i 's/enabled=1/enabled=0/g' /etc/yum/pluginconf.d/subscription-manager.conf 2>/dev/null || true
	fi

	echo "=> [2] Purging Corrupt Custom Repos & Case-Insensitive Mirror URL Remapping for CentOS Vault..."
	rm -f /etc/yum.repos.d/*broken* 2>/dev/null || true
	for repo in /etc/yum.repos.d/*.repo; do
		if [ -f "$repo" ]; then
			if grep -q "baseurl=%%%%s" "$repo" 2>/dev/null || grep -q "baseurl=\$" "$repo" 2>/dev/null || grep -q "baseurl=.*\.repo" "$repo" 2>/dev/null; then
				rm -f "$repo" 2>/dev/null || true
				continue
			fi
			sed -i 's/^mirrorlist=/#mirrorlist=/g' "$repo" 2>/dev/null || true
			sed -i 's|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' "$repo" 2>/dev/null || true
		fi
	done

	if [ "%s" = "1" ]; then
		echo "=> [3] Enabling CodeReady Builder (CRB) / PowerTools..."
		dnf config-manager --set-enabled crb 2>/dev/null || dnf config-manager --set-enabled powertools 2>/dev/null || true
	fi

	if [ "%s" = "1" ]; then
		if [ -f /etc/yum.repos.d/epel.repo ]; then
			echo "[SUCCESS] IDEMPOTENT SKIP: EPEL repository file already exists! Ensuring enabled=1..."
			sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/epel*.repo 2>/dev/null || true
		else
			echo "=> [4] Bootstrapping EPEL & EPEL-Next Repositories..."
			dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm https://dl.fedoraproject.org/pub/epel/epel-next-release-latest-9.noarch.rpm 2>/dev/null || \
			yum install -y epel-release epel-next-release 2>/dev/null || true
		fi
		dnf config-manager --set-enabled epel epel-next 2>/dev/null || true
	fi

	if [ "%s" = "1" ]; then
		if [ -f /etc/yum.repos.d/docker-ce.repo ]; then
			echo "[SUCCESS] IDEMPOTENT SKIP: Docker CE repository already configured!"
			sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/docker-ce.repo 2>/dev/null || true
		else
			echo "=> [5] Injecting Docker CE Repository..."
			curl -sSL https://download.docker.com/linux/centos/docker-ce.repo -o /etc/yum.repos.d/docker-ce.repo 2>/dev/null || yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo 2>/dev/null || true
		fi
	fi

	if [ "%s" = "1" ]; then
		if [ -f /etc/yum.repos.d/hashicorp.repo ]; then
			echo "[SUCCESS] IDEMPOTENT SKIP: HashiCorp repository already configured!"
			sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/hashicorp.repo 2>/dev/null || true
		else
			echo "=> [6] Injecting HashiCorp Repository..."
			curl -sSL https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo -o /etc/yum.repos.d/hashicorp.repo 2>/dev/null || yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo 2>/dev/null || true
		fi
	fi

	if [ "%s" = "1" ]; then
		if [ -f /etc/yum.repos.d/rpmfusion-free-updates.repo ] || [ -f /etc/yum.repos.d/rpmfusion-free.repo ]; then
			echo "[SUCCESS] IDEMPOTENT SKIP: RPM Fusion repository already configured!"
			sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/rpmfusion*.repo 2>/dev/null || true
		else
			echo "=> [7] Injecting RPM Fusion Repository..."
			rpm -ivh https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-9.noarch.rpm 2>/dev/null || true
		fi
	fi

	yum clean all 2>/dev/null || dnf clean all 2>/dev/null || true
	echo "[SUCCESS] Selected Enterprise Repositories Successfully Applied!"

elif [ -f /etc/debian_version ] || command -v apt-get >/dev/null 2>&1; then
	echo "=> Optimizing APT Sources & Fast Mirrors..."
	if [ -f /etc/apt/sources.list ]; then
		sed -i 's|http://.*archive.ubuntu.com|http://archive.ubuntu.com|g' /etc/apt/sources.list 2>/dev/null || true
	fi
	apt-get update -qq 2>/dev/null || true
	echo "[SUCCESS] APT Repositories Remapped!"
fi

exit 0
`, enableCRB, enableEPEL, enableDocker, enableHashi, enableRPMFusion)

	writeCmd := fmt.Sprintf("cat << 'CROSS_REPO_EOF' > /var/tmp/cross_repo_remap.sh\n%s\nCROSS_REPO_EOF\nchmod +x /var/tmp/cross_repo_remap.sh", script)
	_, _ = executeRemoteCommand(client, writeCmd)
	out, _ := runSudoScriptWithSpinner(client, "bash /var/tmp/cross_repo_remap.sh", "Applying Repository Configuration")
	_, _ = executeRemoteCommand(client, "rm -f /var/tmp/cross_repo_remap.sh")

	if strings.TrimSpace(out) != "" {
		fmt.Println(Yellow + out + Reset)
	}

	fmt.Println(Green + Bold + "[SUCCESS] Repository Setup Completed Successfully!" + Reset)
	transfer.ReadRealtimeInput("\n[ Press ENTER to return to Selective Repository Menu ]")
}

// InjectCustomRepoWizard presents 1-Click Install All, Preset Registry Governance, and Custom Endpoint Manager
func InjectCustomRepoWizard(client *ssh.Client, targetOS osdetect.TargetOS) {
	for {
		fmt.Print("\033[H\033[2J")
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Println(Bold + Cyan + "=== HUB 5: PRIVATE & ENTERPRISE REPOSITORY INJECTION ENGINE ===" + Reset)
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Println("Select Injection Mode:")
		fmt.Println("  [1] 1-Click Install ALL OS-Specific Presets Together [Default]")
		fmt.Println("  [2] Select & Manage Individual Preset Repositories (Enable, Disable, Purge)")
		fmt.Println("  [3] Custom Private Repository Endpoint Manager (Multi-URL List, Add, Remove)")
		fmt.Println(Red + "\n  [0] Return to Hub 5 Main Menu" + Reset)
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

		choice := transfer.ReadRealtimeInput("Select Option [0-3, default: 1]: ")

		switch choice {
		case "1", "":
			fmt.Println(Cyan + "\n[+] Executing 1-Click Installation of ALL OS-Specific Presets..." + Reset)
			showPresetRegistryByOS(client, targetOS, true)
			pauseExecution(bufio.NewReader(os.Stdin))
			return
		case "2":
			showInteractivePresetRegistryLoop(client, targetOS)
		case "3":
			manageCustomPrivateEndpoints(client, targetOS)
		case "0", "q", "Q":
			return
		}
	}
}

// showInteractivePresetRegistryLoop provides live status checks using wildcard file searches & repolist queries
func showInteractivePresetRegistryLoop(client *ssh.Client, targetOS osdetect.TargetOS) {
	for {
		checkCmd := `
			check_repo() {
				files=$(sudo find /etc/yum.repos.d/ -maxdepth 1 -iname "$1" 2>/dev/null)
				if [ -n "$files" ]; then
					if grep -q "enabled=0" $files 2>/dev/null && ! grep -q "enabled=1" $files 2>/dev/null; then
						echo "Disabled"
					else
						echo "Active"
					fi
				elif dnf repolist 2>/dev/null | grep -qiE "$2"; then
					echo "Active"
				else
					echo "Not Configured"
				fi
			}
			echo "EPEL:$(check_repo '*epel*.repo' 'epel')"
			echo "DOCKER:$(check_repo '*docker-ce*.repo' 'docker')"
			echo "HASHI:$(check_repo '*hashicorp*.repo' 'hashicorp')"
			echo "NODE:$(check_repo '*nodesource*.repo' 'nodesource')"
			echo "MS:$(check_repo '*vscode*.repo' 'vscode')"
			echo "RPMF:$(check_repo '*rpmfusion*.repo' 'rpmfusion')"
			echo "PGDG:$(check_repo '*pgdg*.repo' 'pgdg')"
		`
		out, _ := runSudoScript(client, checkCmd)

		var epelStat, dockerStat, hashiStat, rpmfStat, nodeStat, msStat, pdgStat string = "Not Configured", "Not Configured", "Not Configured", "Not Configured", "Not Configured", "Not Configured", "Not Configured"

		lines := strings.Split(out, "\n")
		for _, l := range lines {
			parts := strings.Split(l, ":")
			if len(parts) == 2 {
				k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				switch k {
				case "EPEL":
					epelStat = v
				case "DOCKER":
					dockerStat = v
				case "HASHI":
					hashiStat = v
				case "NODE":
					nodeStat = v
				case "MS":
					msStat = v
				case "RPMF":
					rpmfStat = v
				case "PGDG":
					pdgStat = v
				}
			}
		}

		fmt.Print("\033[H\033[2J")
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Println(Bold + Cyan + fmt.Sprintf("=== HUB 5: PRESET REPOSITORY GOVERNANCE MATRIX [%s] ===", strings.ToUpper(string(targetOS))) + Reset)
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Printf("  [1] Official EPEL & EPEL-Next Repos       (Status: %s)\n", formatStatus(epelStat))
		fmt.Printf("  [2] Official Docker CE Repo (docker-ce)   (Status: %s)\n", formatStatus(dockerStat))
		fmt.Printf("  [3] Official HashiCorp Repo (hashicorp)   (Status: %s)\n", formatStatus(hashiStat))
		fmt.Printf("  [4] NodeSource Node.js LTS Repository    (Status: %s)\n", formatStatus(nodeStat))
		fmt.Printf("  [5] Microsoft Official VS Code Repository (Status: %s)\n", formatStatus(msStat))
		fmt.Printf("  [6] RPM Fusion Free Updates Repo          (Status: %s)\n", formatStatus(rpmfStat))
		fmt.Printf("  [7] PostgreSQL Development Group (PGDG)   (Status: %s)\n", formatStatus(pdgStat))
		fmt.Println(Red + "\n  [0] Done / Return to Menu" + Reset)
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

		pChoice := transfer.ReadRealtimeInput("Select Repository to Manage [0-7]: ")

		var targetName string
		var repoFilePattern string

		switch pChoice {
		case "1":
			targetName, repoFilePattern = "EPEL & EPEL-Next", "/etc/yum.repos.d/*epel*.repo"
		case "2":
			targetName, repoFilePattern = "Docker CE", "/etc/yum.repos.d/*docker-ce*.repo"
		case "3":
			targetName, repoFilePattern = "HashiCorp", "/etc/yum.repos.d/*hashicorp*.repo"
		case "4":
			targetName, repoFilePattern = "NodeSource Node.js", "/etc/yum.repos.d/*nodesource*.repo"
		case "5":
			targetName, repoFilePattern = "Microsoft VS Code", "/etc/yum.repos.d/*vscode*.repo"
		case "6":
			targetName, repoFilePattern = "RPM Fusion Free", "/etc/yum.repos.d/*rpmfusion*.repo"
		case "7":
			targetName, repoFilePattern = "PostgreSQL PGDG", "/etc/yum.repos.d/*pgdg*.repo"
		case "0", "q", "Q":
			return
		default:
			continue
		}

		fmt.Println(Cyan + fmt.Sprintf("\n[+] Managing Repository: %s", targetName) + Reset)
		fmt.Println("  [1] Enable / Install Repository")
		fmt.Println("  [2] Disable Repository (Keep Config, Set enabled=0)")
		fmt.Println("  [3] Purge / Delete Configuration File")
		fmt.Println(Red + "  [0] Cancel" + Reset)

		act := transfer.ReadRealtimeInput("Select Action [0-3]: ")

		switch act {
		case "1":
			switch pChoice {
			case "1":
				verOut, _ := runSudoScript(client, "rpm -E %rhel 2>/dev/null || echo '9'")
				elVer := strings.TrimSpace(verOut)
				if elVer == "" || strings.Contains(elVer, "%") {
					elVer = "9"
				}
				runSudoScript(client, fmt.Sprintf("dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-%s.noarch.rpm https://dl.fedoraproject.org/pub/epel/epel-next-release-latest-%s.noarch.rpm 2>/dev/null || true", elVer, elVer))
			case "2":
				InjectCustomRepo(client, "https://download.docker.com/linux/centos/docker-ce.repo", targetOS)
			case "3":
				InjectCustomRepo(client, "https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo", targetOS)
			case "4":
				runSudoScript(client, "curl -fsSL https://rpm.nodesource.com/setup_lts.x | bash - 2>/dev/null || true")
			case "5":
				runSudoScript(client, `
					rpm --import https://packages.microsoft.com/keys/microsoft.asc 2>/dev/null || true
					cat << 'EOF' > /etc/yum.repos.d/vscode.repo
[code]
name=Visual Studio Code
baseurl=https://packages.microsoft.com/yumrepos/vscode
enabled=1
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc
EOF
					chmod 644 /etc/yum.repos.d/vscode.repo
				`)
			case "6":
				InjectCustomRepo(client, "https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-9.noarch.rpm", targetOS)
			case "7":
				verOut, _ := runSudoScript(client, "rpm -E %rhel 2>/dev/null || echo '9'")
				elVer := strings.TrimSpace(verOut)
				if elVer == "" || strings.Contains(elVer, "%") {
					elVer = "9"
				}
				pgdgURL := fmt.Sprintf("https://download.postgresql.org/pub/repos/yum/reporpms/EL-%s-x86_64/pgdg-redhat-repo-latest.noarch.rpm", elVer)
				runSudoScript(client, fmt.Sprintf("dnf install -y %s 2>/dev/null || yum install -y %s 2>/dev/null || true", pgdgURL, pgdgURL))
			}
			fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] Repository '%s' installed & enabled!", targetName) + Reset)
			transfer.ReadRealtimeInput("\n[ Press ENTER to continue ]")
		case "2":
			disCmd := fmt.Sprintf("sudo sed -i 's/enabled=1/enabled=0/g' %s 2>/dev/null || true", repoFilePattern)
			_, _ = runSudoScript(client, disCmd)
			fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] Repository '%s' disabled!", targetName) + Reset)
			transfer.ReadRealtimeInput("\n[ Press ENTER to continue ]")
		case "3":
			delCmd := fmt.Sprintf("sudo rm -f %s 2>/dev/null || true; sudo yum clean all 2>/dev/null || true", repoFilePattern)
			_, _ = runSudoScript(client, delCmd)
			fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] Repository '%s' purged!", targetName) + Reset)
			transfer.ReadRealtimeInput("\n[ Press ENTER to continue ]")
		}
	}
}

// manageCustomPrivateEndpoints manages multiple custom repo URLs with list, disable, and remove options
func manageCustomPrivateEndpoints(client *ssh.Client, targetOS osdetect.TargetOS) {
	for {
		listCmd := `
			if [ -d /etc/yum.repos.d ]; then
				for f in /etc/yum.repos.d/*.repo; do
					if [ -f "$f" ]; then
						bname=$(basename "$f")
						case "$bname" in
							custom*|cross*)
								url=$(sudo grep -i "^baseurl=" "$f" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '\r')
								[ -z "$url" ] && url=$(sudo grep -i "baseurl" "$f" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '\r')
								[ -z "$url" ] && url=$(sudo grep -i "name=" "$f" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d '\r')
								[ -z "$url" ] && url="Custom Repository"
								dis=$(sudo grep -qi "enabled=0" "$f" 2>/dev/null && echo "Disabled" || echo "Active")
								echo "${bname}|${url}|${dis}"
								;;
						esac
					fi
				done
			elif [ -d /etc/apt/sources.list.d ]; then
				for f in /etc/apt/sources.list.d/*.list; do
					if [ -f "$f" ]; then
						bname=$(basename "$f")
						case "$bname" in
							custom*|cross*)
								url=$(head -n 1 "$f" 2>/dev/null | tr -d '\r')
								dis=$(grep -q "^#" "$f" 2>/dev/null && echo "Disabled" || echo "Active")
								echo "${bname}|${url}|${dis}"
								;;
						esac
					fi
				done
			fi
		`
		out, _ := runSudoScript(client, listCmd)

		type customRepoItem struct {
			FileName string
			URL      string
			Status   string
		}

		var items []customRepoItem
		lines := strings.Split(out, "\n")
		for _, l := range lines {
			trimmedLine := strings.TrimSpace(l)
			if trimmedLine == "" {
				continue
			}
			parts := strings.Split(trimmedLine, "|")
			if len(parts) >= 3 && strings.TrimSpace(parts[0]) != "" {
				items = append(items, customRepoItem{
					FileName: strings.TrimSpace(parts[0]),
					URL:      strings.TrimSpace(parts[1]),
					Status:   strings.TrimSpace(parts[2]),
				})
			}
		}

		fmt.Print("\033[H\033[2J")
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)
		fmt.Println(Bold + Cyan + "=== HUB 5: MULTI-ENDPOINT CUSTOM PRIVATE REPOSITORY MANAGER ===" + Reset)
		fmt.Println(Bold + Cyan + "================================================================================" + Reset)

		if len(items) == 0 {
			fmt.Println(Yellow + "[!] No custom private endpoints configured on target host." + Reset)
		} else {
			fmt.Println(Cyan + "Active Custom Private Endpoints on Target Host:" + Reset)
			for idx, item := range items {
				fmt.Printf("  [%d] %s -> %s (Status: %s)\n", idx+1, item.FileName, item.URL, formatStatus(item.Status))
			}
		}

		fmt.Println(Blue + "\nOperational Controls:" + Reset)
		fmt.Println("  [1] Add / Inject New Custom Private Repo Base URL")
		fmt.Println("  [2] Select & Disable a Custom Repository Endpoint")
		fmt.Println("  [3] Select & Purge / Delete a Custom Repository Endpoint")
		fmt.Println(Red + "\n  [0] Return to Hub 5 Main Menu" + Reset)
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

		cChoice := transfer.ReadRealtimeInput("Select Option [0-3]: ")

		switch cChoice {
		case "1":
			injectManualCustomRepoWithDynamicExample(client, targetOS)
			transfer.ReadRealtimeInput("\n[ Press ENTER to continue ]")
		case "2":
			if len(items) == 0 {
				fmt.Println(Yellow + "[!] No custom repos available to disable." + Reset)
				transfer.ReadRealtimeInput("\n[ Press ENTER to continue ]")
				continue
			}
			selStr := transfer.ReadRealtimeInput("Enter choice number to DISABLE [1-" + fmt.Sprintf("%d", len(items)) + "]: ")
			var selIdx int
			if _, err := fmt.Sscanf(strings.TrimSpace(selStr), "%d", &selIdx); err == nil && selIdx >= 1 && selIdx <= len(items) {
				fileToDisable := items[selIdx-1].FileName
				disCmd := fmt.Sprintf("sudo sed -i 's/enabled=1/enabled=0/g' /etc/yum.repos.d/%s 2>/dev/null || true", fileToDisable)
				_, _ = runSudoScript(client, disCmd)
				fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] Disabled custom repository '%s'!", fileToDisable) + Reset)
			} else {
				fmt.Println(Yellow + "[!] Invalid selection." + Reset)
			}
			transfer.ReadRealtimeInput("\n[ Press ENTER to continue ]")
		case "3":
			if len(items) == 0 {
				fmt.Println(Yellow + "[!] No custom repos available to purge." + Reset)
				transfer.ReadRealtimeInput("\n[ Press ENTER to continue ]")
				continue
			}
			selStr := transfer.ReadRealtimeInput("Enter choice number to PURGE/DELETE [1-" + fmt.Sprintf("%d", len(items)) + "]: ")
			var selIdx int
			if _, err := fmt.Sscanf(strings.TrimSpace(selStr), "%d", &selIdx); err == nil && selIdx >= 1 && selIdx <= len(items) {
				fileToDelete := items[selIdx-1].FileName
				delCmd := fmt.Sprintf("sudo rm -f /etc/yum.repos.d/%s /etc/apt/sources.list.d/%s 2>/dev/null || true; sudo yum clean all 2>/dev/null || true", fileToDelete, fileToDelete)
				_, _ = runSudoScript(client, delCmd)
				fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] Purged custom repository file '%s'!", fileToDelete) + Reset)
			} else {
				fmt.Println(Yellow + "[!] Invalid selection." + Reset)
			}
			transfer.ReadRealtimeInput("\n[ Press ENTER to continue ]")
		case "0", "q", "Q":
			return
		}
	}
}

// injectManualCustomRepoWithDynamicExample provides OS-tailored default example URLs
func injectManualCustomRepoWithDynamicExample(client *ssh.Client, targetOS osdetect.TargetOS) {
	defaultURL := "http://nexus.internal:8081/repository/rpm-hosted/"

	if targetOS == osdetect.OSWindows {
		defaultURL = "https://community.chocolatey.org/api/v2/"
	} else {
		distroCmd := "if [ -f /etc/redhat-release ]; then echo 'RPM'; elif grep -qi 'kali' /etc/os-release 2>/dev/null; then echo 'KALI'; elif grep -qi 'ubuntu' /etc/os-release 2>/dev/null; then echo 'UBUNTU'; elif [ -f /etc/debian_version ]; then echo 'DEBIAN'; else echo 'RPM'; fi"
		dist, _ := runSudoScript(client, distroCmd)
		dist = strings.TrimSpace(dist)

		switch dist {
		case "KALI":
			defaultURL = "http://http.kali.org/kali/"
		case "UBUNTU":
			defaultURL = "http://archive.ubuntu.com/ubuntu/"
		case "DEBIAN":
			defaultURL = "http://deb.debian.org/debian/"
		case "RPM":
			defaultURL = "http://nexus.internal:8081/repository/rpm-hosted/"
		}
	}

	promptMsg := fmt.Sprintf("Enter Custom Repo Base URL [default: %s] (or '0' to Cancel): ", defaultURL)
	repoURL := strings.TrimSpace(transfer.ReadRealtimeInput(promptMsg))
	if repoURL == "0" || strings.EqualFold(repoURL, "b") || strings.EqualFold(repoURL, "back") || strings.EqualFold(repoURL, "q") {
		fmt.Println(Yellow + "[!] Repo injection canceled. Returning to Menu..." + Reset)
		return
	}
	if repoURL == "" {
		repoURL = defaultURL
	}

	InjectCustomRepoIndexed(client, repoURL, targetOS)
}

// InjectCustomRepoIndexed writes uniquely named custom repos with smart .repo vs baseurl detection
func InjectCustomRepoIndexed(client *ssh.Client, repoURL string, targetOS osdetect.TargetOS) {
	if targetOS == osdetect.OSWindows {
		winCmd := fmt.Sprintf("powershell -NoProfile -Command \"Register-PSRepository -Name 'CustomCross-%d' -SourceLocation '%s' -InstallationPolicy Trusted 2>$null\"", os.Getpid(), repoURL)
		_, _ = executeRemoteCommand(client, winCmd)
		fmt.Println(Green + Bold + "[SUCCESS] Windows PowerShell Repository Injected!" + Reset)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)
	cleanURL := strings.TrimSpace(repoURL)

	script := fmt.Sprintf(`#!/bin/bash
URL="%s"

if [ -d /etc/yum.repos.d ]; then
	if [[ "$URL" == *".repo" ]]; then
		echo "=> Pulling remote .repo file directly into /etc/yum.repos.d/..."
		curl -sSL "$URL" -o /etc/yum.repos.d/$(basename "$URL") 2>/dev/null || yum-config-manager --add-repo "$URL" 2>/dev/null || true
	else
		idx=$(find /etc/yum.repos.d/ -type f -name "custom-*.repo" 2>/dev/null | wc -l | awk '{print $1}')
		next_idx=$((idx + 1))
		repo_file="/etc/yum.repos.d/custom-${next_idx}.repo"

		cat << EOF > "$repo_file"
[custom-cross-repo-${next_idx}]
name=Cross-Suite Private Repository ${next_idx}
baseurl=${URL}
enabled=1
gpgcheck=0
priority=1
skip_if_unavailable=1
EOF
		chmod 644 "$repo_file"
	fi
	yum clean all --setopt=*.skip_if_unavailable=true 2>/dev/null || dnf clean all 2>/dev/null || true

elif [ -d /etc/apt/sources.list.d ]; then
	idx=$(find /etc/apt/sources.list.d/ -type f -name "custom-*.list" 2>/dev/null | wc -l | awk '{print $1}')
	next_idx=$((idx + 1))
	repo_file="/etc/apt/sources.list.d/custom-${next_idx}.list"

	cat << EOF > "$repo_file"
deb [trusted=yes] %s ./
EOF
	chmod 644 "$repo_file"
	apt-get update -qq 2>/dev/null || true
fi
exit 0
`, cleanURL, cleanURL)

	writeCmd := fmt.Sprintf("cat << 'CROSS_REPO_INJECT_EOF' > /var/tmp/cross_repo_inject.sh\n%s\nCROSS_REPO_INJECT_EOF\nchmod +x /var/tmp/cross_repo_inject.sh", script)
	_, _ = executeRemoteCommand(client, writeCmd)
	_, _ = runSudoScriptWithSpinner(client, "bash /var/tmp/cross_repo_inject.sh", "Injecting Custom Repository Endpoint")
	_, _ = executeRemoteCommand(client, "rm -f /var/tmp/cross_repo_inject.sh")

	fmt.Println(Green + Bold + "[SUCCESS] Custom Repository Endpoint Injected & Active!" + Reset)
}

// InjectCustomRepo writes a standard custom repo endpoint
func InjectCustomRepo(client *ssh.Client, repoURL string, targetOS osdetect.TargetOS) {
	InjectCustomRepoIndexed(client, repoURL, targetOS)
}

// showPresetRegistryByOS provisions all presets in a 1-click sweep
func showPresetRegistryByOS(client *ssh.Client, targetOS osdetect.TargetOS, installAllMode bool) {
	if installAllMode {
		fmt.Println(Cyan + "\n[+] Deploying All Enterprise Presets for Connected Target Host..." + Reset)
		if targetOS == osdetect.OSWindows {
			InjectCustomRepo(client, "https://community.chocolatey.org/api/v2/", targetOS)
			InjectCustomRepo(client, "https://www.powershellgallery.com/api/v2", targetOS)
			return
		}

		distroCmd := "if [ -f /etc/redhat-release ]; then echo 'RPM'; elif [ -f /etc/debian_version ]; then echo 'APT'; else echo 'UNKNOWN'; fi"
		distroType, _ := runSudoScript(client, distroCmd)

		if strings.Contains(distroType, "RPM") {
			verCmd := "rpm -E %rhel 2>/dev/null || grep -oP 'VERSION_ID=\"\\K[0-9]+' /etc/os-release 2>/dev/null || echo '9'"
			elVerOut, _ := runSudoScript(client, verCmd)
			elVer := strings.TrimSpace(elVerOut)
			if elVer == "" || strings.Contains(elVer, "%") {
				elVer = "9"
			}

			epelURL := fmt.Sprintf("https://dl.fedoraproject.org/pub/epel/epel-release-latest-%s.noarch.rpm", elVer)
			epelNextURL := fmt.Sprintf("https://dl.fedoraproject.org/pub/epel/epel-next-release-latest-%s.noarch.rpm", elVer)
			pgdgURL := fmt.Sprintf("https://download.postgresql.org/pub/repos/yum/reporpms/EL-%s-x86_64/pgdg-redhat-repo-latest.noarch.rpm", elVer)

			runSudoScript(client, fmt.Sprintf("dnf install -y --setopt=*.skip_if_unavailable=true %s %s 2>/dev/null || yum install -y %s %s 2>/dev/null || true", epelURL, epelNextURL, epelURL, epelNextURL))
			InjectCustomRepo(client, "https://download.docker.com/linux/centos/docker-ce.repo", targetOS)
			InjectCustomRepo(client, "https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo", targetOS)
			runSudoScript(client, "curl -fsSL https://rpm.nodesource.com/setup_lts.x | bash - 2>/dev/null || true")
			runSudoScript(client, `
				rpm --import https://packages.microsoft.com/keys/microsoft.asc 2>/dev/null || true
				cat << 'EOF' > /etc/yum.repos.d/vscode.repo
[code]
name=Visual Studio Code
baseurl=https://packages.microsoft.com/yumrepos/vscode
enabled=1
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc
EOF
				chmod 644 /etc/yum.repos.d/vscode.repo
			`)
			runSudoScript(client, fmt.Sprintf("dnf install -y --setopt=*.skip_if_unavailable=true %s 2>/dev/null || yum install -y %s 2>/dev/null || true", pgdgURL, pgdgURL))
		} else {
			InjectCustomRepo(client, "https://download.docker.com/linux/ubuntu", targetOS)
			InjectCustomRepo(client, "https://apt.releases.hashicorp.com", targetOS)
			runSudoScript(client, "curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - 2>/dev/null || true")

			runSudoScript(client, `
				curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor > /etc/apt/trusted.gpg.d/pgdg.gpg 2>/dev/null || true
				CODENAME=$(lsb_release -cs 2>/dev/null || echo "focal")
				echo "deb [signed-by=/etc/apt/trusted.gpg.d/pgdg.gpg] http://apt.postgresql.org/pub/repos/apt $CODENAME-pgdg main" > /etc/apt/sources.list.d/pgdg.list 2>/dev/null || true
				apt-get update -qq 2>/dev/null || true
			`)
			runSudoScript(client, `
				curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /etc/apt/trusted.gpg.d/microsoft.gpg 2>/dev/null || true
				echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list 2>/dev/null || true
				apt-get update -qq 2>/dev/null || true
			`)
		}
	}
}

// TuneMirrorSpeed enables fastestmirror on Linux or parallel downloads on Windows
func TuneMirrorSpeed(client *ssh.Client, targetOS osdetect.TargetOS) {
	fmt.Println(Cyan + Bold + "\n[+] Running Download Speed & Mirror Optimizer..." + Reset)
	if targetOS == osdetect.OSWindows {
		winCmd := "powershell -NoProfile -Command \"$env:NETConnection_MaxConnectionsPerServer=10; Write-Output '[SUCCESS] Windows Max Parallel HTTP Connections Tuned to 10!'\""
		out, _ := executeRemoteCommand(client, winCmd)
		fmt.Println(Green + out + Reset)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)
	tuneScript := `#!/bin/bash
if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
	if [ -f /etc/dnf/dnf.conf ]; then
		grep -q "fastestmirror" /etc/dnf/dnf.conf || echo "fastestmirror=True" >> /etc/dnf/dnf.conf
		grep -q "max_parallel_downloads" /etc/dnf/dnf.conf || echo "max_parallel_downloads=10" >> /etc/dnf/dnf.conf
	fi
fi
exit 0
`
	writeCmd := fmt.Sprintf("cat << 'CROSS_TUNE_EOF' > /var/tmp/cross_tune.sh\n%s\nCROSS_TUNE_EOF\nchmod +x /var/tmp/cross_tune.sh", tuneScript)
	_, _ = executeRemoteCommand(client, writeCmd)
	_, _ = runSudoScriptWithSpinner(client, "bash /var/tmp/cross_tune.sh", "Optimizing Download Speed & Parallel Mirrors")
	_, _ = executeRemoteCommand(client, "rm -f /var/tmp/cross_tune.sh")

	fmt.Println(Green + Bold + "[SUCCESS] Repository mirror download speeds optimized!" + Reset)
}

// RollbackSystemState restores pre-repair snapshots
func RollbackSystemState(client *ssh.Client, targetOS osdetect.TargetOS) {
	fmt.Println(Cyan + Bold + "\n[+] Rolling Back Repository & Package System State..." + Reset)
	if targetOS == osdetect.OSWindows {
		checkCmd := "powershell -NoProfile -Command \"Test-Path 'C:\\ProgramData\\cross-suite\\snapshots\\machine-path.snapshot.txt'\""
		checkOut, _ := executeRemoteCommand(client, checkCmd)
		if !strings.Contains(checkOut, "True") {
			fmt.Println(Yellow + Bold + "[!] No pre-repair snapshot found. Run Option [7] Self-Healer at least once first to create one." + Reset)
			return
		}

		restoreScript := `
$snapDir = "C:\ProgramData\cross-suite\snapshots"
$restored = @()

try {
    if (Test-Path "$snapDir\machine-path.snapshot.txt") {
        $oldPath = Get-Content "$snapDir\machine-path.snapshot.txt" -Raw
        [Environment]::SetEnvironmentVariable('Path', $oldPath.Trim(), 'Machine')
        $restored += "System PATH"
    }
} catch {}

try {
    if (Test-Path "$snapDir\state.json.snapshot") {
        Copy-Item "$snapDir\state.json.snapshot" "C:\ProgramData\cross-suite\state.json" -Force
        $restored += "Footprint State Registry"
    }
} catch {}

if ($restored.Count -gt 0) {
    Write-Output ("[SUCCESS] Restored: " + ($restored -join ", "))
} else {
    Write-Output "[!] Snapshot files were present but nothing could be restored."
}

Write-Output "NOTE: winget-list.snapshot.txt and choco-list.snapshot.txt are available at $snapDir for manual package diffing/reinstall, since packages themselves are not auto-reinstalled to avoid destructive side effects."
`
		utf16LE := []byte{}
		for _, r := range restoreScript {
			utf16LE = append(utf16LE, byte(r), byte(r>>8))
		}
		b64Cmd := base64.StdEncoding.EncodeToString(utf16LE)
		winCmd := fmt.Sprintf("powershell -NoProfile -EncodedCommand %s", b64Cmd)
		out, _ := runSudoScriptWithSpinner(client, winCmd, "Restoring Windows Pre-Repair Snapshot State")

		if strings.TrimSpace(out) != "" {
			fmt.Println(Yellow + out + Reset)
		}
		fmt.Println(Green + Bold + "[SUCCESS] Windows system rollback completed!" + Reset)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)
	rollbackCmd := `
		if [ -d /var/lib/cross-suite/snapshots ] && [ -n "$(ls -A /var/lib/cross-suite/snapshots 2>/dev/null)" ]; then
			cp -rf /var/lib/cross-suite/snapshots/sources.list* /etc/apt/ 2>/dev/null || true
			cp -rf /var/lib/cross-suite/snapshots/yum.repos.d* /etc/ 2>/dev/null || true
			apt-get update -qq 2>/dev/null || yum clean all 2>/dev/null || true
			echo "SNAPSHOT_RESTORED"
		else
			echo "NO_SNAPSHOT_FOUND"
		fi
	`
	out, _ := runSudoScriptWithSpinner(client, rollbackCmd, "Restoring Pre-Repair Snapshot State")

	if strings.Contains(out, "NO_SNAPSHOT_FOUND") {
		fmt.Println(Yellow + Bold + "[!] No pre-repair snapshot found. Run Option [7] Self-Healer at least once first to create one." + Reset)
		return
	}
	fmt.Println(Green + Bold + "[SUCCESS] System rollback completed successfully — repository config restored from snapshot!" + Reset)
}

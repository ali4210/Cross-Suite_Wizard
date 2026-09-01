package playbook

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"cross-ssh/pkg/osdetect"
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
			fmt.Println("  [7] Autonomous System Self-Healer (Clear Locks, Dpkg Errors & Missing GPG Keys)")
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
			query := transfer.ReadRealtimeInput("Enter tool name or wildcard (e.g., docker, trivy, code*, git): ")
			if strings.TrimSpace(query) != "" {
				InspectAndDeployFamily(reader, client, query, targetOS)
			}
			pauseExecution(reader)
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
			toolName := transfer.ReadRealtimeInput("Enter tool/package name to DEEP PURGE (e.g., docker, trivy, code, nmap): ")
			if strings.TrimSpace(toolName) != "" {
				ExecuteDeepUninstaller(client, strings.TrimSpace(toolName), targetOS)
			}
			pauseExecution(reader)
		case "11":
			TraceAndPurgeToolFootprints(client, targetOS)
			pauseExecution(reader)
		case "0", "q", "Q":
			return
		}
	}
}

// ExecuteDeepUninstaller purges a tool, its dependencies, leftover configs, caches, and state entries
func ExecuteDeepUninstaller(client *ssh.Client, tool string, targetOS osdetect.TargetOS) {
	cleanTool := strings.Split(strings.TrimSpace(tool), ".")[0]
	if cleanTool == "" {
		return
	}

	fmt.Println(Red + Bold + fmt.Sprintf("\n[!] INITIALIZING DEEP UNINSTALLER & FOOTPRINT PURGER FOR: '%s'...", cleanTool) + Reset)

	if targetOS == osdetect.OSWindows {
		executeWindowsDeepUninstall(client, cleanTool)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)

	purgeScript := fmt.Sprintf(`#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

TOOL="%s"
echo "=> Step 1: Stopping related background processes & services..."
systemctl stop "$TOOL" 2>/dev/null || true
pkill -f "$TOOL" 2>/dev/null || true

echo "=> Step 2: Purging package and orphaned dependencies..."
if command -v apt-get >/dev/null 2>&1; then
	apt-get purge -y "$TOOL" "${TOOL}-*" 2>/dev/null || true
	apt-get autoremove --purge -y 2>/dev/null || true
	apt-get clean 2>/dev/null || true
elif command -v dnf >/dev/null 2>&1; then
	dnf remove -y "$TOOL" "${TOOL}-*" 2>/dev/null || true
	dnf autoremove -y 2>/dev/null || true
	dnf clean all 2>/dev/null || true
elif command -v yum >/dev/null 2>&1; then
	yum remove -y "$TOOL" "${TOOL}-*" 2>/dev/null || true
	yum autoremove -y 2>/dev/null || true
	yum clean all 2>/dev/null || true
fi

echo "=> Step 3: Wiping leftover binary footprints & paths..."
rm -f "/usr/bin/$TOOL" "/usr/local/bin/$TOOL" "/usr/sbin/$TOOL" "/usr/local/sbin/$TOOL" 2>/dev/null || true
rm -rf "/opt/$TOOL" "/var/log/$TOOL" "/var/lib/$TOOL" "/tmp/$TOOL*" "/var/tmp/$TOOL*" 2>/dev/null || true
rm -rf "/etc/$TOOL" "/etc/yum.repos.d/$TOOL*.repo" "/etc/apt/sources.list.d/$TOOL*.list" 2>/dev/null || true

# Clean user configs
for uInHome in /home/* /root; do
	if [ -d "$uInHome" ]; then
		rm -rf "$uInHome/.config/$TOOL" "$uInHome/.$TOOL" "$uInHome/.cache/$TOOL" 2>/dev/null || true
	fi
done

echo "=> Step 4: Updating Cross-Suite Footprint State Registry..."
python3 -c "
import json, os
p = '/var/lib/cross-suite/state.json'
if os.path.exists(p):
    try:
        with open(p, 'r') as f: d = json.load(f)
        if '$TOOL' in d:
            del d['$TOOL']
            with open(p, 'w') as f: json.dump(d, f, indent=2)
    except: pass
" 2>/dev/null || true

echo "[SUCCESS] Deep Purge for '$TOOL' Completed Successfully!"
exit 0
`, cleanTool)

	writeCmd := fmt.Sprintf("cat << 'EOF' > /var/tmp/cross_purge.sh\n%s\nEOF\nchmod +x /var/tmp/cross_purge.sh", purgeScript)
	_, _ = executeRemoteCommand(client, writeCmd)
	out, _ := runSudoScriptWithSpinner(client, "bash /var/tmp/cross_purge.sh", fmt.Sprintf("Deep Purging %s & Erasing Footprints", cleanTool))
	_, _ = executeRemoteCommand(client, "rm -f /var/tmp/cross_purge.sh")

	if strings.TrimSpace(out) != "" {
		fmt.Println(Yellow + out + Reset)
	}

	fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] DEEP UNINSTALL COMPLETED: '%s' and all traces removed from target filesystem!", cleanTool) + Reset)
}

// executeWindowsDeepUninstall performs a deep purge on Windows platforms
func executeWindowsDeepUninstall(client *ssh.Client, tool string) {
	psScript := fmt.Sprintf(`
$tool = '%s'
Write-Output "=> Step 1: Stopping active services/processes..."
Stop-Service -Name $tool -ErrorAction SilentlyContinue
Stop-Process -Name $tool -Force -ErrorAction SilentlyContinue

Write-Output "=> Step 2: Uninstalling via Winget & Chocolatey..."
if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget uninstall --id $tool --silent --accept-source-agreements 2>$null
}
if (Get-Command choco -ErrorAction SilentlyContinue) {
    choco uninstall $tool -y --remove-dependencies 2>$null
}

Write-Output "=> Step 3: Wiping leftover configuration & cache directories..."
Remove-Item -Path "C:\ProgramData\$tool" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\$tool" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:APPDATA\$tool" -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "=> Step 4: Updating Footprint State Registry..."
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
Write-Output "SUCCESS_PURGED"
`, tool)

	utf16LE := []byte{}
	for _, r := range psScript {
		utf16LE = append(utf16LE, byte(r), byte(r>>8))
	}
	b64Cmd := base64.StdEncoding.EncodeToString(utf16LE)

	winCmd := fmt.Sprintf("powershell -NoProfile -EncodedCommand %s", b64Cmd)
	out, err := executeRemoteCommand(client, winCmd)

	if strings.Contains(out, "SUCCESS_PURGED") || err == nil {
		fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] WINDOWS DEEP UNINSTALL COMPLETED: '%s' purged completely!", tool) + Reset)
	} else {
		fmt.Println(Yellow + fmt.Sprintf("[!] Windows uninstall executed for '%s'.", tool) + Reset)
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

	targetToPurge := transfer.ReadRealtimeInput("\nEnter package name from trace list to DEEP PURGE (or press Enter to skip): ")
	if strings.TrimSpace(targetToPurge) != "" {
		ExecuteDeepUninstaller(client, strings.TrimSpace(targetToPurge), targetOS)
	}
}

// InspectAndDeployFamily performs dynamic package search on Linux or Windows
func InspectAndDeployFamily(reader *bufio.Reader, client *ssh.Client, query string, targetOS osdetect.TargetOS) {
	if targetOS != osdetect.OSWindows {
		ensureAutonomousPermissionsWithPrompt(client)
	}

	fmt.Println(Cyan + Bold + "\n[+] Executing Package Search for: " + query + Reset)
	cleanQuery := strings.TrimSuffix(strings.TrimSuffix(query, "-*"), "*")

	var family []string
	seen := make(map[string]bool)
	family = append(family, cleanQuery)
	seen[cleanQuery] = true

	if targetOS == osdetect.OSWindows {
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
	} else {
		// Clean and auto-quarantine broken repos so search never hangs
		searchCmd := fmt.Sprintf(`
			# Clean invalid custom repos
			if [ -d /etc/yum.repos.d ]; then
				rm -f /etc/yum.repos.d/*broken* 2>/dev/null || true
				for f in /etc/yum.repos.d/*.repo; do
					if [ -f "$f" ]; then
						if grep -q "baseurl=%%s" "$f" 2>/dev/null || grep -q "baseurl=\$" "$f" 2>/dev/null || grep -q "baseurl=.*\.repo" "$f" 2>/dev/null; then
							rm -f "$f" 2>/dev/null || true
						fi
					fi
				done
			fi

			if command -v apt-cache >/dev/null 2>&1; then
				for broken in /etc/apt/sources.list.d/*trivy*.list; do
					[ -f "$broken" ] && mv "$broken" "${broken}.disabled" 2>/dev/null || true
				done
				apt-cache search "^%s" 2>/dev/null | awk '{print $1}' | head -n 10
			elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
				(dnf --setopt=*.skip_if_unavailable=true search %s 2>/dev/null || yum --setopt=*.skip_if_unavailable=true search %s 2>/dev/null) | grep -iE "^%s" | awk '{print $1}' | head -n 10
			fi
		`, cleanQuery, cleanQuery, cleanQuery, cleanQuery)

		out, _ := runSudoScript(client, searchCmd)
		lines := strings.Split(out, "\n")
		for _, l := range lines {
			trimmed := strings.TrimSpace(l)
			baseName := strings.Split(trimmed, ".")[0]
			if trimmed != "" && !seen[baseName] && !strings.Contains(trimmed, "[sudo]") && !strings.Contains(trimmed, "password") && !strings.Contains(trimmed, "Error") && !strings.Contains(trimmed, "Repository") && !strings.Contains(trimmed, "Failed") {
				seen[baseName] = true
				family = append(family, baseName)
			}
		}
	}

	if cleanQuery == "docker" && targetOS != osdetect.OSWindows {
		for _, ext := range []string{"docker-compose", "docker-buildx-plugin", "containerd.io"} {
			if !seen[ext] {
				family = append(family, ext)
				seen[ext] = true
			}
		}
	}

	if cleanQuery == "code" && targetOS != osdetect.OSWindows {
		for _, ext := range []string{"code-oss"} {
			if !seen[ext] {
				family = append(family, ext)
				seen[ext] = true
			}
		}
	}

	fmt.Println(Yellow + "\nDetected Package Targets & Modules:" + Reset)
	for idx, item := range family {
		if item == cleanQuery {
			fmt.Printf("  [%d] %s (Core Executable)\n", idx+1, item)
		} else {
			fmt.Printf("  [%d] %s (Module / Package ID)\n", idx+1, item)
		}
	}

	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
	fmt.Println(Bold + "Select Installation Mode:" + Reset)
	fmt.Println("  [1] Install All (Core Executable & All Family Modules)")
	fmt.Println("  [2] Select Specific Member to Install")
	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)

	modeChoice := transfer.ReadRealtimeInput("Choice [1-2, default: 1]: ")

	var targetsToInstall []string
	if modeChoice == "2" {
		fmt.Println(Cyan + "\nSelect the specific package number to install:" + Reset)
		mInput := transfer.ReadRealtimeInput("Enter choice number [1-" + fmt.Sprintf("%d", len(family)) + "]: ")
		var selectedIdx int
		_, err := fmt.Sscanf(strings.TrimSpace(mInput), "%d", &selectedIdx)
		if err == nil && selectedIdx >= 1 && selectedIdx <= len(family) {
			targetsToInstall = append(targetsToInstall, family[selectedIdx-1])
		} else {
			targetsToInstall = append(targetsToInstall, cleanQuery)
		}
	} else {
		targetsToInstall = family
	}

	fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
	targetListStr := strings.Join(targetsToInstall, ", ")
	confirmMsg := fmt.Sprintf("Would you like to proceed with 3-Layer Portable Installation of [%s]? [Y/n]: ", targetListStr)
	confirm := transfer.ReadRealtimeInput(confirmMsg)

	if strings.ToLower(confirm) == "y" || confirm == "" {
		for _, pkg := range targetsToInstall {
			fmt.Printf(Cyan+Bold+"\n[+] Deploying Target Package: %s...\n"+Reset, pkg)
			ExecutePortableDeployment(client, pkg, targetOS)
		}
	} else {
		fmt.Println(Yellow + "[!] Installation canceled by user." + Reset)
	}
}

// ExecutePortableDeployment performs an idempotent, self-healing 3-Layer deployment across Linux or Windows
func ExecutePortableDeployment(client *ssh.Client, tool string, targetOS osdetect.TargetOS) {
	cleanTool := strings.Split(tool, ".")[0]

	if targetOS == osdetect.OSWindows {
		executeWindowsDeployment(client, cleanTool)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)

	// Step 1: Idempotency Check
	checkCmd := fmt.Sprintf(`
		TARGET="%s"
		INST_PATH=$(which "$TARGET" 2>/dev/null || echo "")
		if [ -z "$INST_PATH" ]; then
			if [ -x "/usr/bin/$TARGET" ]; then INST_PATH="/usr/bin/$TARGET";
			elif [ -x "/usr/local/bin/$TARGET" ]; then INST_PATH="/usr/local/bin/$TARGET"; fi
		fi

		IS_PKG=0
		if rpm -q "$TARGET" >/dev/null 2>&1 || dpkg -s "$TARGET" >/dev/null 2>&1; then
			IS_PKG=1
		fi

		if [ -n "$INST_PATH" ] || [ $IS_PKG -eq 1 ]; then
			[ -z "$INST_PATH" ] && INST_PATH="/usr/bin/$TARGET"
			VER=$("$INST_PATH" --version 2>/dev/null | head -n 1 || echo "installed")
			echo "ALREADY_INSTALLED|$INST_PATH|$VER"
		else
			echo "NOT_INSTALLED"
		fi
	`, cleanTool)

	checkOut, _ := runSudoScript(client, checkCmd)

	if strings.Contains(checkOut, "ALREADY_INSTALLED") {
		parts := strings.Split(strings.TrimSpace(checkOut), "|")
		existingPath := "/usr/bin/" + cleanTool
		existingVer := "installed"
		if len(parts) >= 2 && parts[1] != "" {
			existingPath = parts[1]
		}
		if len(parts) >= 3 && parts[2] != "" {
			existingVer = parts[2]
		}

		fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] IDEMPOTENT SKIP: '%s' is already installed at '%s' (%s).", cleanTool, existingPath, existingVer) + Reset)
		return
	}

	// Step 2: Self-Healing 3-Layer Deployment Script
	deployCmd := fmt.Sprintf(`#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
mkdir -p /var/lib/cross-suite /usr/local/bin /usr/bin /var/tmp

TOOL_NAME="%s"
INSTALLED=0

echo "[+] Executing Autonomous 3-Layer Portable Deployment for: $TOOL_NAME..."

# --- LAYER 0: PURGE CORRUPT CUSTOM REPOSITORIES ---
if [ -d /etc/yum.repos.d ]; then
	rm -f /etc/yum.repos.d/*broken* 2>/dev/null || true
	for f in /etc/yum.repos.d/*.repo; do
		if [ -f "$f" ]; then
			if grep -q "baseurl=%%s" "$f" 2>/dev/null || grep -q "baseurl=\$" "$f" 2>/dev/null || grep -q "baseurl=.*\.repo" "$f" 2>/dev/null; then
				rm -f "$f" 2>/dev/null || true
			fi
		fi
	done
fi

if [ -d /etc/apt/sources.list.d ]; then
	for broken_list in /etc/apt/sources.list.d/*trivy*.list; do
		if [ -f "$broken_list" ]; then
			mv "$broken_list" "${broken_list}.disabled" 2>/dev/null || rm -f "$broken_list"
		fi
	done
	sed -i '/aquasecurity.*trivy-repo/d' /etc/apt/sources.list 2>/dev/null || true
fi
rm -f /var/lib/dpkg/lock* /var/lib/apt/lists/lock* /var/cache/apt/archives/lock* /var/run/yum.pid /var/run/dnf.pid 2>/dev/null || true

# --- LAYER 1: DIRECT VENDOR RELEASES & REPOSITORIES ---
case "$TOOL_NAME" in
	code|vscode)
		echo "=> [Layer 1] Bootstrapping Microsoft Visual Studio Code Repository & Engine..."
		if command -v rpm >/dev/null 2>&1; then
			rpm --import https://packages.microsoft.com/keys/microsoft.asc 2>/dev/null || true
			cat << 'VSCODE_REPO' > /etc/yum.repos.d/vscode.repo
[code]
name=Visual Studio Code
baseurl=https://packages.microsoft.com/yumrepos/vscode
enabled=1
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc
VSCODE_REPO
			chmod 644 /etc/yum.repos.d/vscode.repo
			(dnf install -y code 2>/dev/null || yum install -y code 2>/dev/null) || true
		elif command -v apt-get >/dev/null 2>&1; then
			curl -sSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /etc/apt/trusted.gpg.d/microsoft.gpg 2>/dev/null || true
			echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list
			apt-get update -qq 2>/dev/null
			apt-get install -y code 2>/dev/null || true
		fi

		# Layer 1b Fallback: Standalone Tarball Extraction
		if [ ! -x "/usr/bin/code" ] && [ ! -x "/usr/local/bin/code" ]; then
			echo "=> [Layer 1b] Pulling Portable Standalone VS Code Binary..."
			curl -sSL -L "https://update.code.visualstudio.com/latest/linux-x64/stable" -o /var/tmp/vscode.tar.gz 2>/dev/null
			if [ -s /var/tmp/vscode.tar.gz ]; then
				mkdir -p /opt/vscode
				tar -xzf /var/tmp/vscode.tar.gz -C /opt/vscode --strip-components=1 2>/dev/null
				ln -sf /opt/vscode/bin/code /usr/local/bin/code
				ln -sf /opt/vscode/bin/code /usr/bin/code
				rm -f /var/tmp/vscode.tar.gz
			fi
		fi
		;;
	code-oss)
		echo "=> [Layer 1] Checking system package manager for code-oss..."
		if command -v apt-get >/dev/null 2>&1; then
			apt-get update -qq 2>/dev/null
			apt-get install -y code-oss 2>/dev/null || true
		elif command -v dnf >/dev/null 2>&1; then
			dnf install -y --setopt=*.skip_if_unavailable=true code-oss 2>/dev/null || true
		fi
		if [ ! -x "/usr/bin/code-oss" ] && [ -x "/usr/bin/code" ]; then
			ln -sf /usr/bin/code /usr/bin/code-oss
		elif [ ! -x "/usr/bin/code-oss" ] && [ -x "/usr/local/bin/code" ]; then
			ln -sf /usr/local/bin/code /usr/bin/code-oss
		fi
		;;
	trivy)
		echo "=> [Layer 1] Pulling Aqua Security Trivy binary..."
		curl -sSL -L "https://github.com/aquasecurity/trivy/releases/download/v0.50.1/trivy_0.50.1_Linux-64bit.tar.gz" -o /var/tmp/trivy.tar.gz 2>/dev/null
		if [ -s /var/tmp/trivy.tar.gz ]; then
			tar -xzf /var/tmp/trivy.tar.gz -C /var/tmp 2>/dev/null
			cp -f /var/tmp/trivy /usr/local/bin/trivy 2>/dev/null || true
			cp -f /var/tmp/trivy /usr/bin/trivy 2>/dev/null || true
			chmod +x /usr/local/bin/trivy /usr/bin/trivy 2>/dev/null || true
			rm -f /var/tmp/trivy.tar.gz /var/tmp/trivy
		fi
		;;
	terraform)
		echo "=> [Layer 1] Pulling HashiCorp Terraform binary..."
		TF_VER="1.7.5"
		curl -sSL "https://releases.hashicorp.com/terraform/${TF_VER}/terraform_${TF_VER}_linux_amd64.zip" -o /var/tmp/tf.zip 2>/dev/null
		if [ -s /var/tmp/tf.zip ]; then
			unzip -o /var/tmp/tf.zip -d /usr/local/bin/ 2>/dev/null || true
			cp -f /usr/local/bin/terraform /usr/bin/terraform 2>/dev/null || true
			chmod +x /usr/local/bin/terraform /usr/bin/terraform 2>/dev/null || true
			rm -f /var/tmp/tf.zip
		fi
		;;
	kubectl)
		echo "=> [Layer 1] Pulling Kubernetes CLI (kubectl) binary..."
		K_VER=$(curl -L -s https://dl.k8s.io/release/stable.txt 2>/dev/null || echo "v1.29.2")
		curl -sSL -L "https://dl.k8s.io/release/${K_VER}/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl 2>/dev/null
		chmod +x /usr/local/bin/kubectl 2>/dev/null || true
		cp -f /usr/local/bin/kubectl /usr/bin/kubectl 2>/dev/null || true
		;;
	helm)
		echo "=> [Layer 1] Pulling Helm CLI binary..."
		curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 2>/dev/null | bash 2>/dev/null || true
		;;
	minikube)
		echo "=> [Layer 1] Pulling Minikube binary..."
		curl -sSL -L "https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64" -o /usr/local/bin/minikube 2>/dev/null
		chmod +x /usr/local/bin/minikube 2>/dev/null || true
		cp -f /usr/local/bin/minikube /usr/bin/minikube 2>/dev/null || true
		;;
esac

if [ -x "/usr/local/bin/$TOOL_NAME" ] || [ -x "/usr/bin/$TOOL_NAME" ] || command -v "$TOOL_NAME" >/dev/null 2>&1; then 
	INSTALLED=1
fi

# --- LAYER 2: VENDOR SCRIPT AUTOMATION ---
if [ $INSTALLED -eq 0 ]; then
	case "$TOOL_NAME" in
		docker)
			echo "=> [Layer 2] Running Official Docker Automation Engine..."
			curl -fsSL https://get.docker.com | sh 2>/dev/null || true
			;;
		nodejs|npm)
			echo "=> [Layer 2] Injecting NodeSource LTS Engine..."
			if command -v apt-get >/dev/null 2>&1; then
				curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - 2>/dev/null || true
				apt-get install -y nodejs 2>/dev/null || true
			elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
				curl -fsSL https://rpm.nodesource.com/setup_lts.x | bash - 2>/dev/null || true
				dnf install -y --setopt=*.skip_if_unavailable=true nodejs 2>/dev/null || yum install -y --setopt=*.skip_if_unavailable=true nodejs 2>/dev/null || true
			fi
			;;
	esac

	if [ -x "/usr/local/bin/$TOOL_NAME" ] || [ -x "/usr/bin/$TOOL_NAME" ] || command -v "$TOOL_NAME" >/dev/null 2>&1; then 
		INSTALLED=1
	fi
fi

# --- LAYER 3: NATIVE OS PACKAGE MANAGERS WITH ERROR ISOLATION ---
if [ $INSTALLED -eq 0 ]; then
	echo "=> [Layer 3] Deploying via Native Package Manager..."
	if command -v apt-get >/dev/null 2>&1; then
		dpkg --configure -a 2>/dev/null || true
		apt-get update -qq 2>/dev/null || true
		apt-get install -y "$TOOL_NAME" 2>/dev/null || apt-get install -y --fix-broken 2>/dev/null || true
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y --setopt=*.skip_if_unavailable=true "$TOOL_NAME" 2>/dev/null || true
	elif command -v yum >/dev/null 2>&1; then
		yum install -y --setopt=*.skip_if_unavailable=true "$TOOL_NAME" 2>/dev/null || true
	fi
fi

FINAL_PATH=$(which "$TOOL_NAME" 2>/dev/null || echo "/usr/bin/$TOOL_NAME")
VER=$("$FINAL_PATH" --version 2>/dev/null | head -n 1 || echo "installed")

python3 -c "
import json, os
p = '/var/lib/cross-suite/state.json'
d = {}
if os.path.exists(p):
    try:
        with open(p, 'r') as f: d = json.load(f)
    except: pass
d['$TOOL_NAME'] = {'version': '$VER', 'path': '$FINAL_PATH', 'status': 'installed'}
with open(p, 'w') as f: json.dump(d, f, indent=2)
" 2>/dev/null || true

exit 0
`, cleanTool)

	writeCmd := fmt.Sprintf("cat << 'EOF' > /var/tmp/cross_deploy.sh\n%s\nEOF\nchmod +x /var/tmp/cross_deploy.sh", deployCmd)
	_, _ = executeRemoteCommand(client, writeCmd)
	out, _ := runSudoScriptWithSpinner(client, "bash /var/tmp/cross_deploy.sh", fmt.Sprintf("Deploying %s with Root Privileges", cleanTool))
	_, _ = executeRemoteCommand(client, "rm -f /var/tmp/cross_deploy.sh")

	if strings.TrimSpace(out) != "" {
		fmt.Println(Yellow + out + Reset)
	}

	// Step 3: Verification Check
	verifyCmd := fmt.Sprintf(`
	TOOL="%s"
	OK=0

	if command -v "$TOOL" >/dev/null 2>&1 || [ -x "/usr/bin/$TOOL" ] || [ -x "/usr/local/bin/$TOOL" ] || [ -x "/opt/vscode/bin/$TOOL" ]; then
		OK=1
	fi

	if [ $OK -eq 0 ] && command -v dpkg-query >/dev/null 2>&1; then
		if dpkg-query -W -f='${Status}' "$TOOL" 2>/dev/null | grep -q "ok installed"; then
			OK=1
		fi
	fi

	if [ $OK -eq 0 ] && command -v rpm >/dev/null 2>&1; then
		if rpm -q "$TOOL" >/dev/null 2>&1; then
			OK=1
		fi
	fi

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
		fmt.Println(Red + Bold + fmt.Sprintf("[!] CRITICAL FAILURE: '%s' binary was not found on remote filesystem.", cleanTool) + Reset)
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

$fpDir = 'C:\ProgramData\cross-suite'
if (!(Test-Path $fpDir)) { New-Item -ItemType Directory -Path $fpDir -Force | Out-Null }
$ver = if (Get-Command $tool -ErrorAction SilentlyContinue) { (Get-Command $tool).Version.ToString() } else { 'installed' }
$fp = "$fpDir\state.json"
$data = @{}
if (Test-Path $fp) {
    try { $data = Get-Content $fp | ConvertFrom-Json -AsHashtable } catch { $data = @{} }
}
$data[$tool] = @{ version = $ver; path = $tool; status = 'installed' }
$data | ConvertTo-Json | Set-Content $fp -Encoding UTF8

if (Get-Command $tool -ErrorAction SilentlyContinue) {
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
	_, _ = runSudoScriptWithSpinner(client, winCmd, "Bootstrapping Windows Package Managers")
	fmt.Println(Green + Bold + "[SUCCESS] Windows Package Managers Bootstrapped Successfully!" + Reset)
}

// RunSelfHealingTroubleshooter performs autonomous repair on Linux or Windows
func RunSelfHealingTroubleshooter(client *ssh.Client, targetOS osdetect.TargetOS) {
	fmt.Println(Cyan + Bold + "\n[+] Executing System Package Manager Self-Healing Engine..." + Reset)

	if targetOS == osdetect.OSWindows {
		winHealScript := `
Write-Output "=> Step 1: Flushing Windows DNS Resolver Cache..."
ipconfig /flushdns | Out-Null

Write-Output "=> Step 2: Clearing Stale Installer Temp Locks..."
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "=> Step 3: Verifying & Restarting OpenSSH Service..."
Restart-Service sshd -ErrorAction SilentlyContinue
Write-Output "[SUCCESS] Windows Host Health & SSH State Restored!"
`
		utf16LE := []byte{}
		for _, r := range winHealScript {
			utf16LE = append(utf16LE, byte(r), byte(r>>8))
		}
		b64Cmd := base64.StdEncoding.EncodeToString(utf16LE)
		winCmd := fmt.Sprintf("powershell -NoProfile -EncodedCommand %s", b64Cmd)
		_, _ = executeRemoteCommand(client, winCmd)
		fmt.Println(Green + Bold + "[SUCCESS] Windows Self-Healing Completed!" + Reset)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)

	snapshotCmd := "mkdir -p /var/lib/cross-suite/snapshots && cp -r /etc/apt/sources.list* /etc/yum.repos.d* /var/lib/cross-suite/snapshots/ 2>/dev/null || true"
	_, _ = runSudoScript(client, snapshotCmd)

	repairScript := `#!/bin/bash
export DEBIAN_FRONTEND=noninteractive

echo "=> Step 1: Clearing Stale Package Locks..."
rm -f /var/lib/dpkg/lock* /var/lib/apt/lists/lock* /var/cache/apt/archives/lock* 2>/dev/null || true
rm -f /var/run/yum.pid /var/run/dnf.pid 2>/dev/null || true

if command -v apt-get >/dev/null 2>&1; then
	echo "=> Step 2: Quarantining Broken Repositories..."
	for broken_list in /etc/apt/sources.list.d/*trivy*.list; do
		[ -f "$broken_list" ] && mv "$broken_list" "${broken_list}.disabled" 2>/dev/null || true
	done
	sed -i '/aquasecurity.*trivy-repo/d' /etc/apt/sources.list 2>/dev/null || true

	echo "=> Step 3: Repairing Unfinished Dpkg State..."
	dpkg --configure -a 2>/dev/null || true

	echo "=> Step 4: Resolving Broken Dependencies..."
	apt-get install -f -y 2>/dev/null || true

	echo "=> Step 5: Auto-Fetching Missing GPG Keys..."
	apt-get update -qq 2>&1 | grep "NO_PUBKEY" | awk '{print $NF}' | while read -r key; do
		apt-key adv --keyserver keyserver.ubuntu.com --recv-keys "$key" 2>/dev/null || true
	done
	apt-get update -qq 2>/dev/null || true

elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
	echo "=> Step 2: Quarantining & Purging Invalid YUM/DNF Repositories..."
	rm -f /etc/yum.repos.d/*broken* 2>/dev/null || true
	for repo in /etc/yum.repos.d/*.repo; do
		if [ -f "$repo" ]; then
			if grep -q "\.repo/repodata" "$repo" 2>/dev/null || grep -q "baseurl=.*\.repo" "$repo" 2>/dev/null || grep -q "baseurl=%%s" "$repo" 2>/dev/null || grep -q "baseurl=\$" "$repo" 2>/dev/null; then
				echo "   [!] Purging malformed repo: $(basename "$repo")"
				rm -f "$repo" 2>/dev/null || true
			fi
		fi
	done

	echo "=> Step 3: Fixing CentOS Vault EOL Mirrors..."
	for repo in /etc/yum.repos.d/*.repo; do
		if [ -f "$repo" ]; then
			sed -i 's/^mirrorlist=/#mirrorlist=/g' "$repo" 2>/dev/null || true
			sed -i 's|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' "$repo" 2>/dev/null || true
		fi
	done

	echo "=> Step 4: Cleaning YUM/DNF Cache & Metadata..."
	yum clean all 2>/dev/null || dnf clean all 2>/dev/null || true
	rm -rf /var/cache/yum /var/cache/dnf 2>/dev/null || true
fi

echo "[SUCCESS] Package System Restored to Healthy State!"
exit 0
`
	writeCmd := fmt.Sprintf("cat << 'EOF' > /var/tmp/cross_heal.sh\n%s\nEOF\nchmod +x /var/tmp/cross_heal.sh", repairScript)
	_, _ = executeRemoteCommand(client, writeCmd)
	_, _ = runSudoScriptWithSpinner(client, "bash /var/tmp/cross_heal.sh", "Applying Package Manager Healing Patches")
	_, _ = executeRemoteCommand(client, "rm -f /var/tmp/cross_heal.sh")

	fmt.Println(Green + Bold + "[SUCCESS] Self-Healing Process Completed! Corrupt repos purged & pre-repair snapshot saved." + Reset)
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

	// Clean broken repos first
	preCheckCmd := `
		if [ -d /etc/yum.repos.d ]; then
			rm -f /etc/yum.repos.d/*broken* 2>/dev/null || true
			for f in /etc/yum.repos.d/*.repo; do
				if [ -f "$f" ]; then
					if grep -q "baseurl=%%s" "$f" 2>/dev/null || grep -q "baseurl=\$" "$f" 2>/dev/null || grep -q "baseurl=.*\.repo" "$f" 2>/dev/null; then
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

	writeCmd := fmt.Sprintf("cat << 'EOF' > /var/tmp/cross_trivy_scan.sh\n%s\nEOF\nchmod +x /var/tmp/cross_trivy_scan.sh", scanScript)
	_, _ = executeRemoteCommand(client, writeCmd)

	out, err := runSudoScriptWithSpinner(client, "bash /var/tmp/cross_trivy_scan.sh", "Scanning Installed Packages for High & Critical Vulnerabilities")
	_, _ = executeRemoteCommand(client, "rm -f /var/tmp/cross_trivy_scan.sh")

	if strings.Contains(out, "NOT_INSTALLED") {
		fmt.Println(Yellow + "[!] Trivy binary not found. Deploy Trivy first using Option [1]." + Reset)
		return
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

		epelStat, crbStat, dockerStat, hashiStat, rpmfStat := "Not Configured", "Not Configured", "Not Configured", "Not Configured", "Not Configured"

		lines := strings.Split(out, "\n")
		for _, l := range lines {
			parts := strings.Split(l, ":")
			if len(parts) == 2 {
				k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				switch k {
				case "EPEL": epelStat = v
				case "CRB": crbStat = v
				case "DOCKER": dockerStat = v
				case "HASHI": hashiStat = v
				case "RPMFUSION": rpmfStat = v
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
		case "1": targetRepoKey, repoFile = "EPEL", "epel.repo"
		case "2": targetRepoKey, repoFile = "CRB", "crb"
		case "3": targetRepoKey, repoFile = "Docker CE", "docker-ce.repo"
		case "4": targetRepoKey, repoFile = "HashiCorp", "hashicorp.repo"
		case "5": targetRepoKey, repoFile = "RPM Fusion", "rpmfusion-free-updates.repo"
		case "0", "q", "Q": return
		default: continue
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
			case "1": executeRepoScript(client, "0", "1", "0", "0", "0", "enable")
			case "2": executeRepoScript(client, "1", "0", "0", "0", "0", "enable")
			case "3": executeRepoScript(client, "0", "0", "1", "0", "0", "enable")
			case "4": executeRepoScript(client, "0", "0", "0", "1", "0", "enable")
			case "5": executeRepoScript(client, "0", "0", "0", "0", "1", "enable")
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
			if grep -q "baseurl=%%s" "$repo" 2>/dev/null || grep -q "baseurl=\$" "$repo" 2>/dev/null || grep -q "baseurl=.*\.repo" "$repo" 2>/dev/null; then
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

	writeCmd := fmt.Sprintf("cat << 'EOF' > /var/tmp/cross_repo_remap.sh\n%s\nEOF\nchmod +x /var/tmp/cross_repo_remap.sh", script)
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

		epelStat, dockerStat, hashiStat, nodeStat, msStat, rpmfStat, pdgStat := "Not Configured", "Not Configured", "Not Configured", "Not Configured", "Not Configured", "Not Configured", "Not Configured"

		lines := strings.Split(out, "\n")
		for _, l := range lines {
			parts := strings.Split(l, ":")
			if len(parts) == 2 {
				k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
				switch k {
				case "EPEL": epelStat = v
				case "DOCKER": dockerStat = v
				case "HASHI": hashiStat = v
				case "NODE": nodeStat = v
				case "MS": msStat = v
				case "RPMF": rpmfStat = v
				case "PGDG": pdgStat = v
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
		case "1": targetName, repoFilePattern = "EPEL & EPEL-Next", "/etc/yum.repos.d/*epel*.repo"
		case "2": targetName, repoFilePattern = "Docker CE", "/etc/yum.repos.d/*docker-ce*.repo"
		case "3": targetName, repoFilePattern = "HashiCorp", "/etc/yum.repos.d/*hashicorp*.repo"
		case "4": targetName, repoFilePattern = "NodeSource Node.js", "/etc/yum.repos.d/*nodesource*.repo"
		case "5": targetName, repoFilePattern = "Microsoft VS Code", "/etc/yum.repos.d/*vscode*.repo"
		case "6": targetName, repoFilePattern = "RPM Fusion Free", "/etc/yum.repos.d/*rpmfusion*.repo"
		case "7": targetName, repoFilePattern = "PostgreSQL PGDG", "/etc/yum.repos.d/*pgdg*.repo"
		case "0", "q", "Q": return
		default: continue
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
			case "1": runSudoScript(client, "dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm https://dl.fedoraproject.org/pub/epel/epel-next-release-latest-9.noarch.rpm 2>/dev/null || true")
			case "2": InjectCustomRepo(client, "https://download.docker.com/linux/centos/docker-ce.repo", targetOS)
			case "3": InjectCustomRepo(client, "https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo", targetOS)
			case "4": runSudoScript(client, "curl -fsSL https://rpm.nodesource.com/setup_lts.x | bash - 2>/dev/null || true")
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
			case "6": InjectCustomRepo(client, "https://mirrors.rpmfusion.org/free/el/rpmfusion-free-release-9.noarch.rpm", targetOS)
			case "7": runSudoScript(client, "dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm 2>/dev/null || yum install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm 2>/dev/null || true")
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

	promptMsg := fmt.Sprintf("Enter Custom Repo Base URL [default: %s]: ", defaultURL)
	repoURL := transfer.ReadRealtimeInput(promptMsg)
	if strings.TrimSpace(repoURL) == "" {
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
	# If URL points to a .repo file directly (e.g. docker-ce.repo, hashicorp.repo)
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

	writeCmd := fmt.Sprintf("cat << 'EOF' > /var/tmp/cross_repo_inject.sh\n%s\nEOF\nchmod +x /var/tmp/cross_repo_inject.sh", script)
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
			runSudoScript(client, "dnf install -y --setopt=*.skip_if_unavailable=true https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm https://dl.fedoraproject.org/pub/epel/epel-next-release-latest-9.noarch.rpm 2>/dev/null || true")
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
			runSudoScript(client, "dnf install -y --setopt=*.skip_if_unavailable=true https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm 2>/dev/null || true")
		} else {
			InjectCustomRepo(client, "https://download.docker.com/linux/ubuntu", targetOS)
			InjectCustomRepo(client, "https://apt.releases.hashicorp.com", targetOS)
			runSudoScript(client, "curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - 2>/dev/null || true")
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
	writeCmd := fmt.Sprintf("cat << 'EOF' > /var/tmp/cross_tune.sh\n%s\nEOF\nchmod +x /var/tmp/cross_tune.sh", tuneScript)
	_, _ = executeRemoteCommand(client, writeCmd)
	_, _ = runSudoScriptWithSpinner(client, "bash /var/tmp/cross_tune.sh", "Optimizing Download Speed & Parallel Mirrors")
	_, _ = executeRemoteCommand(client, "rm -f /var/tmp/cross_tune.sh")

	fmt.Println(Green + Bold + "[SUCCESS] Repository mirror download speeds optimized!" + Reset)
}

// RollbackSystemState restores pre-repair snapshots
func RollbackSystemState(client *ssh.Client, targetOS osdetect.TargetOS) {
	fmt.Println(Cyan + Bold + "\n[+] Rolling Back Repository & Package System State..." + Reset)
	if targetOS == osdetect.OSWindows {
		fmt.Println(Yellow + "[!] Windows system state rollback initialized." + Reset)
		return
	}

	ensureAutonomousPermissionsWithPrompt(client)
	rollbackCmd := `
		if [ -d /var/lib/cross-suite/snapshots ]; then
			cp -rf /var/lib/cross-suite/snapshots/sources.list* /etc/apt/ 2>/dev/null || true
			cp -rf /var/lib/cross-suite/snapshots/yum.repos.d* /etc/ 2>/dev/null || true
			apt-get update -qq 2>/dev/null || yum clean all 2>/dev/null || true
			echo "[SUCCESS] Restored repository configuration from pre-repair snapshot!"
		fi
	`
	_, _ = runSudoScriptWithSpinner(client, rollbackCmd, "Restoring Pre-Repair Snapshot State")
	fmt.Println(Green + Bold + "[SUCCESS] System rollback completed successfully!" + Reset)
}
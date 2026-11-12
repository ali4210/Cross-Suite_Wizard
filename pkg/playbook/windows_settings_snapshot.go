package playbook

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// windowsSnapshotRoot mirrors the Linux/macOS snapshot convention (/var/lib/cross-suite/...)
// for the one piece of Windows state this tool can reliably export and restore: the
// CurrentUser execution policy and the WinINet connection-limit registry values Option 8
// tunes. Chocolatey sources are captured in choco's own stable, documented `-r` format and
// are restored too (source add is additive, never destructive). Winget sources are captured
// only as reference text: winget has no documented stable export/import pair, so automatic
// restore is not attempted — the UI says so explicitly.
const windowsSnapshotRoot = `C:\ProgramData\cross-suite\snapshots`

type windowsSettingsSnapshotInfo struct {
	ID        string
	Path      string
	Label     string
	CreatedAt string
}

// createWindowsSettingsSnapshot captures current execution policy, Option 8's registry
// values, and Chocolatey/winget source lists to a JSON file on the target, before any
// Windows healer or mirror-tuner change. Returns the snapshot ID on success.
func createWindowsSettingsSnapshot(client *ssh.Client, label string) (id string, ok bool) {
	id = "winset-" + time.Now().UTC().Format("20060102T150405Z")
	dir := windowsSnapshotRoot + `\` + id
	path := dir + `\settings.json`

	script := fmt.Sprintf(`
New-Item -ItemType Directory -Path '%[1]s' -Force | Out-Null

$execPolicy = (Get-ExecutionPolicy -Scope CurrentUser).ToString()

$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$maxConn10 = (Get-ItemProperty -Path $regPath -Name MaxConnectionsPerServer -ErrorAction SilentlyContinue).MaxConnectionsPerServer
$maxConn11 = (Get-ItemProperty -Path $regPath -Name MaxConnectionsPer1_0Server -ErrorAction SilentlyContinue).MaxConnectionsPer1_0Server

$chocoSourcesRaw = ""
if (Get-Command choco -ErrorAction SilentlyContinue) {
    $chocoSourcesRaw = (choco source list -r 2>$null | Out-String)
}

$wingetSourcesRaw = ""
if (Get-Command winget -ErrorAction SilentlyContinue) {
    $wingetSourcesRaw = (winget source list 2>$null | Out-String)
}

$snapshot = [ordered]@{
    label = '%[2]s'
    created_at = (Get-Date).ToUniversalTime().ToString("o")
    execution_policy_current_user = $execPolicy
    max_connections_per_server = $maxConn10
    max_connections_per_1_0_server = $maxConn11
    choco_sources_raw = $chocoSourcesRaw
    winget_sources_raw_reference_only = $wingetSourcesRaw
}

$snapshot | ConvertTo-Json | Set-Content -Path '%[3]s' -Encoding UTF8
Write-Output "SNAPSHOT_CREATED"
`, dir, label, path)

	out := runWindowsPowerShell(client, script, "Snapshotting Windows settings before change")
	return id, strings.Contains(out, "SNAPSHOT_CREATED")
}

// listWindowsSettingsSnapshots enumerates every settings.json snapshot under
// windowsSnapshotRoot, newest first.
func listWindowsSettingsSnapshots(client *ssh.Client) []windowsSettingsSnapshotInfo {
	script := fmt.Sprintf(`
$root = '%s'
if (-not (Test-Path $root)) { exit 0 }
Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $settingsPath = Join-Path $_.FullName "settings.json"
    if (Test-Path $settingsPath) {
        try {
            $data = Get-Content $settingsPath -Raw | ConvertFrom-Json
            Write-Output ("SNAPSHOT|" + $_.Name + "|" + $settingsPath + "|" + $data.label + "|" + $data.created_at)
        } catch {}
    }
}
`, windowsSnapshotRoot)

	out := runWindowsPowerShell(client, script, "Listing Windows settings snapshots")

	var snaps []windowsSettingsSnapshotInfo
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "SNAPSHOT|") {
			continue
		}
		parts := strings.SplitN(line, "|", 5)
		if len(parts) < 5 {
			continue
		}
		snaps = append(snaps, windowsSettingsSnapshotInfo{ID: parts[1], Path: parts[2], Label: parts[3], CreatedAt: parts[4]})
	}
	sort.Slice(snaps, func(i, j int) bool { return snaps[i].ID > snaps[j].ID })
	return snaps
}

// restoreWindowsSettingsSnapshot restores execution policy and the Option 8 registry
// values directly (both are simple, well-documented single-value Set-ItemProperty/
// Set-ExecutionPolicy operations), and replays Chocolatey's captured sources via
// `choco source add` (additive, never destructive, using choco's own documented `-r`
// pipe format). Winget sources are only printed back as reference text — winget has no
// documented stable import counterpart to its `source list` output, so no automatic
// restore is attempted for it.
func restoreWindowsSettingsSnapshot(client *ssh.Client, snapshot windowsSettingsSnapshotInfo) string {
	script := fmt.Sprintf(`
$data = Get-Content '%s' -Raw | ConvertFrom-Json
$restored = @()

if ($data.execution_policy_current_user) {
    try {
        Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy $data.execution_policy_current_user -Force
        $restored += "ExecutionPolicy=$($data.execution_policy_current_user)"
    } catch { Write-Output "RESTORE_ERROR|execution_policy|$($_.Exception.Message)" }
}

$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
if ($null -ne $data.max_connections_per_server) {
    try {
        New-Item -Path $regPath -Force | Out-Null
        Set-ItemProperty -Path $regPath -Name MaxConnectionsPerServer -Value $data.max_connections_per_server -Type DWord
        $restored += "MaxConnectionsPerServer=$($data.max_connections_per_server)"
    } catch { Write-Output "RESTORE_ERROR|max_connections_per_server|$($_.Exception.Message)" }
}
if ($null -ne $data.max_connections_per_1_0_server) {
    try {
        Set-ItemProperty -Path $regPath -Name MaxConnectionsPer1_0Server -Value $data.max_connections_per_1_0_server -Type DWord
        $restored += "MaxConnectionsPer1_0Server=$($data.max_connections_per_1_0_server)"
    } catch { Write-Output "RESTORE_ERROR|max_connections_per_1_0_server|$($_.Exception.Message)" }
}

if ($data.choco_sources_raw -and (Get-Command choco -ErrorAction SilentlyContinue)) {
    ($data.choco_sources_raw -split '\r?\n') | ForEach-Object {
        $line = $_.Trim()
        $fields = $line -split '\|'
        if ($fields.Count -ge 5 -and $fields[0]) {
            try {
                choco source add -n="$($fields[0])" -s="$($fields[1])" --priority=$($fields[4]) -y 2>$null | Out-Null
                $restored += "choco-source:$($fields[0])"
            } catch {}
        }
    }
}

Write-Output ("RESTORED|" + ($restored -join ","))
if ($data.winget_sources_raw_reference_only) {
    Write-Output "--- Winget sources at snapshot time (REFERENCE ONLY -- not auto-restored; winget has no documented import for this) ---"
    Write-Output $data.winget_sources_raw_reference_only
}
`, snapshot.Path)

	return runWindowsPowerShell(client, script, "Restoring Windows settings snapshot")
}

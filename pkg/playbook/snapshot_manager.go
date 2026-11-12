package playbook

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"cross-ssh/pkg/osdetect"
	"cross-ssh/pkg/repohealer"
	"cross-ssh/pkg/transfer"

	"golang.org/x/crypto/ssh"
)

// snapshotManagerHomebrewSnapshotIDPattern mirrors repohealer's unexported
// homebrewSnapshotIDPattern, so a Homebrew snapshot ID is never embedded into a follow-up
// remote script here unless it matches exactly.
var snapshotManagerHomebrewSnapshotIDPattern = regexp.MustCompile(`^brew-[0-9TZ]+-[0-9a-f]+$`)

// RunSnapshotManager is Option 9: Save a checkpoint now, Show change history, Restore a chosen
// checkpoint, or Delete old checkpoints. It never installs or removes a package itself — every
// package list it captures or diffs is for reference only.
func RunSnapshotManager(client *ssh.Client, targetOS osdetect.TargetOS) {
	for {
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
		fmt.Println(Bold + Cyan + "=== OPTION 9: SNAPSHOT MANAGER ===" + Reset)
		fmt.Println("  [1] Save a checkpoint now")
		fmt.Println("  [2] Show change history")
		fmt.Println("  [3] Restore a chosen checkpoint")
		fmt.Println("  [4] Delete old checkpoints")
		fmt.Println(Red + "  [0] Return to Hub 5 Menu" + Reset)
		fmt.Println(Blue + "--------------------------------------------------------------------------------" + Reset)
		fmt.Println(Yellow + "This tool never installs or removes a package automatically — package lists are captured and diffed for reference only." + Reset)

		choice := strings.TrimSpace(transfer.ReadRealtimeInput("Select option [0-4]: "))

		switch choice {
		case "1":
			snapshotManagerSaveCheckpoint(client, targetOS)
		case "2":
			snapshotManagerShowHistory(client, targetOS)
		case "3":
			snapshotManagerRestore(client, targetOS)
		case "4":
			snapshotManagerDeleteOld(client, targetOS)
		case "0", "q", "Q", "":
			return
		default:
			fmt.Println(Yellow + "Invalid selection." + Reset)
		}
	}
}

// --- [1] Save a checkpoint now -------------------------------------------------------------

func snapshotManagerSaveCheckpoint(client *ssh.Client, targetOS osdetect.TargetOS) {
	fmt.Println(Cyan + Bold + "\n[+] Saving a checkpoint..." + Reset)

	switch targetOS {
	case osdetect.OSWindows:
		snapshotManagerSaveWindowsCheckpoint(client)
	case osdetect.OSMacOS:
		snapshotManagerSaveHomebrewCheckpoint(client)
	default:
		snapshotManagerSaveLinuxCheckpoint(client)
	}
}

func snapshotManagerSaveLinuxCheckpoint(client *ssh.Client) {
	exec := repoHealerExecutor{client: client}

	facts, _ := repohealer.DetectTargetFacts(exec, repohealer.PlatformLinux)

	files, discoverErr := repohealer.DiscoverAPTConfigFiles(exec)
	if discoverErr != nil {
		fmt.Println(Yellow + fmt.Sprintf("[!] Could not discover APT configuration files: %v", discoverErr) + Reset)
	}

	packageList, pkgOK := repohealer.CapturePackageList(exec, facts.PackageManager)
	if pkgOK {
		fmt.Println(Cyan + fmt.Sprintf("[+] Captured the current %s package list for reference (never auto-installed/removed).", facts.PackageManager) + Reset)
	} else {
		fmt.Println(Yellow + fmt.Sprintf("[!] No package-list capture is implemented for %q — continuing without one.", facts.PackageManager) + Reset)
	}

	if len(files) == 0 {
		fmt.Println(Yellow + "[!] No APT source/keyring configuration files were discovered to snapshot." + Reset)
		if !pkgOK {
			fmt.Println(Yellow + "[!] No checkpoint was recorded: nothing to snapshot and no supported package list for this target." + Reset)
			return
		}
		recordSnapshotHistory(client, "Option 9 [1]", "manual-checkpoint", "", "", nil, facts.PackageManager, packageList, repohealer.SnapshotHistoryResultManualCheckpoint)
		fmt.Println(Green + Bold + "[SUCCESS] Package-list-only checkpoint recorded (no config files were found to snapshot)." + Reset)
		return
	}

	snapshot, err := repohealer.CreateAPTFileSnapshot(exec, files)
	if err != nil || !snapshot.Created {
		fmt.Println(Red + Bold + fmt.Sprintf("[!] Could not create checkpoint snapshot: %v", err) + Reset)
		return
	}

	recordSnapshotHistory(client, "Option 9 [1]", "manual-checkpoint", snapshot.ID, snapshot.Path, files, facts.PackageManager, packageList, repohealer.SnapshotHistoryResultManualCheckpoint)
	fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] Checkpoint %s saved (%d file(s) snapshotted).", snapshot.ID, len(files)) + Reset)
	for _, f := range files {
		fmt.Println("  - " + f)
	}
}

func snapshotManagerSaveHomebrewCheckpoint(client *ssh.Client) {
	exec := repoHealerExecutor{client: client}

	snapshot, err := repohealer.CreateHomebrewSnapshot(exec)
	if err != nil || !snapshot.Created {
		fmt.Println(Red + Bold + fmt.Sprintf("[!] Could not create a Homebrew checkpoint: %v", err) + Reset)
		return
	}

	recordSnapshotHistory(client, "Option 9 [1]", "manual-checkpoint", snapshot.ID, snapshot.Path, []string{snapshot.Path}, repohealer.ManagerHomebrew, "", repohealer.SnapshotHistoryResultManualCheckpoint)
	fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] Homebrew checkpoint %s saved (Brewfile: %s).", snapshot.ID, snapshot.Path) + Reset)
}

func snapshotManagerSaveWindowsCheckpoint(client *ssh.Client) {
	id, ok := createWindowsSettingsSnapshot(client, "manual-checkpoint")
	if !ok {
		fmt.Println(Red + Bold + "[!] Could not create a Windows settings checkpoint." + Reset)
		return
	}

	packageLists := captureWindowsPackageLists(client)
	fmt.Println(Cyan + "[+] Captured winget/Chocolatey/Scoop package lists for reference (never auto-installed/removed)." + Reset)

	recordSnapshotHistory(client, "Option 9 [1]", "manual-checkpoint", id, "", nil, repohealer.ManagerWinget, packageLists, repohealer.SnapshotHistoryResultManualCheckpoint)
	fmt.Println(Green + Bold + fmt.Sprintf("[SUCCESS] Windows settings checkpoint %s saved.", id) + Reset)
}

// captureWindowsPackageLists runs winget/choco/scoop's own read-only list commands and returns
// their concatenated output for reference and diffing only — this is never parsed back into an
// install/uninstall action.
func captureWindowsPackageLists(client *ssh.Client) string {
	script := `
$out = @()
if (Get-Command winget -ErrorAction SilentlyContinue) {
    $out += "--- winget list ---"
    $out += (winget list 2>$null | Out-String)
}
if (Get-Command choco -ErrorAction SilentlyContinue) {
    $out += "--- choco list ---"
    $out += (choco list 2>$null | Out-String)
}
if (Get-Command scoop -ErrorAction SilentlyContinue) {
    $out += "--- scoop list ---"
    $out += (scoop list 2>$null | Out-String)
}
Write-Output ($out -join [Environment]::NewLine)
`
	return strings.TrimSpace(runWindowsPowerShell(client, script, "Capturing winget/Chocolatey/Scoop package lists"))
}

// --- [2] Show change history ----------------------------------------------------------------

func snapshotManagerShowHistory(client *ssh.Client, targetOS osdetect.TargetOS) {
	target := targetIdentity(client)
	path := repohealer.SnapshotHistoryPath()

	entries, err := repohealer.ListSnapshotHistoryForTarget(path, target)
	if err != nil {
		fmt.Println(Red + Bold + fmt.Sprintf("[!] Could not read change history: %v", err) + Reset)
		return
	}
	if len(entries) == 0 {
		fmt.Println(Yellow + "[!] No change history recorded yet for this target." + Reset)
		return
	}

	fmt.Println(Yellow + "\nChange history (newest first):" + Reset)
	for i, entry := range entries {
		fmt.Printf(
			"  [%d] %s | %s | %s | result=%s | snapshot=%s | files=%d\n",
			i+1,
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.Option,
			entry.Action,
			entry.Result,
			firstNonEmptyHistoryField(entry.SnapshotID, "-"),
			len(entry.FilesTouched),
		)
	}

	choice := strings.TrimSpace(transfer.ReadRealtimeInput(fmt.Sprintf("\nSelect an entry to inspect [1-%d] or 0 to go back: ", len(entries))))
	idx, convErr := strconv.Atoi(choice)
	if convErr != nil || idx < 1 || idx > len(entries) {
		return
	}

	snapshotManagerInspectHistoryEntry(client, targetOS, entries[idx-1])
}

func firstNonEmptyHistoryField(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// snapshotManagerInspectHistoryEntry shows exactly which files the selected entry's snapshot
// would restore, a real diff of each against the live file, and a package-list diff against
// the current package list — all read-only.
func snapshotManagerInspectHistoryEntry(client *ssh.Client, targetOS osdetect.TargetOS, entry repohealer.SnapshotHistoryEntry) {
	exec := repoHealerExecutor{client: client}

	fmt.Println(Cyan + Bold + "\n[+] Inspecting history entry..." + Reset)
	fmt.Printf("Timestamp: %s\nOption: %s\nAction: %s\nResult: %s\n", entry.Timestamp.Format("2006-01-02 15:04:05"), entry.Option, entry.Action, entry.Result)

	if entry.SnapshotID == "" {
		fmt.Println(Yellow + "[!] This entry has no associated file snapshot (a package-list-only checkpoint, or a blocked/declined attempt)." + Reset)
	} else {
		switch {
		case repoHealerSnapshotIDPattern.MatchString(entry.SnapshotID):
			snapshotManagerInspectAPTSnapshot(exec, entry)
		case snapshotManagerHomebrewSnapshotIDPattern.MatchString(entry.SnapshotID):
			fmt.Println(Yellow + fmt.Sprintf("[!] This is a Homebrew snapshot (%s): restoring it runs `brew bundle install` against %s, reinstalling anything the Brewfile lists that is currently missing.", entry.SnapshotID, entry.SnapshotPath) + Reset)
		case targetOS == osdetect.OSWindows:
			fmt.Println(Yellow + fmt.Sprintf("[!] This is a Windows settings snapshot (%s): restoring it resets execution policy, Option [8]'s registry values, and replays Chocolatey sources additively.", entry.SnapshotID) + Reset)
		default:
			fmt.Println(Yellow + fmt.Sprintf("[!] Unrecognized snapshot ID format %q — cannot show a detailed preview.", entry.SnapshotID) + Reset)
		}
	}

	if entry.PackageList == "" {
		return
	}

	facts, _ := repohealer.DetectTargetFacts(exec, repohealer.PlatformLinux)
	current, ok := repohealer.CapturePackageList(exec, repohealer.PackageManager(entry.PackageManager))
	if !ok {
		current, ok = repohealer.CapturePackageList(exec, facts.PackageManager)
	}
	if !ok {
		fmt.Println(Yellow + "[!] Could not capture the current package list to diff against the checkpoint." + Reset)
		return
	}

	fmt.Println(Yellow + "\nPackage list diff (checkpoint vs. now; nothing is installed or removed):" + Reset)
	fmt.Println(repohealer.DiffPackageLists(entry.PackageList, current))
}

// snapshotManagerInspectAPTSnapshot shows the exact files an APT-family snapshot would
// restore, and a real unified diff of each against its current live content.
func snapshotManagerInspectAPTSnapshot(exec repohealer.Executor, entry repohealer.SnapshotHistoryEntry) {
	files, err := listRepoHealerSnapshotFiles(exec, entry.SnapshotID)
	if err != nil {
		fmt.Println(Red + Bold + fmt.Sprintf("[!] Could not read snapshot %s: %v", entry.SnapshotID, err) + Reset)
		return
	}
	if len(files) == 0 {
		fmt.Println(Yellow + fmt.Sprintf("[!] Snapshot %s has no recorded files.", entry.SnapshotID) + Reset)
		return
	}

	fmt.Println(Yellow + fmt.Sprintf("\nFiles that would be restored from snapshot %s:", entry.SnapshotID) + Reset)
	for _, f := range files {
		fmt.Println("  - " + f)
	}

	fmt.Println(Yellow + "\nDiff of current vs. snapshot (unified diff; - = snapshot, + = current):" + Reset)
	for _, f := range files {
		out, diffErr := diffSnapshotFileAgainstLive(exec, entry.SnapshotID, f)
		if diffErr != nil {
			fmt.Println(Red + fmt.Sprintf("  %s: could not diff: %v", f, diffErr) + Reset)
			continue
		}
		trimmed := strings.TrimSpace(out)
		if trimmed == "" {
			fmt.Println("  " + f + ": no difference")
			continue
		}
		fmt.Println("--- " + f + " ---")
		fmt.Println(trimmed)
	}
}

// diffSnapshotFileAgainstLive runs a real `diff -u` between a snapshot's stored content for
// one file and that file's current content on the target. It never modifies anything.
func diffSnapshotFileAgainstLive(exec repohealer.Executor, snapshotID, path string) (string, error) {
	if !repoHealerSnapshotIDPattern.MatchString(snapshotID) {
		return "", fmt.Errorf("invalid snapshot id %q", snapshotID)
	}

	script := fmt.Sprintf(`set +e
SNAPSHOT_DIR=/var/lib/cross-suite/snapshots/%s
LIVE=%s
REL="${LIVE#/}"
CONTENT="$SNAPSHOT_DIR/files/$REL.content"

if [ ! -f "$CONTENT" ]; then
	if [ -e "$LIVE" ]; then
		echo "SNAPSHOT RECORDS THIS FILE AS ABSENT; IT NOW EXISTS"
	else
		echo "(no difference: absent in both the snapshot and now)"
	fi
	exit 0
fi

if [ ! -e "$LIVE" ]; then
	echo "SNAPSHOT RECORDS CONTENT; THE LIVE FILE IS NOW MISSING"
	exit 0
fi

diff -u "$CONTENT" "$LIVE"
exit 0
`, snapshotID, strconv.Quote(path))

	out, err := exec.RunSudo(script)
	return out, err
}

// --- [3] Restore a chosen checkpoint --------------------------------------------------------

func snapshotManagerRestore(client *ssh.Client, targetOS osdetect.TargetOS) {
	fmt.Println(Cyan + Bold + "\n[+] Restoring a checkpoint..." + Reset)
	RollbackSystemState(client, targetOS)
}

// --- [4] Delete old checkpoints --------------------------------------------------------------

func snapshotManagerDeleteOld(client *ssh.Client, targetOS osdetect.TargetOS) {
	fmt.Println(Cyan + Bold + "\n[+] Reviewing checkpoints for retention..." + Reset)

	retention := repohealer.SnapshotRetentionCount()
	fmt.Println(Cyan + fmt.Sprintf("Configured retention: keep the %d most recent checkpoint(s) (set CROSS_SUITE_SNAPSHOT_RETENTION to change).", retention) + Reset)

	switch targetOS {
	case osdetect.OSWindows:
		snapshotManagerDeleteOldWindows(client, retention)
	case osdetect.OSMacOS:
		snapshotManagerDeleteOldHomebrew(client, retention)
	default:
		snapshotManagerDeleteOldLinux(client, retention)
	}
}

func snapshotManagerDeleteOldLinux(client *ssh.Client, retention int) {
	exec := repoHealerExecutor{client: client}

	snapshots, err := listRepoHealerSnapshots(exec)
	if err != nil {
		fmt.Println(Red + Bold + fmt.Sprintf("[!] Could not list snapshots: %v", err) + Reset)
		return
	}

	ids := make([]string, 0, len(snapshots))
	for _, s := range snapshots {
		ids = append(ids, s.ID)
	}

	toPrune := repohealer.SnapshotIDsToPrune(ids, retention)
	if len(toPrune) == 0 {
		fmt.Println(Green + "Nothing to delete — checkpoint count is at or below retention (and at least one is always kept)." + Reset)
		return
	}

	fmt.Println(Yellow + fmt.Sprintf("\nThe following %d checkpoint(s) would be deleted (oldest beyond retention):", len(toPrune)) + Reset)
	for _, id := range toPrune {
		fmt.Println("  - " + id)
	}

	confirm := strings.ToLower(strings.TrimSpace(transfer.ReadRealtimeInput("Type 'yes' to permanently delete these checkpoints, or anything else to cancel: ")))
	if confirm != "yes" {
		fmt.Println(Yellow + "Deletion cancelled." + Reset)
		return
	}

	for _, id := range toPrune {
		if !repoHealerSnapshotIDPattern.MatchString(id) {
			continue
		}
		script := fmt.Sprintf("set -eu\nrm -rf -- %s\n", strconv.Quote("/var/lib/cross-suite/snapshots/"+id))
		if _, err := exec.RunSudo(script); err != nil {
			fmt.Println(Red + fmt.Sprintf("  [!] Failed to delete %s: %v", id, err) + Reset)
			continue
		}
		fmt.Println(Green + "  [OK] Deleted " + id + Reset)
	}
}

func snapshotManagerDeleteOldHomebrew(client *ssh.Client, retention int) {
	exec := repoHealerExecutor{client: client}

	snapshots, err := repohealer.ListHomebrewSnapshots(exec)
	if err != nil {
		fmt.Println(Red + Bold + fmt.Sprintf("[!] Could not list Homebrew snapshots: %v", err) + Reset)
		return
	}

	ids := make([]string, 0, len(snapshots))
	for _, s := range snapshots {
		ids = append(ids, s.ID)
	}

	toPrune := repohealer.SnapshotIDsToPrune(ids, retention)
	if len(toPrune) == 0 {
		fmt.Println(Green + "Nothing to delete — checkpoint count is at or below retention (and at least one is always kept)." + Reset)
		return
	}

	fmt.Println(Yellow + fmt.Sprintf("\nThe following %d Homebrew checkpoint(s) would be deleted:", len(toPrune)) + Reset)
	for _, id := range toPrune {
		fmt.Println("  - " + id)
	}

	confirm := strings.ToLower(strings.TrimSpace(transfer.ReadRealtimeInput("Type 'yes' to permanently delete these checkpoints, or anything else to cancel: ")))
	if confirm != "yes" {
		fmt.Println(Yellow + "Deletion cancelled." + Reset)
		return
	}

	for _, id := range toPrune {
		if !snapshotManagerHomebrewSnapshotIDPattern.MatchString(id) {
			continue
		}
		// Mirrors repohealer.defaultHomebrewSnapshotRoot ("$HOME/.cross-suite/homebrew-snapshots"),
		// which is unexported; the id has already been validated against homebrewSnapshotIDPattern
		// above, so it is safe to interpolate directly.
		script := fmt.Sprintf("set -eu\nrm -rf -- \"$HOME/.cross-suite/homebrew-snapshots/%s\"\n", id)
		if _, err := exec.Run(script); err != nil {
			fmt.Println(Red + fmt.Sprintf("  [!] Failed to delete %s: %v", id, err) + Reset)
			continue
		}
		fmt.Println(Green + "  [OK] Deleted " + id + Reset)
	}
}

func snapshotManagerDeleteOldWindows(client *ssh.Client, retention int) {
	snapshots := listWindowsSettingsSnapshots(client)

	ids := make([]string, 0, len(snapshots))
	for _, s := range snapshots {
		ids = append(ids, s.ID)
	}

	toPrune := repohealer.SnapshotIDsToPrune(ids, retention)
	if len(toPrune) == 0 {
		fmt.Println(Green + "Nothing to delete — checkpoint count is at or below retention (and at least one is always kept)." + Reset)
		return
	}

	fmt.Println(Yellow + fmt.Sprintf("\nThe following %d Windows checkpoint(s) would be deleted:", len(toPrune)) + Reset)
	for _, id := range toPrune {
		fmt.Println("  - " + id)
	}

	confirm := strings.ToLower(strings.TrimSpace(transfer.ReadRealtimeInput("Type 'yes' to permanently delete these checkpoints, or anything else to cancel: ")))
	if confirm != "yes" {
		fmt.Println(Yellow + "Deletion cancelled." + Reset)
		return
	}

	for _, id := range toPrune {
		script := fmt.Sprintf(`Remove-Item -Recurse -Force -Path '%s' -ErrorAction SilentlyContinue; Write-Output "DELETED"`, windowsSnapshotRoot+`\`+id)
		out := runWindowsPowerShell(client, script, "Deleting old Windows checkpoint")
		if strings.Contains(out, "DELETED") {
			fmt.Println(Green + "  [OK] Deleted " + id + Reset)
		} else {
			fmt.Println(Red + "  [!] Failed to delete " + id + Reset)
		}
	}
}

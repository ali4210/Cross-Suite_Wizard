package repohealer

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// RPMVerificationScript returns the post-repair health check for the given RPM-family
// package manager: `dnf makecache` for dnf/yum, `zypper --non-interactive refresh` for
// zypper. Both are read-only metadata refreshes, matching defaultAPTVerificationScript's
// role for the APT pipeline.
func RPMVerificationScript(manager PackageManager) string {
	switch manager {
	case ManagerZypper:
		return `
set +e
zypper --non-interactive refresh 2>&1
exit ${PIPESTATUS[0]}
`
	default:
		return `
set +e
dnf makecache 2>&1
exit ${PIPESTATUS[0]}
`
	}
}

// ApplyKnownRPMRepairs mirrors ApplyKnownAPTRepairs for the dnf/yum/zypper family: scans
// result's repair plan for the first eligible, known-vendor RPM repair action and applies
// it. See rpm_repair_policy.go for the operator-policy gate this additionally requires
// before anything is written.
func ApplyKnownRPMRepairs(exec Executor, result Result) RepairResult {
	actions := BuildRPMRepairPlan(result)

	for _, action := range actions {
		if !action.Eligible || !IsKnownRPMRepairFinding(action.FindingCode) {
			continue
		}

		profile, ok := FindVendorProfile(canonicalRPMManager(result.Target.PackageManager), action.RepositoryURL)
		if !ok || profile.ID != action.ProfileID {
			continue
		}

		return applyKnownRPMRepairActionWithVerification(exec, result.Target, profile, action)
	}

	return RepairResult{
		Attempted: false,
		Error:     fmt.Errorf("no eligible known-vendor RPM repair was found"),
	}
}

func applyKnownRPMRepairActionWithVerification(
	exec Executor,
	facts TargetFacts,
	profile VendorProfile,
	action RepairAction,
) RepairResult {
	repairResult := RepairResult{
		Attempted: true,
		ProfileID: profile.ID,
	}

	if !RPMRepairExecutionEnabled() {
		repairResult.Error = fmt.Errorf(
			"repair blocked: operator policy %s is not set to \"true\" on this host",
			RPMRepairExecutionEnabledEnv,
		)
		return repairResult
	}

	if err := validateRPMRepairAction(profile, action); err != nil {
		repairResult.Error = err
		return repairResult
	}

	repoFileContent, err := RenderRPMRepoFile(profile)
	if err != nil {
		repairResult.Error = fmt.Errorf(
			"repair blocked: unable to render repo file for %s: %w",
			profile.DisplayName,
			err,
		)
		return repairResult
	}

	if err := ensureRPMRepairUnlocked(exec, profile.PackageManager); err != nil {
		repairResult.Error = err
		return repairResult
	}

	// The GPG key side has no file to snapshot (rpm --import mutates the RPM database
	// directly, not a path we control) — record which gpg-pubkey NEVRAs already exist so
	// a rollback can erase only the one this repair newly imports, never a pre-existing
	// key. The .repo file itself (and the local verified-key copy at KeyringPath) is a
	// normal file this pipeline DOES snapshot and can restore byte-for-byte.
	preExistingKeys, err := listImportedRPMGPGKeys(exec)
	if err != nil {
		repairResult.Error = fmt.Errorf("repair blocked: could not enumerate existing RPM GPG keys: %w", err)
		return repairResult
	}

	snapshotTargets := []string{action.SourceFile, profile.KeyringPath}

	snapshot, err := CreateRPMFileSnapshot(exec, snapshotTargets)
	if err != nil {
		repairResult.Error = fmt.Errorf("repair blocked: could not create targeted RPM snapshot: %w", err)
		return repairResult
	}
	repairResult.Snapshot = snapshot

	tempDir := fmt.Sprintf(
		"/var/tmp/cross-suite-repoheal-%s-%d",
		profile.ID,
		time.Now().UTC().UnixNano(),
	)

	// REPO_FILE_CONTENT is delivered base64-encoded, not as a literal %q-quoted bash
	// string: a rendered .repo file legitimately contains dnf/zypper's own "$basearch"/
	// "$releasever" macros (meant for dnf/zypper to expand later, never bash), and bash
	// expands "$...") inside an ordinary double-quoted assignment regardless of Go's own
	// %q escaping — confirmed as a real failure ("basearch: unbound variable" under
	// set -u) against a live HashiCorp repo in a Fedora container. Base64 has no
	// shell-special characters, sidestepping the problem entirely, the same approach
	// rbac.go's buildSudoersInstallScript already uses for arbitrary file content.
	repoFileContentB64 := base64.StdEncoding.EncodeToString([]byte(repoFileContent))

	script := fmt.Sprintf(`
set -eu

PROFILE_ID=%q
KEY_URL=%q
KEYRING_PATH=%q
SOURCE_FILE=%q
REPO_FILE_CONTENT_B64=%q
TEMP_DIR=%q
EXPECTED_FINGERPRINTS=(%s)

KEYRING_DIR="$(dirname "$KEYRING_PATH")"
SOURCE_DIR="$(dirname "$SOURCE_FILE")"
KEYRING_TMP=""
SOURCE_TMP=""

cleanup() {
	rm -rf "$TEMP_DIR"
	if [ -n "$KEYRING_TMP" ]; then
		rm -f "$KEYRING_TMP"
	fi
	if [ -n "$SOURCE_TMP" ]; then
		rm -f "$SOURCE_TMP"
	fi
}
trap cleanup EXIT

mkdir -p "$TEMP_DIR"
install -d -m 0755 "$KEYRING_DIR"
install -d -m 0755 "$SOURCE_DIR"

export GNUPGHOME="$TEMP_DIR/gnupg"
mkdir -p "$GNUPGHOME"
chmod 0700 "$GNUPGHOME"

curl -fsSL --proto '=https' --tlsv1.2 "$KEY_URL" \
	-o "$TEMP_DIR/vendor.asc"

test -s "$TEMP_DIR/vendor.asc"

MATCHED_FINGERPRINT=""
while IFS= read -r fingerprint; do
	[ -z "$fingerprint" ] && continue

	for expected in "${EXPECTED_FINGERPRINTS[@]}"; do
		if [ "$fingerprint" = "$expected" ]; then
			MATCHED_FINGERPRINT="$fingerprint"
			break 2
		fi
	done
done < <(
	gpg --show-keys --with-colons --fingerprint "$TEMP_DIR/vendor.asc" \
	| awk -F: '$1 == "fpr" {print toupper($10)}'
)

if [ -z "$MATCHED_FINGERPRINT" ]; then
	echo "REPAIR_ERROR|fingerprint_mismatch|profile=$PROFILE_ID"
	exit 22
fi

# Only now, after the fingerprint has matched, is the key imported into the RPM
# database — never before, and never for an unmatched key.
rpm --import "$TEMP_DIR/vendor.asc"

KEYRING_TMP="$(mktemp "$KEYRING_DIR/.cross-suite-${PROFILE_ID}.keyring.XXXXXX")"
install -o root -g root -m 0644 \
	"$TEMP_DIR/vendor.asc" \
	"$KEYRING_TMP"
test -s "$KEYRING_TMP"

SOURCE_TMP="$(mktemp "$SOURCE_DIR/.cross-suite-${PROFILE_ID}.repo.XXXXXX")"
printf '%%s' "$REPO_FILE_CONTENT_B64" | base64 -d > "$SOURCE_TMP"
chown root:root "$SOURCE_TMP"
chmod 0644 "$SOURCE_TMP"
test -s "$SOURCE_TMP"

mv -f "$KEYRING_TMP" "$KEYRING_PATH"
KEYRING_TMP=""

mv -f "$SOURCE_TMP" "$SOURCE_FILE"
SOURCE_TMP=""

echo "REPAIR_APPLIED|$PROFILE_ID|fingerprint=$MATCHED_FINGERPRINT"
`,
		profile.ID,
		profile.KeyURL,
		profile.KeyringPath,
		action.SourceFile,
		repoFileContentB64,
		tempDir,
		shellArray(profile.ExpectedFingerprints),
	)

	output, err := exec.RunSudoWithLabel(script, "Restoring "+profile.DisplayName+" RPM Trust")
	repairResult.Output = strings.TrimSpace(output)

	if err != nil || !strings.Contains(output, "REPAIR_APPLIED|") {
		if err != nil {
			repairResult.Error = fmt.Errorf("key import/repo repair failed: %w", err)
		} else {
			repairResult.Error = fmt.Errorf("key import/repo repair failed: repair command did not report REPAIR_APPLIED")
		}
		rollbackErr := restoreRPMRepairState(exec, snapshot, snapshotTargets, preExistingKeys)
		repairResult.RolledBack = rollbackErr == nil
		if rollbackErr != nil {
			repairResult.Error = fmt.Errorf("%w; targeted rollback also failed: %v", repairResult.Error, rollbackErr)
		}
		return repairResult
	}

	verificationOut, verifyErr := exec.RunSudoWithLabel(
		RPMVerificationScript(profile.PackageManager),
		"Verifying RPM Repository Health",
	)
	repairResult.VerificationOut = strings.TrimSpace(verificationOut)

	if verifyErr != nil || hasRPMVerificationFailureSignature(verificationOut) {
		if verifyErr != nil {
			repairResult.Error = fmt.Errorf("post-repair RPM verification failed: %w", verifyErr)
		} else {
			repairResult.Error = fmt.Errorf("post-repair RPM verification failed: repository trust or fetch errors were reported")
		}
		rollbackErr := restoreRPMRepairState(exec, snapshot, snapshotTargets, preExistingKeys)
		repairResult.RolledBack = rollbackErr == nil
		if rollbackErr != nil {
			repairResult.Error = fmt.Errorf("%w; targeted rollback also failed: %v", repairResult.Error, rollbackErr)
		}
		return repairResult
	}

	repairResult.Applied = true
	return repairResult
}

// hasRPMVerificationFailureSignature checks for the real wording dnf/zypper report on a
// GPG/trust failure during metadata refresh (dnf: "gpg check failed" / "nokey" / "public
// key"; zypper: "signature verification failed" / "gpg check"), mirroring apt_repair.go's
// NO_PUBKEY/BADSIG/EXPKEYSIG check for the APT pipeline.
func hasRPMVerificationFailureSignature(output string) bool {
	lower := strings.ToLower(output)
	for _, signature := range []string{
		"gpg check failed",
		"nokey",
		"public key",
		"signature verification failed",
		"gpg check",
		"could not be verified",
	} {
		if strings.Contains(lower, signature) {
			return true
		}
	}
	return false
}

// restoreRPMRepairState performs the full RPM rollback sequence: prune any GPG key this
// repair newly imported (never one that already existed before it ran), then restore the
// .repo file and local verified-key copy from the pre-repair snapshot.
func restoreRPMRepairState(exec Executor, snapshot Snapshot, files []string, preExistingKeys map[string]bool) error {
	pruneErr := pruneImportedRPMGPGKeys(exec, preExistingKeys)
	restoreErr := RestoreRPMFileSnapshot(exec, snapshot, files)

	if restoreErr != nil {
		if pruneErr != nil {
			return fmt.Errorf("%w (and pruning the imported GPG key also failed: %v)", restoreErr, pruneErr)
		}
		return restoreErr
	}
	return pruneErr
}

func validateRPMRepairAction(profile VendorProfile, action RepairAction) error {
	switch profile.PackageManager {
	case ManagerDNF, ManagerYUM, ManagerZypper:
	default:
		return fmt.Errorf("repair blocked: profile %q is not an RPM-family profile", profile.ID)
	}
	if len(profile.ExpectedFingerprints) == 0 {
		return fmt.Errorf("repair blocked: %s has no pinned signing-key fingerprint", profile.ID)
	}
	if !action.Eligible {
		return fmt.Errorf("repair blocked: action %q is not eligible", action.ID)
	}
	if action.ProfileID != profile.ID {
		return fmt.Errorf(
			"repair blocked: action profile %q does not match verified profile %q",
			action.ProfileID,
			profile.ID,
		)
	}
	if !IsKnownRPMRepairFinding(action.FindingCode) {
		return fmt.Errorf("repair blocked: action %q has unsupported RPM finding code %q", action.ID, action.FindingCode)
	}
	if action.SourceFile == "" || action.SourceFile != profile.RPMRepoFile {
		return fmt.Errorf(
			"repair blocked: approved RPM repo file %q does not match verified profile repo file %q",
			action.SourceFile,
			profile.RPMRepoFile,
		)
	}
	if action.KeyringPath == "" || action.KeyringPath != profile.KeyringPath {
		return fmt.Errorf(
			"repair blocked: approved RPM key path %q does not match verified profile key path %q",
			action.KeyringPath,
			profile.KeyringPath,
		)
	}

	return nil
}

// ensureRPMRepairUnlocked checks for an active dnf/rpm transaction (the rpmdb lock file)
// or, for zypper, the same stale-vs-active lock distinction zypper.go's own diagnose
// already makes — a repair must never run concurrently with a live package operation.
func ensureRPMRepairUnlocked(exec Executor, manager PackageManager) error {
	var lockProbe string
	if manager == ManagerZypper {
		lockProbe = `
set +e
if [ -f /var/run/zypp.pid ] && pgrep -x zypper >/dev/null 2>&1; then
	printf 'RPM_LOCK_ACTIVE|owner=zypper\n'
	exit 20
fi
exit 0
`
	} else {
		lockProbe = `
set +e
if fuser /var/lib/rpm/.rpm.lock >/dev/null 2>&1; then
	owners="$(fuser /var/lib/rpm/.rpm.lock 2>/dev/null)"
	printf 'RPM_LOCK_ACTIVE|owners=%s\n' "$owners"
	exit 20
fi
exit 0
`
	}

	output, err := exec.RunSudoWithLabel(lockProbe, "Checking RPM Package-Manager Lock State")
	if err != nil || strings.Contains(output, "RPM_LOCK_ACTIVE|") {
		return fmt.Errorf(
			"repair blocked: an RPM package-manager lock is active; wait for the owning transaction to finish and retry: %s",
			strings.TrimSpace(output),
		)
	}

	return nil
}

// listImportedRPMGPGKeys returns the set of gpg-pubkey package NEVRAs currently imported
// into the RPM database, so a later rollback can tell which key (if any) this repair
// itself just added.
func listImportedRPMGPGKeys(exec Executor) (map[string]bool, error) {
	output, err := exec.RunSudo(`rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\n' 2>/dev/null || true`)
	if err != nil {
		return nil, err
	}

	keys := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			keys[line] = true
		}
	}
	return keys, nil
}

// pruneImportedRPMGPGKeys erases every currently-imported gpg-pubkey NEVRA that was not
// present in preExisting — i.e. only keys this repair itself imported — never a
// pre-existing key the host already trusted before this repair ran.
func pruneImportedRPMGPGKeys(exec Executor, preExisting map[string]bool) error {
	current, err := listImportedRPMGPGKeys(exec)
	if err != nil {
		return fmt.Errorf("could not enumerate RPM GPG keys for rollback: %w", err)
	}

	var newlyImported []string
	for nevra := range current {
		if !preExisting[nevra] {
			newlyImported = append(newlyImported, nevra)
		}
	}

	for _, nevra := range newlyImported {
		if _, err := exec.RunSudo(fmt.Sprintf("rpm -e %s", shellSingleQuote(nevra))); err != nil {
			return fmt.Errorf("could not remove newly-imported GPG key %q during rollback: %w", nevra, err)
		}
	}

	return nil
}

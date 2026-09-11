package repohealer

import (
	"fmt"
	"strings"
	"time"
)

type RepairResult struct {
	Attempted       bool
	Applied         bool
	RolledBack      bool
	Snapshot        Snapshot
	ProfileID       string
	Output          string
	VerificationOut string
	Error           error
}

const defaultAPTVerificationScript = `
set +e
apt-get update 2>&1
exit ${PIPESTATUS[0]}
`

func ApplyKnownAPTRepairs(exec Executor, result Result) RepairResult {
	actions := BuildRepairPlan(result)

	for _, action := range actions {
		if !action.Eligible || !IsKnownAPTRepairFinding(action.FindingCode) {
			continue
		}

		profile, ok := FindVendorProfile(ManagerAPT, action.RepositoryURL)
		if !ok || profile.ID != action.ProfileID {
			continue
		}

		return applyKnownAPTRepairActionWithVerification(
			exec,
			result.Target,
			profile,
			action,
			defaultAPTVerificationScript,
		)
	}

	return RepairResult{
		Attempted: false,
		Error:     fmt.Errorf("no eligible known-vendor APT repair was found"),
	}
}

func applyKnownAPTProfileRepair(
	exec Executor,
	facts TargetFacts,
	profile VendorProfile,
) RepairResult {
	action := RepairAction{
		ID:            APTRepairActionID(profile.ID, "APT_KEYRING_PATH_MISSING"),
		FindingCode:   "APT_KEYRING_PATH_MISSING",
		Eligible:      true,
		ProfileID:     profile.ID,
		RepositoryURL: profile.AllowedURLPrefixes[0],
		SourceFile:    profile.SourceFile,
		SourceFormat:  SourceFormatAPTList,
		KeyringPath:   profile.KeyringPath,
		SnapshotTargets: []string{
			profile.SourceFile,
			profile.KeyringPath,
		},
	}

	return applyKnownAPTRepairActionWithVerification(
		exec,
		facts,
		profile,
		action,
		defaultAPTVerificationScript,
	)
}

func applyKnownAPTProfileRepairWithVerification(
	exec Executor,
	facts TargetFacts,
	profile VendorProfile,
	verificationScript string,
) RepairResult {
	action := RepairAction{
		ID:            APTRepairActionID(profile.ID, "APT_KEYRING_PATH_MISSING"),
		FindingCode:   "APT_KEYRING_PATH_MISSING",
		Eligible:      true,
		ProfileID:     profile.ID,
		RepositoryURL: profile.AllowedURLPrefixes[0],
		SourceFile:    profile.SourceFile,
		SourceFormat:  SourceFormatAPTList,
		KeyringPath:   profile.KeyringPath,
		SnapshotTargets: []string{
			profile.SourceFile,
			profile.KeyringPath,
		},
	}

	return applyKnownAPTRepairActionWithVerification(
		exec,
		facts,
		profile,
		action,
		verificationScript,
	)
}

func applyKnownAPTRepairActionWithVerification(
	exec Executor,
	facts TargetFacts,
	profile VendorProfile,
	action RepairAction,
	verificationScript string,
) RepairResult {
	repairResult := RepairResult{
		Attempted: true,
		ProfileID: profile.ID,
	}

	if err := validateAPTRepairAction(profile, action); err != nil {
		repairResult.Error = err
		return repairResult
	}

	sourceLine, err := RenderAPTSource(profile, SourceRenderInput{
		Architecture: facts.Architecture,
		Distribution: facts.Distribution,
		Version:      facts.Version,
		Codename:     facts.Codename,
	})
	if err != nil {
		repairResult.Error = fmt.Errorf(
			"repair blocked: unable to render source for %s: %w",
			profile.DisplayName,
			err,
		)
		return repairResult
	}

	if err := ensureAPTRepairUnlocked(exec); err != nil {
		repairResult.Error = err
		return repairResult
	}

	snapshotTargets := []string{
		action.SourceFile,
		profile.KeyringPath,
	}

	snapshot, err := CreateAPTFileSnapshot(exec, snapshotTargets)
	if err != nil {
		repairResult.Error = fmt.Errorf(
			"repair blocked: could not create targeted APT snapshot: %w",
			err,
		)
		return repairResult
	}
	repairResult.Snapshot = snapshot

	tempDir := fmt.Sprintf(
		"/var/tmp/cross-suite-repoheal-%s-%d",
		profile.ID,
		time.Now().UTC().UnixNano(),
	)

	script := fmt.Sprintf(`
set -eu

PROFILE_ID=%q
KEY_URL=%q
KEYRING_PATH=%q
SOURCE_FILE=%q
SOURCE_LINE=%q
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

gpg --dearmor --yes \
	--output "$TEMP_DIR/vendor.gpg" \
	"$TEMP_DIR/vendor.asc"

test -s "$TEMP_DIR/vendor.gpg"

KEYRING_TMP="$(mktemp "$KEYRING_DIR/.cross-suite-${PROFILE_ID}.keyring.XXXXXX")"
install -o root -g root -m 0644 \
	"$TEMP_DIR/vendor.gpg" \
	"$KEYRING_TMP"
test -s "$KEYRING_TMP"

SOURCE_TMP="$(mktemp "$SOURCE_DIR/.cross-suite-${PROFILE_ID}.source.XXXXXX")"
printf '%%s\n' "$SOURCE_LINE" > "$SOURCE_TMP"
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
		sourceLine,
		tempDir,
		shellArray(profile.ExpectedFingerprints),
	)

	output, err := exec.RunSudoWithLabel(
		script,
		"Restoring "+profile.DisplayName+" APT Trust",
	)
	repairResult.Output = strings.TrimSpace(output)

	if err != nil || !strings.Contains(output, "REPAIR_APPLIED|") {
		if err != nil {
			repairResult.Error = fmt.Errorf("keyring/source repair failed: %w", err)
		} else {
			repairResult.Error = fmt.Errorf(
				"keyring/source repair failed: repair command did not report REPAIR_APPLIED",
			)
		}

		rollbackErr := RestoreAPTFileSnapshot(exec, snapshot, snapshotTargets)
		repairResult.RolledBack = rollbackErr == nil
		if rollbackErr != nil {
			repairResult.Error = fmt.Errorf(
				"%w; targeted rollback also failed: %v",
				repairResult.Error,
				rollbackErr,
			)
		}
		return repairResult
	}

	verificationOut, verifyErr := exec.RunSudoWithLabel(
		verificationScript,
		"Verifying APT Repository Health",
	)
	repairResult.VerificationOut = strings.TrimSpace(verificationOut)

	if verifyErr != nil ||
		strings.Contains(verificationOut, "NO_PUBKEY") ||
		strings.Contains(verificationOut, "BADSIG") ||
		strings.Contains(verificationOut, "EXPKEYSIG") ||
		strings.Contains(verificationOut, "Failed to fetch") {
		if verifyErr != nil {
			repairResult.Error = fmt.Errorf(
				"post-repair APT verification failed: %w",
				verifyErr,
			)
		} else {
			repairResult.Error = fmt.Errorf(
				"post-repair APT verification failed: repository trust or fetch errors were reported",
			)
		}

		rollbackErr := RestoreAPTFileSnapshot(exec, snapshot, snapshotTargets)
		repairResult.RolledBack = rollbackErr == nil
		if rollbackErr != nil {
			repairResult.Error = fmt.Errorf(
				"%w; targeted rollback also failed: %v",
				repairResult.Error,
				rollbackErr,
			)
		}
		return repairResult
	}

	repairResult.Applied = true
	return repairResult
}

func validateAPTRepairAction(profile VendorProfile, action RepairAction) error {
	if profile.PackageManager != ManagerAPT {
		return fmt.Errorf(
			"repair blocked: profile %q is not an APT profile",
			profile.ID,
		)
	}
	if len(profile.ExpectedFingerprints) == 0 {
		return fmt.Errorf(
			"repair blocked: %s has no pinned signing-key fingerprint",
			profile.ID,
		)
	}
	if !action.Eligible {
		return fmt.Errorf(
			"repair blocked: action %q is not eligible",
			action.ID,
		)
	}
	if action.ProfileID != profile.ID {
		return fmt.Errorf(
			"repair blocked: action profile %q does not match verified profile %q",
			action.ProfileID,
			profile.ID,
		)
	}
	if !IsKnownAPTRepairFinding(action.FindingCode) {
		return fmt.Errorf(
			"repair blocked: action %q has unsupported APT finding code %q",
			action.ID,
			action.FindingCode,
		)
	}
	if action.SourceFormat != SourceFormatAPTList {
		return fmt.Errorf(
			"repair blocked: APT source format %q is not supported for execution",
			action.SourceFormat,
		)
	}
	if action.SourceFile == "" || action.SourceFile != profile.SourceFile {
		return fmt.Errorf(
			"repair blocked: approved APT source file %q does not match verified profile source file %q",
			action.SourceFile,
			profile.SourceFile,
		)
	}
	if action.KeyringPath == "" || action.KeyringPath != profile.KeyringPath {
		return fmt.Errorf(
			"repair blocked: approved APT keyring path %q does not match verified profile keyring path %q",
			action.KeyringPath,
			profile.KeyringPath,
		)
	}

	return nil
}

func ensureAPTRepairUnlocked(exec Executor) error {
	const lockProbe = `
set +e

LOCKS=(
	/var/lib/dpkg/lock-frontend
	/var/lib/dpkg/lock
	/var/lib/apt/lists/lock
	/var/cache/apt/archives/lock
)

owners="$(fuser "${LOCKS[@]}" 2>/dev/null)"
status=$?

if [ "$status" -eq 0 ] && [ -n "$owners" ]; then
	printf 'APT_LOCK_ACTIVE|owners=%s\n' "$owners"
	exit 20
fi

exit 0
`

	output, err := exec.RunSudoWithLabel(
		lockProbe,
		"Checking APT/Dpkg Lock State",
	)
	if err != nil || strings.Contains(output, "APT_LOCK_ACTIVE|") {
		return fmt.Errorf(
			"repair blocked: APT/dpkg package-manager lock is active; wait for the owning transaction to finish and retry: %s",
			strings.TrimSpace(output),
		)
	}

	return nil
}

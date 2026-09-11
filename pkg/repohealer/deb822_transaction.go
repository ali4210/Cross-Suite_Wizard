package repohealer

import (
	"fmt"
	"strings"
	"time"
)

type Deb822RepairApplyResult struct {
	Attempted       bool
	Applied         bool
	RolledBack      bool
	Snapshot        Snapshot
	ActionID        string
	ProfileID       string
	SourceFile      string
	KeyringPath     string
	Output          string
	VerificationOut string
	Error           error
}

func ApplyDeb822RepairExecution(
	exec Executor,
	request Deb822RepairExecutionRequest,
) Deb822RepairApplyResult {
	applyResult := Deb822RepairApplyResult{
		Attempted:   true,
		ActionID:    request.ActionID,
		ProfileID:   request.ProfileID,
		SourceFile:  request.SourceFile,
		KeyringPath: request.KeyringPath,
	}

	if err := ValidateDeb822RepairExecutionRequest(request); err != nil {
		applyResult.Error = err
		return applyResult
	}

	profile, ok := FindVendorProfile(ManagerAPT, request.RepositoryURL)
	if !ok || profile.ID != request.ProfileID {
		applyResult.Error = fmt.Errorf(
			"Deb822 execution request blocked: verified profile binding changed before execution",
		)
		return applyResult
	}

	if err := ensureAPTRepairUnlocked(exec); err != nil {
		applyResult.Error = err
		return applyResult
	}

	snapshot, err := CreateAPTFileSnapshot(exec, request.SnapshotTargets)
	if err != nil {
		applyResult.Error = fmt.Errorf(
			"Deb822 repair blocked: could not create targeted APT snapshot: %w",
			err,
		)
		return applyResult
	}
	applyResult.Snapshot = snapshot

	tempDir := fmt.Sprintf(
		"/var/tmp/cross-suite-deb822-repoheal-%s-%d",
		profile.ID,
		time.Now().UTC().UnixNano(),
	)

	script := fmt.Sprintf(`
set -eu

PROFILE_ID=%q
KEY_URL=%q
KEYRING_PATH=%q
SOURCE_FILE=%q
RENDERED_SOURCE=%q
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
	echo "DEB822_REPAIR_ERROR|fingerprint_mismatch|profile=$PROFILE_ID"
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

SOURCE_TMP="$(mktemp "$SOURCE_DIR/.cross-suite-${PROFILE_ID}.sources.XXXXXX")"
printf '%%s\n' "$RENDERED_SOURCE" > "$SOURCE_TMP"
chown root:root "$SOURCE_TMP"
chmod 0644 "$SOURCE_TMP"
test -s "$SOURCE_TMP"

mv -f "$KEYRING_TMP" "$KEYRING_PATH"
KEYRING_TMP=""

mv -f "$SOURCE_TMP" "$SOURCE_FILE"
SOURCE_TMP=""

echo "DEB822_REPAIR_APPLIED|$PROFILE_ID|fingerprint=$MATCHED_FINGERPRINT"
`,
		profile.ID,
		profile.KeyURL,
		request.KeyringPath,
		request.SourceFile,
		request.RenderedSource,
		tempDir,
		shellArray(request.ExpectedFingerprints),
	)

	output, err := exec.RunSudoWithLabel(
		script,
		"Restoring "+profile.DisplayName+" Deb822 APT Trust",
	)
	applyResult.Output = strings.TrimSpace(output)

	if err != nil || !hasDeb822RepairAppliedMarker(output, profile) {
		if err != nil {
			if strings.TrimSpace(output) != "" {
				applyResult.Error = fmt.Errorf(
					"Deb822 keyring/source repair failed: %w: %s",
					err,
					strings.TrimSpace(output),
				)
			} else {
				applyResult.Error = fmt.Errorf(
					"Deb822 keyring/source repair failed: %w",
					err,
				)
			}
		} else {
			applyResult.Error = fmt.Errorf(
				"Deb822 keyring/source repair failed: repair command did not report a valid DEB822_REPAIR_APPLIED marker",
			)
		}
		rollbackDeb822Repair(exec, &applyResult, request.SnapshotTargets)
		return applyResult
	}

	verificationOut, verifyErr := exec.RunSudoWithLabel(
		defaultAPTVerificationScript,
		"Verifying Deb822 APT Repository Health",
	)
	applyResult.VerificationOut = strings.TrimSpace(verificationOut)

	if verifyErr != nil ||
		strings.Contains(verificationOut, "NO_PUBKEY") ||
		strings.Contains(verificationOut, "BADSIG") ||
		strings.Contains(verificationOut, "EXPKEYSIG") ||
		strings.Contains(verificationOut, "Failed to fetch") {
		if verifyErr != nil {
			applyResult.Error = fmt.Errorf(
				"post-repair Deb822 APT verification failed: %w",
				verifyErr,
			)
		} else {
			applyResult.Error = fmt.Errorf(
				"post-repair Deb822 APT verification failed: repository trust or fetch errors were reported",
			)
		}
		rollbackDeb822Repair(exec, &applyResult, request.SnapshotTargets)
		return applyResult
	}

	applyResult.Applied = true
	return applyResult
}

func rollbackDeb822Repair(
	exec Executor,
	applyResult *Deb822RepairApplyResult,
	snapshotTargets []string,
) {
	rollbackErr := RestoreAPTFileSnapshot(
		exec,
		applyResult.Snapshot,
		snapshotTargets,
	)
	applyResult.RolledBack = rollbackErr == nil

	if rollbackErr != nil {
		applyResult.Error = fmt.Errorf(
			"%w; targeted Deb822 rollback also failed: %v",
			applyResult.Error,
			rollbackErr,
		)
	}
}

func hasDeb822RepairAppliedMarker(
	output string,
	profile VendorProfile,
) bool {
	prefix := "DEB822_REPAIR_APPLIED|" + profile.ID + "|fingerprint="

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}

		fingerprint := strings.TrimSpace(
			strings.TrimPrefix(line, prefix),
		)
		if fingerprint == "" {
			continue
		}

		if IsPinnedFingerprint(profile, fingerprint) {
			return true
		}
	}

	return false
}

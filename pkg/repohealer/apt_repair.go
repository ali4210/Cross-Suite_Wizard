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

func ApplyKnownAPTRepairs(exec Executor, result Result) RepairResult {
	for _, finding := range result.Findings {
		if finding.Code != "APT_KEYRING_PATH_MISSING" {
			continue
		}

		profile, ok := FindVendorProfile(ManagerAPT, finding.RepositoryURL)
		if !ok {
			continue
		}

		return applyKnownAPTProfileRepair(exec, result.Target, profile)
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
	repairResult := RepairResult{
		Attempted: true,
		ProfileID: profile.ID,
	}

	if profile.PackageManager != ManagerAPT {
		repairResult.Error = fmt.Errorf(
			"repair blocked: profile %q is not an APT profile",
			profile.ID,
		)
		return repairResult
	}

	if len(profile.ExpectedFingerprints) == 0 {
		repairResult.Error = fmt.Errorf(
			"repair blocked: %s has no pinned signing-key fingerprint",
			profile.ID,
		)
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

	snapshotTargets := []string{
		profile.SourceFile,
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

cleanup() {
	rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TEMP_DIR"
install -d -m 0755 /etc/apt/keyrings

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

install -o root -g root -m 0644 \
	"$TEMP_DIR/vendor.gpg" \
	"$KEYRING_PATH"

printf '%%s\n' "$SOURCE_LINE" > "$TEMP_DIR/source.list"

install -o root -g root -m 0644 \
	"$TEMP_DIR/source.list" \
	"$SOURCE_FILE"

echo "REPAIR_APPLIED|$PROFILE_ID|fingerprint=$MATCHED_FINGERPRINT"
`,
		profile.ID,
		profile.KeyURL,
		profile.KeyringPath,
		profile.SourceFile,
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
		repairResult.Error = fmt.Errorf("keyring/source repair failed: %w", err)
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

	verificationScript := `
set +e
apt-get update 2>&1
exit ${PIPESTATUS[0]}
`

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
		repairResult.Error = fmt.Errorf(
			"post-repair APT verification failed: %w",
			verifyErr,
		)
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

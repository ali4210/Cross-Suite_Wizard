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
	Output          string
	VerificationOut string
	Error           error
}

func ApplyKnownAPTRepairs(exec Executor, result Result) RepairResult {
	repairResult := RepairResult{
		Attempted: true,
	}

	for _, finding := range result.Findings {
		if finding.Code != "APT_KEYRING_PATH_MISSING" {
			continue
		}

		profile, ok := FindVendorProfile(ManagerAPT, finding.RepositoryURL)
		if !ok || profile.ID != "microsoft-vscode" {
			continue
		}

		return applyMicrosoftVSCodeAPTRepair(exec, profile)
	}

	repairResult.Attempted = false
	repairResult.Error = fmt.Errorf("no eligible known-vendor APT repair was found")
	return repairResult
}

func applyMicrosoftVSCodeAPTRepair(exec Executor, profile VendorProfile) RepairResult {
	repairResult := RepairResult{
		Attempted: true,
	}

	if len(profile.ExpectedFingerprints) == 0 {
		repairResult.Error = fmt.Errorf(
			"repair blocked: %s has no pinned signing-key fingerprint",
			profile.ID,
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

	timestamp := time.Now().UTC().UnixNano()
	tempDir := fmt.Sprintf("/var/tmp/cross-suite-repoheal-%d", timestamp)

	script := fmt.Sprintf(`
set -eu

PROFILE_ID=%q
KEY_URL=%q
KEYRING_PATH=%q
SOURCE_FILE=%q
TEMP_DIR=%q
EXPECTED_FINGERPRINT=%q

cleanup() {
	rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

mkdir -p "$TEMP_DIR"
install -d -m 0755 /etc/apt/keyrings

export GNUPGHOME="$TEMP_DIR/gnupg"
mkdir -p "$GNUPGHOME"
chmod 0700 "$GNUPGHOME"

APT_ARCH="$(dpkg --print-architecture)"
if [ -z "$APT_ARCH" ]; then
	echo "REPAIR_ERROR|could_not_determine_apt_architecture"
	exit 20
fi

curl -fsSL --proto '=https' --tlsv1.2 "$KEY_URL" \
	-o "$TEMP_DIR/microsoft.asc"

test -s "$TEMP_DIR/microsoft.asc"

ACTUAL_FINGERPRINT="$(
	gpg --show-keys --with-colons --fingerprint "$TEMP_DIR/microsoft.asc" \
	| awk -F: '$1 == "fpr" {print toupper($10); exit}'
)"

if [ -z "$ACTUAL_FINGERPRINT" ]; then
	echo "REPAIR_ERROR|could_not_extract_fingerprint"
	exit 21
fi

if [ "$ACTUAL_FINGERPRINT" != "$EXPECTED_FINGERPRINT" ]; then
	echo "REPAIR_ERROR|fingerprint_mismatch|expected=$EXPECTED_FINGERPRINT|actual=$ACTUAL_FINGERPRINT"
	exit 22
fi

gpg --dearmor --yes \
	--output "$TEMP_DIR/microsoft.gpg" \
	"$TEMP_DIR/microsoft.asc"

test -s "$TEMP_DIR/microsoft.gpg"

install -o root -g root -m 0644 \
	"$TEMP_DIR/microsoft.gpg" \
	"$KEYRING_PATH"

printf 'deb [arch=%%s signed-by=%%s] %%s stable main\n' \
	"$APT_ARCH" \
	"$KEYRING_PATH" \
	"https://packages.microsoft.com/repos/code" \
	> "$TEMP_DIR/vscode.list"

install -o root -g root -m 0644 \
	"$TEMP_DIR/vscode.list" \
	"$SOURCE_FILE"

echo "REPAIR_APPLIED|$PROFILE_ID|fingerprint=$ACTUAL_FINGERPRINT|arch=$APT_ARCH"
`,
		profile.ID,
		profile.KeyURL,
		profile.KeyringPath,
		profile.SourceFile,
		tempDir,
		profile.ExpectedFingerprints[0],
	)

	output, err := exec.RunSudoWithLabel(
		script,
		"Restoring Microsoft VS Code APT Trust",
	)
	repairResult.Output = strings.TrimSpace(output)

	if err != nil || !strings.Contains(output, "REPAIR_APPLIED|") {
		repairResult.Error = fmt.Errorf("keyring/source repair failed: %w", err)
		_ = RestoreAPTFileSnapshot(exec, snapshot, snapshotTargets)
		repairResult.RolledBack = true
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
		strings.Contains(verificationOut, "NO_PUBKEY EB3E94ADBE1229CF") ||
		strings.Contains(verificationOut, "BADSIG") ||
		strings.Contains(verificationOut, "EXPKEYSIG") ||
		strings.Contains(verificationOut, "Failed to fetch") {
		repairResult.Error = fmt.Errorf(
			"post-repair APT verification failed: %w",
			verifyErr,
		)
		_ = RestoreAPTFileSnapshot(exec, snapshot, snapshotTargets)
		repairResult.RolledBack = true
		return repairResult
	}

	repairResult.Applied = true
	return repairResult
}

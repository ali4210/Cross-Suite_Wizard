package repohealer

import (
	"fmt"
	"reflect"
	"strings"
)

type HashiCorpAPTListRepairExecutionStatus string

const (
	HashiCorpAPTListRepairExecutionBlocked HashiCorpAPTListRepairExecutionStatus = "blocked"
	HashiCorpAPTListRepairExecutionFailed  HashiCorpAPTListRepairExecutionStatus = "failed"
	HashiCorpAPTListRepairExecutionApplied HashiCorpAPTListRepairExecutionStatus = "applied"
)

type HashiCorpAPTListRepairExecutionResult struct {
	Status          HashiCorpAPTListRepairExecutionStatus
	ActionID        string
	ProfileID       string
	KeyringPath     string
	Attempted       bool
	Applied         bool
	RolledBack      bool
	Output          string
	VerificationOut string
	Reason          string
}

func ExecuteHashiCorpAPTListRepair(
	exec Executor,
	request HashiCorpAPTListRepairExecutionRequest,
	preflight HashiCorpAPTListRepairPreflight,
) HashiCorpAPTListRepairExecutionResult {
	result := HashiCorpAPTListRepairExecutionResult{
		Status:      HashiCorpAPTListRepairExecutionBlocked,
		ActionID:    request.ActionID,
		ProfileID:   request.ProfileID,
		KeyringPath: request.KeyringPath,
	}

	if err := validateHashiCorpAPTListRepairExecutionRequest(request); err != nil {
		result.Reason = err.Error()
		return result
	}

	if !preflight.Ready {
		result.Reason = fmt.Sprintf(
			"HashiCorp APT-list repair execution blocked: preflight is not ready: %s",
			strings.TrimSpace(preflight.Reason),
		)
		return result
	}

	if !reflect.DeepEqual(preflight.Request, request) {
		result.Reason = "HashiCorp APT-list repair execution blocked: preflight request does not match the approved request"
		return result
	}

	freshProbe, err := ProbeHashiCorpAPTListRepairPreflight(exec, request)
	if err != nil {
		result.Reason = fmt.Sprintf(
			"HashiCorp APT-list repair execution blocked: fresh preflight probe failed: %v",
			err,
		)
		return result
	}

	freshPreflight := EvaluateHashiCorpAPTListRepairPreflight(
		request,
		freshProbe,
		preflight.DoctorReport,
	)
	if !freshPreflight.Ready {
		result.Reason = fmt.Sprintf(
			"HashiCorp APT-list repair execution blocked: fresh preflight is not ready: %s",
			strings.TrimSpace(freshPreflight.Reason),
		)
		return result
	}

	return applyHashiCorpAPTListRepairExecution(
		exec,
		request,
		freshPreflight.DoctorReport,
	)
}

func buildHashiCorpAPTListRepairExecutionScript(
	request HashiCorpAPTListRepairExecutionRequest,
) (string, error) {
	if err := validateHashiCorpAPTListRepairExecutionRequest(request); err != nil {
		return "", fmt.Errorf(
			"HashiCorp APT-list repair execution script blocked: invalid request: %w",
			err,
		)
	}

	profile, ok := FindVendorProfileByID(
		ManagerAPT,
		HashiCorpAPTListProfileID,
	)
	if !ok || profile.ID != request.ProfileID {
		return "", fmt.Errorf(
			"HashiCorp APT-list repair execution script blocked: verified profile binding is unavailable",
		)
	}

	return fmt.Sprintf(`
set -eu

PROFILE_ID=%q
KEY_URL=%q
KEYRING_PATH=%q
EXPECTED_FINGERPRINT=%q
TEMP_DIR="$(mktemp -d /var/tmp/cross-suite-hashicorp-apt-list-repair.XXXXXX)"
chmod 0700 "$TEMP_DIR"

KEYRING_DIR="$(dirname "$KEYRING_PATH")"
KEYRING_TMP=""

cleanup() {
	rm -rf "$TEMP_DIR"
	if [ -n "$KEYRING_TMP" ]; then
		rm -f "$KEYRING_TMP"
	fi
}
trap cleanup EXIT

mkdir -p "$TEMP_DIR"
install -d -m 0755 "$KEYRING_DIR"

export GNUPGHOME="$TEMP_DIR/gnupg"
mkdir -p "$GNUPGHOME"
chmod 0700 "$GNUPGHOME"

curl -fsSL --proto '=https' --tlsv1.2 "$KEY_URL" \
	-o "$TEMP_DIR/vendor.asc"

test -s "$TEMP_DIR/vendor.asc"

MATCHED_FINGERPRINT=""
while IFS= read -r fingerprint; do
	[ -z "$fingerprint" ] && continue
	if [ "$fingerprint" = "$EXPECTED_FINGERPRINT" ]; then
		MATCHED_FINGERPRINT="$fingerprint"
		break
	fi
done < <(
	gpg --show-keys --with-colons --fingerprint "$TEMP_DIR/vendor.asc" \
	| awk -F: '$1 == "fpr" {print toupper($10)}'
)

if [ -z "$MATCHED_FINGERPRINT" ]; then
	echo "HASHICORP_APT_LIST_REPAIR_ERROR|fingerprint_mismatch|profile=$PROFILE_ID"
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

mv -f "$KEYRING_TMP" "$KEYRING_PATH"
KEYRING_TMP=""

echo "HASHICORP_APT_LIST_REPAIR_APPLIED|$PROFILE_ID|fingerprint=$MATCHED_FINGERPRINT"
`,
		profile.ID,
		request.KeyURL,
		request.KeyringPath,
		request.ExpectedFingerprint,
	), nil
}

func hasHashiCorpAPTListRepairAppliedMarker(
	output string,
	request HashiCorpAPTListRepairExecutionRequest,
) bool {
	profile, ok := FindVendorProfileByID(
		ManagerAPT,
		HashiCorpAPTListProfileID,
	)
	if !ok || profile.ID != request.ProfileID {
		return false
	}

	prefix := "HASHICORP_APT_LIST_REPAIR_APPLIED|" +
		profile.ID +
		"|fingerprint="

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

		if fingerprint == request.ExpectedFingerprint &&
			IsPinnedFingerprint(profile, fingerprint) {
			return true
		}
	}

	return false
}

func applyHashiCorpAPTListRepairExecution(
	exec Executor,
	request HashiCorpAPTListRepairExecutionRequest,
	report APTListDoctorReport,
) HashiCorpAPTListRepairExecutionResult {
	result := HashiCorpAPTListRepairExecutionResult{
		Status:      HashiCorpAPTListRepairExecutionFailed,
		ActionID:    request.ActionID,
		ProfileID:   request.ProfileID,
		KeyringPath: request.KeyringPath,
		Attempted:   true,
	}

	if err := validateHashiCorpAPTListRepairExecutionRequest(request); err != nil {
		result.Status = HashiCorpAPTListRepairExecutionBlocked
		result.Attempted = false
		result.Reason = err.Error()
		return result
	}

	if err := ValidateAPTListDoctorReport(report); err != nil {
		result.Status = HashiCorpAPTListRepairExecutionBlocked
		result.Attempted = false
		result.Reason = fmt.Sprintf(
			"HashiCorp APT-list repair execution blocked: Doctor report is invalid: %v",
			err,
		)
		return result
	}

	snapshotTargets := []string{request.KeyringPath}
	snapshot, err := CreateAPTFileSnapshot(exec, snapshotTargets)
	if err != nil {
		result.Reason = fmt.Sprintf(
			"HashiCorp APT-list repair execution failed: could not create keyring snapshot: %v",
			err,
		)
		return result
	}
	_ = snapshot

	script, err := buildHashiCorpAPTListRepairExecutionScript(request)
	if err != nil {
		result.Status = HashiCorpAPTListRepairExecutionBlocked
		result.Attempted = false
		result.Reason = err.Error()
		return result
	}

	output, err := exec.RunSudoWithLabel(
		script,
		"Repairing HashiCorp APT Signing Key",
	)
	result.Output = strings.TrimSpace(output)

	if err != nil {
		result.Reason = fmt.Sprintf(
			"HashiCorp APT-list repair execution failed: %v",
			err,
		)
		rollbackHashiCorpAPTListRepairExecution(
			exec,
			&result,
			snapshot,
			snapshotTargets,
		)
		return result
	}

	if !hasHashiCorpAPTListRepairAppliedMarker(output, request) {
		result.Reason = "HashiCorp APT-list repair execution failed: repair command did not report a valid success marker"
		rollbackHashiCorpAPTListRepairExecution(
			exec,
			&result,
			snapshot,
			snapshotTargets,
		)
		return result
	}

	verificationOutput, verificationErr := exec.RunSudoWithLabel(
		hashicorpAPTListRepairVerificationScript(request),
		"Verify HashiCorp APT repository trust",
	)
	result.VerificationOut = strings.TrimSpace(verificationOutput)
	if verificationErr != nil {
		result.Reason = fmt.Sprintf(
			"HashiCorp APT-list repair verification failed: %v",
			verificationErr,
		)
		rollbackHashiCorpAPTListRepairExecution(
			exec,
			&result,
			snapshot,
			snapshotTargets,
		)
		return result
	}

	if hashicorpAPTListRepairVerificationFailed(verificationOutput, request) {
		result.Reason = "HashiCorp APT-list repair verification failed: apt-get update reported a HashiCorp repository trust or fetch error"
		rollbackHashiCorpAPTListRepairExecution(
			exec,
			&result,
			snapshot,
			snapshotTargets,
		)
		return result
	}

	result.Status = HashiCorpAPTListRepairExecutionApplied

	result.Applied = true
	result.Reason = ""
	return result
}

const hashicorpAPTListRepairVerificationHost = "apt.releases.hashicorp.com"

func hashicorpAPTListRepairVerificationScript(
	request HashiCorpAPTListRepairExecutionRequest,
) string {
	return "apt-get update 2>&1\n" +
		"exitCode=$?\n" +
		"printf '\\nHASHICORP_APT_LIST_REPAIR_VERIFIED|host=" +
		hashicorpAPTListRepairVerificationHost +
		"|exit=%s\\n' \"$exitCode\"\n" +
		"exit 0"
}

func hashicorpAPTListRepairVerificationFailed(
	output string,
	request HashiCorpAPTListRepairExecutionRequest,
) bool {
	normalized := strings.ToLower(output)
	host := strings.ToLower(hashicorpAPTListRepairVerificationHost)
	marker := "HASHICORP_APT_LIST_REPAIR_VERIFIED|host=" +
		hashicorpAPTListRepairVerificationHost + "|exit=0"

	if !strings.Contains(output, marker) {
		return true
	}

	if !strings.Contains(normalized, host) {
		return false
	}

	for _, indicator := range []string{
		"no_pubkey",
		"gpg error:",
		"the following signatures couldn't be verified",
		"failed to fetch",
		"hash sum mismatch",
	} {
		if strings.Contains(normalized, indicator) {
			return true
		}
	}

	return false
}

func rollbackHashiCorpAPTListRepairExecution(
	exec Executor,
	result *HashiCorpAPTListRepairExecutionResult,
	snapshot Snapshot,
	snapshotTargets []string,
) {
	rollbackErr := RestoreAPTFileSnapshot(exec, snapshot, snapshotTargets)
	result.RolledBack = rollbackErr == nil

	if rollbackErr != nil {
		result.Reason = fmt.Sprintf(
			"%s; targeted HashiCorp APT-list keyring rollback also failed: %v",
			result.Reason,
			rollbackErr,
		)
	}
}

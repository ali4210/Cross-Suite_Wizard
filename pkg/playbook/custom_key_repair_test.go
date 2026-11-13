package playbook

import (
	"os"
	"strings"
	"testing"
)

// TestConfirmCustomRepositoryKeyFingerprintNeverWeakensTheGate is a source-order guardrail
// (confirmCustomRepositoryKeyFingerprint takes a real *ssh.Client, so it cannot be unit-tested
// directly without a live connection): it confirms the function checks operator policy and
// runs the safety gate before ever asking for the typed fingerprint, requires the *exact*
// fingerprint rather than a bare "yes", and never references a keyserver.
func TestConfirmCustomRepositoryKeyFingerprintNeverWeakensTheGate(t *testing.T) {
	source, err := os.ReadFile("universal_healer.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	code := string(source)

	funcStart := strings.Index(code, "func confirmCustomRepositoryKeyFingerprint(")
	if funcStart == -1 {
		t.Fatal("expected confirmCustomRepositoryKeyFingerprint to exist")
	}
	funcEnd := strings.Index(code[funcStart:], "\n// InjectCustomRepoIndexed")
	if funcEnd == -1 {
		t.Fatal("could not find the end of confirmCustomRepositoryKeyFingerprint")
	}
	body := code[funcStart : funcStart+funcEnd]

	policyIndex := strings.Index(body, "printOperatorPolicyGateIfDisabled(")
	safetyIndex := strings.Index(body, "EvaluateGatedAPTRepairSafety(")
	promptIndex := strings.Index(body, "Type the exact fingerprint shown above to confirm")

	if policyIndex == -1 || safetyIndex == -1 || promptIndex == -1 {
		t.Fatal("expected policy check, safety gate, and typed-fingerprint prompt to all be present")
	}
	if policyIndex > promptIndex || safetyIndex > promptIndex {
		t.Fatal("the policy check and safety gate must both come before the typed-fingerprint prompt")
	}
	if strings.Contains(body, "keyserver") {
		t.Fatal("confirm-the-fingerprint mode must never reference a keyserver")
	}
	if !strings.Contains(body, "NormalizeFingerprint(typed)") || !strings.Contains(body, "NormalizeFingerprint(preview)") {
		t.Fatal("expected the typed response to be compared against the previewed fingerprint, not a bare yes/no")
	}
}

// TestCustomRepoKeyFetchReVerifiesFingerprintBeforeInstalling confirms the apply script itself
// (not just the preview/confirm step) re-checks the fingerprint immediately before dearmoring
// and installing the key — defense in depth against the key changing between preview and apply.
func TestCustomRepoKeyFetchReVerifiesFingerprintBeforeInstalling(t *testing.T) {
	source, err := os.ReadFile("universal_healer.go")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	code := string(source)

	keyFetchStart := strings.Index(code, "keyFetch = fmt.Sprintf(`")
	if keyFetchStart == -1 {
		t.Fatal("expected the APT keyFetch script template to exist")
	}
	keyFetchEnd := strings.Index(code[keyFetchStart:], "`,")
	if keyFetchEnd == -1 {
		t.Fatal("could not find the end of the keyFetch script template")
	}
	script := code[keyFetchStart : keyFetchStart+keyFetchEnd]

	if !strings.Contains(script, "ACTUAL_FP") || !strings.Contains(script, "fingerprint_mismatch") {
		t.Fatal("expected the key-fetch script to compare the downloaded fingerprint and fail closed on mismatch")
	}
	gpgShowKeysIndex := strings.Index(script, "gpg --show-keys")
	gpgDearmorIndex := strings.Index(script, "gpg --dearmor")
	if gpgShowKeysIndex == -1 || gpgDearmorIndex == -1 || gpgShowKeysIndex > gpgDearmorIndex {
		t.Fatal("expected the fingerprint check to happen before dearmoring/installing the key")
	}
}

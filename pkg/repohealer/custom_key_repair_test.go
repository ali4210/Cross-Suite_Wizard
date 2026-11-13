package repohealer

import (
	"errors"
	"testing"
)

func TestPreviewCustomRepositoryKeyFingerprintRejectsNonHTTPS(t *testing.T) {
	exec := &fakeExecutor{}

	_, err := PreviewCustomRepositoryKeyFingerprint(exec, "http://example.invalid/key.asc")
	if err == nil {
		t.Fatal("expected an error for a non-HTTPS key URL")
	}
	if len(exec.commands) != 0 {
		t.Fatalf("a non-HTTPS URL must never reach the shell, got %d commands", len(exec.commands))
	}
}

func TestPreviewCustomRepositoryKeyFingerprintReturnsSingleFingerprint(t *testing.T) {
	exec := &fakeExecutor{runOutputs: []string{"D55C0D1AC78A8D8126CB631CFC9CA96ACA026560\n"}}

	got, err := PreviewCustomRepositoryKeyFingerprint(exec, "https://example.invalid/key.asc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "D55C0D1AC78A8D8126CB631CFC9CA96ACA026560" {
		t.Fatalf("got %q", got)
	}

	if len(exec.commands) != 1 || exec.commands[0][:4] != "RUN:" {
		t.Fatalf("expected a single non-sudo Run call, got %v", exec.commands)
	}
}

func TestPreviewCustomRepositoryKeyFingerprintRejectsMultipleFingerprints(t *testing.T) {
	exec := &fakeExecutor{runOutputs: []string{"AAAA\nBBBB\n"}}

	_, err := PreviewCustomRepositoryKeyFingerprint(exec, "https://example.invalid/key.asc")
	if err == nil {
		t.Fatal("expected an error for a bundle of multiple fingerprints")
	}
}

func TestPreviewCustomRepositoryKeyFingerprintRejectsEmptyResult(t *testing.T) {
	exec := &fakeExecutor{runOutputs: []string{""}}

	_, err := PreviewCustomRepositoryKeyFingerprint(exec, "https://example.invalid/key.asc")
	if err == nil {
		t.Fatal("expected an error when no fingerprint is found")
	}
}

func TestPreviewCustomRepositoryKeyFingerprintPropagatesDownloadFailure(t *testing.T) {
	exec := &fakeExecutor{runErrors: []error{errors.New("curl: (6) Could not resolve host")}}

	_, err := PreviewCustomRepositoryKeyFingerprint(exec, "https://example.invalid/key.asc")
	if err == nil {
		t.Fatal("expected a download failure to propagate")
	}
}

func TestPreviewCustomRepositoryKeyFingerprintScriptNeverUsesAKeyserver(t *testing.T) {
	exec := &fakeExecutor{runOutputs: []string{"AAAABBBBCCCCDDDDEEEEFFFF0000111122223333\n"}}

	if _, err := PreviewCustomRepositoryKeyFingerprint(exec, "https://example.invalid/key.asc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(exec.commands) != 1 {
		t.Fatalf("expected exactly one command, got %d", len(exec.commands))
	}
	if containsSubstring(exec.commands[0], "keyserver") {
		t.Fatalf("the preview script must never reference a keyserver: %s", exec.commands[0])
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"d55c 0d1a c78a 8d81 26cb 631c fc9c a96a ca02 6560", "D55C0D1AC78A8D8126CB631CFC9CA96ACA026560"},
		{"  D55C0D1AC78A8D8126CB631CFC9CA96ACA026560  ", "D55C0D1AC78A8D8126CB631CFC9CA96ACA026560"},
	}
	for _, test := range tests {
		if got := NormalizeFingerprint(test.input); got != test.want {
			t.Fatalf("NormalizeFingerprint(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

func TestCustomKeyRepairExecutionEnabledRequiresExactTrue(t *testing.T) {
	t.Setenv(CustomKeyRepairExecutionEnabledEnv, "")
	if CustomKeyRepairExecutionEnabled() {
		t.Fatal("expected disabled by default")
	}

	t.Setenv(CustomKeyRepairExecutionEnabledEnv, "true")
	if !CustomKeyRepairExecutionEnabled() {
		t.Fatal("expected enabled when set to true")
	}

	t.Setenv(CustomKeyRepairExecutionEnabledEnv, "1")
	if CustomKeyRepairExecutionEnabled() {
		t.Fatal("expected disabled for any value other than exactly 'true'")
	}
}

func containsSubstring(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

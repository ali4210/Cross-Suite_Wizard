package repohealer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestHashiCorpAPTListRepairPreflightProbeScriptSplitsRealFileMetadataFields runs the actual
// generated probe script (not a hand-written fixture) against a real file with bash, the same
// way it runs over SSH in production. It would have caught a real bug where the uid and
// sha256sum fields were corrupted by a fmt.Sprintf double-escaping mistake (%% collapsing to a
// single %, turning a longest-match shell parameter expansion into a shortest-match one) that
// every other test in this package missed because they all feed hand-written output strings
// straight into the parser instead of exercising the shell script itself.
func TestHashiCorpAPTListRepairPreflightProbeScriptSplitsRealFileMetadataFields(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	for _, tool := range []string{"stat", "sha256sum", "gpg", "install", "mv"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}

	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "hashicorp.list")
	keyringPath := filepath.Join(dir, "hashicorp-archive-keyring.gpg")

	content := "deb [signed-by=" + keyringPath + "] https://apt.releases.hashicorp.com noble main\n"
	if err := os.WriteFile(sourcePath, []byte(content), 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}
	// Deliberately not root-owned in this test process, so the FILE record takes the
	// "unsafe_owner" branch — the exact branch whose extra uid|mode|size|hash fields were
	// corrupted by the bug, while still exercising full real field extraction end to end.

	// Exercises the exact same production template buildHashiCorpAPTListRepairPreflightProbeScript
	// uses, substituted against an arbitrary temp path instead of the pinned HashiCorp source/
	// keyring paths that function's request validation requires (and that this process has no
	// permission to write to without root).
	script := strings.ReplaceAll(
		hashicorpAPTListRepairPreflightProbeScriptTemplate,
		"@@SOURCE_PATH@@",
		shellSingleQuote(sourcePath),
	)
	script = strings.ReplaceAll(script, "@@KEYRING_PATH@@", shellSingleQuote(keyringPath))

	out, err := exec.Command("bash", "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("real probe script failed: %v\noutput: %s", err, out)
	}

	probe, err := parseHashiCorpAPTListRepairPreflightProbeOutput(string(out))
	if err != nil {
		t.Fatalf("parseHashiCorpAPTListRepairPreflightProbeOutput() error = %v\nraw output: %s", err, out)
	}

	wantUID := os.Getuid()
	if probe.Source.UID != wantUID {
		t.Fatalf("source UID = %d, want %d (real process UID)", probe.Source.UID, wantUID)
	}
	if probe.Source.Mode != "644" {
		t.Fatalf("source mode = %q, want 644", probe.Source.Mode)
	}
	if probe.Source.Size != int64(len(content)) {
		t.Fatalf("source size = %d, want %d", probe.Source.Size, len(content))
	}

	wantHash, err := exec.Command("sha256sum", sourcePath).Output()
	if err != nil {
		t.Fatalf("sha256sum reference: %v", err)
	}
	wantHashHex := strings.Fields(string(wantHash))[0]
	if probe.Source.SHA256 != wantHashHex {
		t.Fatalf("source SHA-256 = %q, want %q (and must have no trailing space)", probe.Source.SHA256, wantHashHex)
	}
	if strings.HasSuffix(probe.Source.SHA256, " ") {
		t.Fatalf("source SHA-256 has a trailing space: %q", probe.Source.SHA256)
	}
}

package repohealer

import (
	"strings"
	"testing"
)

func TestPreviewDeb822RepairReturnsExactBoundReview(t *testing.T) {
	inspection, request := readyDockerDeb822ApprovalInputs(t)

	got := PreviewDeb822Repair(inspection, request)

	if !got.Ready {
		t.Fatalf("preview was not ready: %s", got.Reason)
	}
	if got.Reason != "" {
		t.Fatalf("reason = %q, want empty", got.Reason)
	}
	if got.ActionID != request.ActionID {
		t.Fatalf("action ID = %q, want %q", got.ActionID, request.ActionID)
	}
	if got.FindingCode != request.FindingCode {
		t.Fatalf("finding code = %q, want %q", got.FindingCode, request.FindingCode)
	}
	if got.ProfileID != request.ProfileID {
		t.Fatalf("profile ID = %q, want %q", got.ProfileID, request.ProfileID)
	}
	if got.ProfileDisplayName != request.ProfileDisplayName {
		t.Fatalf(
			"profile display name = %q, want %q",
			got.ProfileDisplayName,
			request.ProfileDisplayName,
		)
	}
	if got.RepositoryURL != request.RepositoryURL {
		t.Fatalf(
			"repository URL = %q, want %q",
			got.RepositoryURL,
			request.RepositoryURL,
		)
	}
	if got.SourceFile != request.SourceFile {
		t.Fatalf("source file = %q, want %q", got.SourceFile, request.SourceFile)
	}
	if got.KeyringPath != request.KeyringPath {
		t.Fatalf("keyring path = %q, want %q", got.KeyringPath, request.KeyringPath)
	}
	if got.RenderedSource != request.RenderedSource {
		t.Fatalf("rendered source = %q, want %q", got.RenderedSource, request.RenderedSource)
	}
	if !sameOrderedStrings(got.SnapshotTargets, request.SnapshotTargets) {
		t.Fatalf(
			"snapshot targets = %#v, want %#v",
			got.SnapshotTargets,
			request.SnapshotTargets,
		)
	}
	if !sameOrderedStrings(got.ExpectedFingerprints, request.ExpectedFingerprints) {
		t.Fatalf(
			"fingerprints = %#v, want %#v",
			got.ExpectedFingerprints,
			request.ExpectedFingerprints,
		)
	}
}

func TestPreviewDeb822RepairBlocksInvalidBinding(t *testing.T) {
	inspection, request := readyDockerDeb822ApprovalInputs(t)
	request.SourceFile = "/etc/apt/sources.list.d/other.sources"

	got := PreviewDeb822Repair(inspection, request)

	if got.Ready {
		t.Fatalf("unsafe preview unexpectedly ready: %#v", got)
	}
	if strings.TrimSpace(got.Reason) == "" {
		t.Fatalf("blocked preview reason is empty: %#v", got)
	}
	if got.SourceFile != request.SourceFile {
		t.Fatalf(
			"preview should identify reviewed request source file = %q, want %q",
			got.SourceFile,
			request.SourceFile,
		)
	}
}

func TestPreviewDeb822RepairDefensivelyCopiesSlices(t *testing.T) {
	inspection, request := readyDockerDeb822ApprovalInputs(t)

	got := PreviewDeb822Repair(inspection, request)
	if !got.Ready {
		t.Fatalf("preview was not ready: %s", got.Reason)
	}

	originalTarget := got.SnapshotTargets[0]
	originalFingerprint := got.ExpectedFingerprints[0]

	request.SnapshotTargets[0] = "/tmp/tampered.sources"
	request.ExpectedFingerprints[0] = "TAMPERED"

	if got.SnapshotTargets[0] != originalTarget {
		t.Fatalf(
			"preview snapshot target changed after request mutation: %q",
			got.SnapshotTargets[0],
		)
	}
	if got.ExpectedFingerprints[0] != originalFingerprint {
		t.Fatalf(
			"preview fingerprint changed after request mutation: %q",
			got.ExpectedFingerprints[0],
		)
	}
}

func TestPreviewDeb822RepairDoesNotRequireExecutionPolicy(t *testing.T) {
	t.Setenv(deb822RepairExecutionEnabledEnv, "")

	inspection, request := readyDockerDeb822ApprovalInputs(t)

	got := PreviewDeb822Repair(inspection, request)

	if !got.Ready {
		t.Fatalf(
			"preview must remain available while execution policy is disabled: %s",
			got.Reason,
		)
	}
}

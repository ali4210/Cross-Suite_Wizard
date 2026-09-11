package repohealer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
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

func TestBuildDeb822RepairPreviewAuditEvent(t *testing.T) {
	inspection, request := readyDockerDeb822ApprovalInputs(t)
	preview := PreviewDeb822Repair(inspection, request)
	occurredAt := time.Date(2026, time.September, 12, 0, 0, 0, 0, time.UTC)

	got := BuildDeb822RepairPreviewAuditEvent(preview, occurredAt)

	if got.Event != "apt_deb822_repository_repair_preview" {
		t.Fatalf("event = %q", got.Event)
	}
	if !got.Ready {
		t.Fatalf("ready = false, want true")
	}
	if got.ActionID != request.ActionID {
		t.Fatalf("action ID = %q, want %q", got.ActionID, request.ActionID)
	}
	if got.ProfileID != request.ProfileID {
		t.Fatalf("profile ID = %q, want %q", got.ProfileID, request.ProfileID)
	}
	if !got.OccurredAt.Equal(occurredAt) {
		t.Fatalf("occurred at = %s, want %s", got.OccurredAt, occurredAt)
	}
	if got.FailureCategory != "" {
		t.Fatalf("failure category = %q, want empty", got.FailureCategory)
	}
}

func TestBuildDeb822RepairPreviewAuditEventForBlockedPreview(t *testing.T) {
	event := BuildDeb822RepairPreviewAuditEvent(
		Deb822RepairDryRunResult{
			ActionID:    "apt-source-binding-repair-docker-ce",
			ProfileID:   "docker-ce",
			SourceFile:  "/etc/apt/sources.list.d/docker.sources",
			KeyringPath: "/etc/apt/keyrings/docker.gpg",
			Reason:      "SECRET_BLOCK_REASON_DO_NOT_LOG",
		},
		time.Now(),
	)

	if event.Ready {
		t.Fatalf("ready = true, want false")
	}
	if event.FailureCategory != RepairFailureBlocked {
		t.Fatalf(
			"failure category = %q, want %q",
			event.FailureCategory,
			RepairFailureBlocked,
		)
	}
}

func TestDeb822RepairPreviewAuditEventDoesNotContainRenderedSourceOrReason(t *testing.T) {
	event := BuildDeb822RepairPreviewAuditEvent(
		Deb822RepairDryRunResult{
			ActionID:       "apt-source-binding-repair-docker-ce",
			ProfileID:      "docker-ce",
			SourceFile:     "/etc/apt/sources.list.d/docker.sources",
			KeyringPath:    "/etc/apt/keyrings/docker.gpg",
			RenderedSource: "SECRET_RENDERED_SOURCE_DO_NOT_LOG",
			Reason:         "SECRET_PREVIEW_REASON_DO_NOT_LOG",
		},
		time.Now(),
	)

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	for _, forbidden := range []string{
		"SECRET_RENDERED_SOURCE_DO_NOT_LOG",
		"SECRET_PREVIEW_REASON_DO_NOT_LOG",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("preview audit JSON must not contain %q: %s", forbidden, encoded)
		}
	}
}

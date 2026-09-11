package repohealer

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildDeb822RepairAuditEventForAppliedRepair(t *testing.T) {
	occurredAt := time.Date(
		2026,
		time.September,
		12,
		2,
		10,
		0,
		0,
		time.FixedZone("+06", 6*60*60),
	)

	event := BuildDeb822RepairAuditEvent(
		Deb822RepairApprovalResult{
			Status:      Deb822RepairApprovalStatusApplied,
			ActionID:    "apt-source-binding-repair-docker-ce",
			ProfileID:   "docker-ce",
			SourceFile:  "/etc/apt/sources.list.d/docker.sources",
			KeyringPath: "/etc/apt/keyrings/docker.gpg",
			ApplyResult: Deb822RepairApplyResult{
				Attempted: true,
				Applied:   true,
				Snapshot: Snapshot{
					ID:      "apt-test",
					Path:    "/var/lib/cross-suite/snapshots/apt-test",
					Created: true,
				},
			},
		},
		occurredAt,
	)

	if event.Event != "apt_deb822_repository_repair" {
		t.Fatalf("event = %q", event.Event)
	}
	if event.Status != Deb822RepairApprovalStatusApplied {
		t.Fatalf("status = %q", event.Status)
	}
	if event.FailureCategory != RepairFailureNone {
		t.Fatalf("failure category = %q", event.FailureCategory)
	}
	if !event.RepairAttempted || !event.Applied || event.RolledBack {
		t.Fatalf("unexpected event state: %#v", event)
	}
	if event.SourceFile != "/etc/apt/sources.list.d/docker.sources" {
		t.Fatalf("source file = %q", event.SourceFile)
	}
	if event.KeyringPath != "/etc/apt/keyrings/docker.gpg" {
		t.Fatalf("keyring path = %q", event.KeyringPath)
	}
	if !event.OccurredAt.Equal(occurredAt.UTC()) {
		t.Fatalf("occurred at = %s, want %s", event.OccurredAt, occurredAt.UTC())
	}
}

func TestBuildDeb822RepairAuditEventClassifiesStates(t *testing.T) {
	tests := []struct {
		name string
		in   Deb822RepairApprovalResult
		want RepairFailureCategory
	}{
		{
			name: "Blocked",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusBlocked,
				Reason: "inspection invalid",
			},
			want: RepairFailureBlocked,
		},
		{
			name: "Declined",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusDeclined,
			},
			want: RepairFailureDeclined,
		},
		{
			name: "Fingerprint failure",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusFailed,
				Reason: "DEB822_REPAIR_ERROR|fingerprint_mismatch",
			},
			want: RepairFailureFingerprint,
		},
		{
			name: "Verification failure",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusFailed,
				Reason: "post-repair Deb822 APT verification failed",
			},
			want: RepairFailureVerification,
		},
		{
			name: "Snapshot failure",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusFailed,
				Reason: "could not create targeted APT snapshot",
			},
			want: RepairFailureSnapshot,
		},
		{
			name: "Rollback failure",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusFailed,
				Reason: "targeted Deb822 rollback also failed",
			},
			want: RepairFailureRollback,
		},
		{
			name: "Generic execution failure",
			in: Deb822RepairApprovalResult{
				Status: Deb822RepairApprovalStatusFailed,
				Reason: "key download command failed",
			},
			want: RepairFailureExecution,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := BuildDeb822RepairAuditEvent(test.in, time.Now())
			if event.FailureCategory != test.want {
				t.Fatalf(
					"failure category = %q, want %q",
					event.FailureCategory,
					test.want,
				)
			}
		})
	}
}

func TestDeb822RepairAuditEventJSONDoesNotContainRawExecutionData(t *testing.T) {
	event := BuildDeb822RepairAuditEvent(
		Deb822RepairApprovalResult{
			Status:      Deb822RepairApprovalStatusFailed,
			ActionID:    "apt-source-binding-repair-docker-ce",
			ProfileID:   "docker-ce",
			SourceFile:  "/etc/apt/sources.list.d/docker.sources",
			KeyringPath: "/etc/apt/keyrings/docker.gpg",
			Reason:      "SECRET_REASON_DO_NOT_LOG",
			ApplyResult: Deb822RepairApplyResult{
				Attempted:       true,
				Output:          "SECRET_MUTATION_OUTPUT_DO_NOT_LOG",
				VerificationOut: "SECRET_VERIFICATION_OUTPUT_DO_NOT_LOG",
			},
		},
		time.Now(),
	)

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	text := string(encoded)
	for _, forbidden := range []string{
		"SECRET_REASON_DO_NOT_LOG",
		"SECRET_MUTATION_OUTPUT_DO_NOT_LOG",
		"SECRET_VERIFICATION_OUTPUT_DO_NOT_LOG",
		"RenderedSource",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("audit JSON must not contain %q: %s", forbidden, text)
		}
	}
}

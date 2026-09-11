package repohealer

import (
	"strings"
	"testing"
)

func validDockerDeb822ExecutionRequest(
	t *testing.T,
) Deb822RepairExecutionRequest {
	t.Helper()

	action := blockedDockerDeb822RepairAction()
	profile := dockerDeb822Profile(t)
	inspection := readyDockerDeb822Inspection(action, profile)

	request, err := BuildDeb822RepairExecutionRequest(
		inspection,
		action,
		profile,
	)
	if err != nil {
		t.Fatalf("BuildDeb822RepairExecutionRequest() error = %v", err)
	}

	return request
}

func TestValidateDeb822RepairExecutionRequestAcceptsBoundRequest(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)

	if err := ValidateDeb822RepairExecutionRequest(request); err != nil {
		t.Fatalf("ValidateDeb822RepairExecutionRequest() error = %v", err)
	}
}

func TestPrepareDeb822RepairExecutionReturnsReadyForBoundRequest(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)

	got := PrepareDeb822RepairExecution(request)

	if got.Status != Deb822RepairExecutionStatusReady {
		t.Fatalf(
			"status = %q, want %q; reason = %q",
			got.Status,
			Deb822RepairExecutionStatusReady,
			got.Reason,
		)
	}
	if got.Reason != "" {
		t.Fatalf("reason = %q, want empty", got.Reason)
	}
	if got.ActionID != request.ActionID {
		t.Fatalf("action ID = %q, want %q", got.ActionID, request.ActionID)
	}
	if got.ProfileID != request.ProfileID {
		t.Fatalf("profile ID = %q, want %q", got.ProfileID, request.ProfileID)
	}
	if got.SourceFile != request.SourceFile {
		t.Fatalf("source file = %q, want %q", got.SourceFile, request.SourceFile)
	}
	if got.KeyringPath != request.KeyringPath {
		t.Fatalf("keyring path = %q, want %q", got.KeyringPath, request.KeyringPath)
	}
}

func TestPrepareDeb822RepairExecutionBlocksUnsafeRequest(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*Deb822RepairExecutionRequest)
		wantReason string
	}{
		{
			name: "Incomplete request binding",
			mutate: func(request *Deb822RepairExecutionRequest) {
				request.ActionID = ""
			},
			wantReason: "request binding is incomplete",
		},
		{
			name: "Non Deb822 source format",
			mutate: func(request *Deb822RepairExecutionRequest) {
				request.SourceFormat = SourceFormatAPTList
			},
			wantReason: "is not Deb822",
		},
		{
			name: "Unknown profile",
			mutate: func(request *Deb822RepairExecutionRequest) {
				request.ProfileID = "unknown-profile"
			},
			wantReason: "does not match verified profile",
		},
		{
			name: "Profile display name mismatch",
			mutate: func(request *Deb822RepairExecutionRequest) {
				request.ProfileDisplayName = "Untrusted Profile"
			},
			wantReason: "profile display name",
		},
		{
			name: "Keyring mismatch",
			mutate: func(request *Deb822RepairExecutionRequest) {
				request.KeyringPath = "/etc/apt/keyrings/other.gpg"
			},
			wantReason: "does not match verified profile keyring path",
		},
		{
			name: "Repository URL mismatch",
			mutate: func(request *Deb822RepairExecutionRequest) {
				request.RepositoryURL = "https://download.docker.com/linux/debian/extra"
			},
			wantReason: "is not exact for profile",
		},
		{
			name: "Unsafe source path",
			mutate: func(request *Deb822RepairExecutionRequest) {
				request.SourceFile = "/tmp/docker.sources"
			},
			wantReason: "is outside /etc/apt/sources.list.d",
		},
		{
			name: "Missing rendered replacement",
			mutate: func(request *Deb822RepairExecutionRequest) {
				request.RenderedSource = ""
			},
			wantReason: "has no rendered replacement source",
		},
		{
			name: "Tampered rendered replacement",
			mutate: func(request *Deb822RepairExecutionRequest) {
				request.RenderedSource = strings.Replace(
					request.RenderedSource,
					"Signed-By: "+request.KeyringPath,
					"Signed-By: /etc/apt/keyrings/other.gpg",
					1,
				)
			},
			wantReason: "rendered replacement source is invalid",
		},
		{
			name: "Snapshot scope mismatch",
			mutate: func(request *Deb822RepairExecutionRequest) {
				request.SnapshotTargets = []string{
					request.SourceFile,
					"/etc/apt/keyrings/other.gpg",
				}
			},
			wantReason: "snapshot targets do not match",
		},
		{
			name: "Missing fingerprints",
			mutate: func(request *Deb822RepairExecutionRequest) {
				request.ExpectedFingerprints = nil
			},
			wantReason: "has no pinned signing-key fingerprints",
		},
		{
			name: "Fingerprint mismatch",
			mutate: func(request *Deb822RepairExecutionRequest) {
				request.ExpectedFingerprints = []string{
					"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
				}
			},
			wantReason: "do not match verified profile fingerprints",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validDockerDeb822ExecutionRequest(t)
			request.SnapshotTargets = append(
				[]string(nil),
				request.SnapshotTargets...,
			)
			request.ExpectedFingerprints = append(
				[]string(nil),
				request.ExpectedFingerprints...,
			)

			test.mutate(&request)

			got := PrepareDeb822RepairExecution(request)

			if got.Status != Deb822RepairExecutionStatusBlocked {
				t.Fatalf(
					"status = %q, want %q",
					got.Status,
					Deb822RepairExecutionStatusBlocked,
				)
			}
			if !strings.Contains(got.Reason, test.wantReason) {
				t.Fatalf(
					"reason = %q, want it to contain %q",
					got.Reason,
					test.wantReason,
				)
			}
			if got.ActionID != request.ActionID {
				t.Fatalf("action ID = %q, want %q", got.ActionID, request.ActionID)
			}
			if got.ProfileID != request.ProfileID {
				t.Fatalf("profile ID = %q, want %q", got.ProfileID, request.ProfileID)
			}
			if got.SourceFile != request.SourceFile {
				t.Fatalf(
					"source file = %q, want %q",
					got.SourceFile,
					request.SourceFile,
				)
			}
			if got.KeyringPath != request.KeyringPath {
				t.Fatalf(
					"keyring path = %q, want %q",
					got.KeyringPath,
					request.KeyringPath,
				)
			}
		})
	}
}

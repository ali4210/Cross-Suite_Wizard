package repohealer

import (
	"strings"
	"testing"
)

func readyDockerDeb822ApprovalInputs(
	t *testing.T,
) (Deb822RepairInspection, Deb822RepairExecutionRequest) {
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

	return inspection, request
}

func approvedDockerDeb822Executor() *fakeExecutor {
	return &fakeExecutor{
		runSudoOutputs: []string{
			"",
		},
		runSudoLabelOutputs: []string{
			"DEB822_REPAIR_APPLIED|docker-ce|fingerprint=9DC858229FC7DD38854AE2D88D81803C0EBFCD88\n",
			"Hit:1 https://download.docker.com/linux/debian bookworm InRelease\n",
		},
	}
}

func TestApproveAndApplyDeb822RepairAppliesExactApprovedRequest(t *testing.T) {
	inspection, request := readyDockerDeb822ApprovalInputs(t)
	exec := approvedDockerDeb822Executor()

	got := ApproveAndApplyDeb822Repair(
		exec,
		inspection,
		request,
		"yes",
	)

	if got.Status != Deb822RepairApprovalStatusApplied {
		t.Fatalf(
			"status = %q, want %q; reason = %q",
			got.Status,
			Deb822RepairApprovalStatusApplied,
			got.Reason,
		)
	}
	if got.Reason != "" {
		t.Fatalf("reason = %q, want empty", got.Reason)
	}
	if !got.ApplyResult.Applied {
		t.Fatalf("apply result = %#v, want applied", got.ApplyResult)
	}
	if len(exec.commands) != 4 {
		t.Fatalf(
			"command count = %d, want lock, snapshot, mutation, verification",
			len(exec.commands),
		)
	}
}

func TestApproveAndApplyDeb822RepairDeclinesWithoutCommands(t *testing.T) {
	inspection, request := readyDockerDeb822ApprovalInputs(t)
	exec := &fakeExecutor{}

	got := ApproveAndApplyDeb822Repair(
		exec,
		inspection,
		request,
		"no",
	)

	if got.Status != Deb822RepairApprovalStatusDeclined {
		t.Fatalf(
			"status = %q, want %q",
			got.Status,
			Deb822RepairApprovalStatusDeclined,
		)
	}
	if !strings.Contains(got.Reason, "was not approved") {
		t.Fatalf("reason = %q, want decline reason", got.Reason)
	}
	if got.ApplyResult.Attempted {
		t.Fatalf(
			"declined repair unexpectedly attempted execution: %#v",
			got.ApplyResult,
		)
	}
	if len(exec.commands) != 0 {
		t.Fatalf("declined repair ran commands: %#v", exec.commands)
	}
}

func TestApproveAndApplyDeb822RepairRejectsNonExplicitApproval(t *testing.T) {
	inspection, request := readyDockerDeb822ApprovalInputs(t)

	responses := []string{
		"",
		" ",
		"approve",
		"ok",
		"true",
		"1",
		"yes please",
		"YEs!",
	}

	for _, response := range responses {
		t.Run(response, func(t *testing.T) {
			exec := &fakeExecutor{}

			got := ApproveAndApplyDeb822Repair(
				exec,
				inspection,
				request,
				response,
			)

			if got.Status != Deb822RepairApprovalStatusDeclined {
				t.Fatalf(
					"status = %q, want %q for response %q",
					got.Status,
					Deb822RepairApprovalStatusDeclined,
					response,
				)
			}
			if len(exec.commands) != 0 {
				t.Fatalf(
					"response %q ran commands: %#v",
					response,
					exec.commands,
				)
			}
		})
	}
}

func TestApproveAndApplyDeb822RepairAcceptsCaseInsensitiveExplicitApproval(t *testing.T) {
	inspection, request := readyDockerDeb822ApprovalInputs(t)

	for _, response := range []string{
		"yes",
		"YES",
		" Yes ",
		"y",
		"Y",
	} {
		t.Run(response, func(t *testing.T) {
			exec := approvedDockerDeb822Executor()

			got := ApproveAndApplyDeb822Repair(
				exec,
				inspection,
				request,
				response,
			)

			if got.Status != Deb822RepairApprovalStatusApplied {
				t.Fatalf(
					"status = %q, want %q for response %q; reason = %q",
					got.Status,
					Deb822RepairApprovalStatusApplied,
					response,
					got.Reason,
				)
			}
		})
	}
}

func TestApproveAndApplyDeb822RepairBlocksUnsafeBindingsWithoutCommands(t *testing.T) {
	baseInspection, baseRequest := readyDockerDeb822ApprovalInputs(t)

	tests := []struct {
		name       string
		mutate     func(*Deb822RepairInspection, *Deb822RepairExecutionRequest)
		wantReason string
	}{
		{
			name: "Inspection not ready",
			mutate: func(
				inspection *Deb822RepairInspection,
				request *Deb822RepairExecutionRequest,
			) {
				inspection.Ready = false
				inspection.BlockReason = "document changed"
			},
			wantReason: "inspection is not ready",
		},
		{
			name: "Invalid request",
			mutate: func(
				inspection *Deb822RepairInspection,
				request *Deb822RepairExecutionRequest,
			) {
				request.SourceFile = "/tmp/docker.sources"
			},
			wantReason: "execution request is invalid",
		},
		{
			name: "Action mismatch",
			mutate: func(
				inspection *Deb822RepairInspection,
				request *Deb822RepairExecutionRequest,
			) {
				request.ActionID = "different-action"
			},
			wantReason: "does not match the exact execution request",
		},
		{
			name: "Profile mismatch",
			mutate: func(
				inspection *Deb822RepairInspection,
				request *Deb822RepairExecutionRequest,
			) {
				request.ProfileID = "microsoft-vscode"
			},
			wantReason: "execution request is invalid",
		},
		{
			name: "Source path mismatch",
			mutate: func(
				inspection *Deb822RepairInspection,
				request *Deb822RepairExecutionRequest,
			) {
				request.SourceFile = "/etc/apt/sources.list.d/other.sources"
				request.SnapshotTargets[0] = request.SourceFile
			},
			wantReason: "does not match the exact execution request",
		},
		{
			name: "Keyring mismatch",
			mutate: func(
				inspection *Deb822RepairInspection,
				request *Deb822RepairExecutionRequest,
			) {
				request.KeyringPath = "/etc/apt/keyrings/other.gpg"
				request.SnapshotTargets[1] = request.KeyringPath
			},
			wantReason: "execution request is invalid",
		},
		{
			name: "Rendered source mismatch",
			mutate: func(
				inspection *Deb822RepairInspection,
				request *Deb822RepairExecutionRequest,
			) {
				request.RenderedSource += "# changed\n"
			},
			wantReason: "does not match the exact execution request",
		},
		{
			name: "Snapshot scope order mismatch",
			mutate: func(
				inspection *Deb822RepairInspection,
				request *Deb822RepairExecutionRequest,
			) {
				request.SnapshotTargets[0],
					request.SnapshotTargets[1] =
					request.SnapshotTargets[1],
					request.SnapshotTargets[0]
			},
			wantReason: "execution request is invalid",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inspection := baseInspection
			inspection.SnapshotTargets = append(
				[]string(nil),
				baseInspection.SnapshotTargets...,
			)

			request := baseRequest
			request.SnapshotTargets = append(
				[]string(nil),
				baseRequest.SnapshotTargets...,
			)
			request.ExpectedFingerprints = append(
				[]string(nil),
				baseRequest.ExpectedFingerprints...,
			)

			test.mutate(&inspection, &request)

			exec := &fakeExecutor{}
			got := ApproveAndApplyDeb822Repair(
				exec,
				inspection,
				request,
				"yes",
			)

			if got.Status != Deb822RepairApprovalStatusBlocked {
				t.Fatalf(
					"status = %q, want %q; reason = %q",
					got.Status,
					Deb822RepairApprovalStatusBlocked,
					got.Reason,
				)
			}
			if !strings.Contains(got.Reason, test.wantReason) {
				t.Fatalf(
					"reason = %q, want it to contain %q",
					got.Reason,
					test.wantReason,
				)
			}
			if got.ApplyResult.Attempted {
				t.Fatalf(
					"unsafe approval unexpectedly attempted execution: %#v",
					got.ApplyResult,
				)
			}
			if len(exec.commands) != 0 {
				t.Fatalf(
					"unsafe approval ran commands: %#v",
					exec.commands,
				)
			}
		})
	}
}

func TestApproveAndApplyDeb822RepairReturnsExecutionFailure(t *testing.T) {
	inspection, request := readyDockerDeb822ApprovalInputs(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoLabelOutputs: []string{
			"DEB822_REPAIR_APPLIED|docker-ce|fingerprint=9DC858229FC7DD38854AE2D88D81803C0EBFCD88\n",
			"NO_PUBKEY 0000000000000000\n",
		},
	}

	got := ApproveAndApplyDeb822Repair(
		exec,
		inspection,
		request,
		"yes",
	)

	if got.Status != Deb822RepairApprovalStatusFailed {
		t.Fatalf(
			"status = %q, want %q",
			got.Status,
			Deb822RepairApprovalStatusFailed,
		)
	}
	if !got.ApplyResult.RolledBack {
		t.Fatalf(
			"apply result = %#v, want rolled back failure",
			got.ApplyResult,
		)
	}
	if !strings.Contains(got.Reason, "post-repair Deb822 APT verification failed") &&
		!strings.Contains(
			got.Reason,
			"repository trust or fetch errors were reported",
		) {
		t.Fatalf("reason = %q, want execution failure reason", got.Reason)
	}
	if len(exec.commands) != 5 {
		t.Fatalf(
			"command count = %d, want lock, snapshot, mutation, verification, rollback",
			len(exec.commands),
		)
	}
}

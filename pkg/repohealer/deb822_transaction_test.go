package repohealer

import (
	"errors"
	"strings"
	"testing"
)

func TestApplyDeb822RepairExecutionAppliesBoundRequest(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
		},
		runSudoLabelOutputs: []string{
			"DEB822_REPAIR_APPLIED|docker-ce|fingerprint=9DC858229FC7DD38854AE2D88D81803C0EBFCD88\n",
			"Hit:1 https://download.docker.com/linux/debian bookworm InRelease\n",
		},
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if !got.Attempted {
		t.Fatal("repair was not marked attempted")
	}
	if !got.Applied {
		t.Fatalf("repair was not applied: %#v", got)
	}
	if got.RolledBack {
		t.Fatalf("repair unexpectedly rolled back: %#v", got)
	}
	if got.Error != nil {
		t.Fatalf("repair error = %v", got.Error)
	}
	if !got.Snapshot.Created {
		t.Fatalf("snapshot = %#v, want created snapshot", got.Snapshot)
	}
	if len(exec.commands) != 4 {
		t.Fatalf("command count = %d, want 4", len(exec.commands))
	}
	if !strings.Contains(exec.commands[0], "Checking APT/Dpkg Lock State") {
		t.Fatalf("first command did not probe APT locks:\n%s", exec.commands[0])
	}
	if !strings.Contains(exec.commands[1], "SNAPSHOT_DIR") {
		t.Fatalf("second command did not create a snapshot:\n%s", exec.commands[1])
	}
	if !strings.Contains(exec.commands[2], "DEB822_REPAIR_APPLIED|") {
		t.Fatalf("third command did not contain Deb822 mutation marker:\n%s", exec.commands[2])
	}
	if !strings.Contains(exec.commands[2], request.SourceFile) {
		t.Fatalf("mutation command missing approved source file:\n%s", exec.commands[2])
	}
	if !strings.Contains(exec.commands[2], request.KeyringPath) {
		t.Fatalf("mutation command missing approved keyring path:\n%s", exec.commands[2])
	}
	if !strings.Contains(
		exec.commands[2],
		"RENDERED_SOURCE="+shellQuote(request.RenderedSource),
	) {
		t.Fatalf(
			"mutation command missing quoted rendered Deb822 source binding:\n%s",
			exec.commands[2],
		)
	}
	if !strings.Contains(exec.commands[3], "apt-get update") {
		t.Fatalf("fourth command did not verify with apt-get update:\n%s", exec.commands[3])
	}
}

func TestApplyDeb822RepairExecutionBlocksInvalidRequestBeforeCommands(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	request.SourceFile = "/tmp/docker.sources"

	exec := &fakeExecutor{}
	got := ApplyDeb822RepairExecution(exec, request)

	if !got.Attempted {
		t.Fatal("repair was not marked attempted")
	}
	if got.Applied {
		t.Fatalf("invalid repair was applied: %#v", got)
	}
	if got.RolledBack {
		t.Fatalf("invalid repair unexpectedly rolled back: %#v", got)
	}
	if got.Error == nil {
		t.Fatal("expected blocked request error")
	}
	if !strings.Contains(got.Error.Error(), "outside /etc/apt/sources.list.d") {
		t.Fatalf("error = %q, want unsafe source path rejection", got.Error)
	}
	if len(exec.commands) != 0 {
		t.Fatalf("invalid request ran commands: %#v", exec.commands)
	}
}

func TestApplyDeb822RepairExecutionBlocksOnLockBeforeSnapshot(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		lockProbeOutput: "APT_LOCK_ACTIVE|owners=4321\n",
		lockProbeError:  errors.New("exit status 20"),
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if got.Applied {
		t.Fatalf("locked repair was applied: %#v", got)
	}
	if got.Snapshot.Created {
		t.Fatalf("snapshot was created while lock was active: %#v", got.Snapshot)
	}
	if got.RolledBack {
		t.Fatalf("locked repair unexpectedly rolled back: %#v", got)
	}
	if got.Error == nil ||
		!strings.Contains(got.Error.Error(), "package-manager lock is active") {
		t.Fatalf("error = %v, want APT lock rejection", got.Error)
	}
	if len(exec.commands) != 1 {
		t.Fatalf("command count = %d, want lock probe only", len(exec.commands))
	}
}

func TestApplyDeb822RepairExecutionFailsBeforeMutationWhenSnapshotFails(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		runSudoErrors: []error{
			errors.New("snapshot storage unavailable"),
		},
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if got.Applied {
		t.Fatalf("repair was applied after snapshot failure: %#v", got)
	}
	if got.Snapshot.Created {
		t.Fatalf("snapshot marked created after failure: %#v", got.Snapshot)
	}
	if got.RolledBack {
		t.Fatalf("repair rolled back despite no successful snapshot: %#v", got)
	}
	if got.Error == nil ||
		!strings.Contains(got.Error.Error(), "could not create targeted APT snapshot") {
		t.Fatalf("error = %v, want snapshot failure", got.Error)
	}
	if len(exec.commands) != 2 {
		t.Fatalf("command count = %d, want lock and snapshot only", len(exec.commands))
	}
}

func TestApplyDeb822RepairExecutionRollsBackMutationFailure(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoLabelOutputs: []string{
			"DEB822_REPAIR_ERROR|fingerprint_mismatch|profile=docker-ce\n",
		},
		runSudoLabelErrors: []error{
			errors.New("exit status 22"),
		},
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if got.Applied {
		t.Fatalf("failed repair was applied: %#v", got)
	}
	if !got.Snapshot.Created {
		t.Fatalf("snapshot = %#v, want created snapshot", got.Snapshot)
	}
	if !got.RolledBack {
		t.Fatalf("repair did not roll back after mutation failure: %#v", got)
	}
	if got.Error == nil ||
		!strings.Contains(got.Error.Error(), "fingerprint_mismatch") {
		t.Fatalf("error = %v, want fingerprint mismatch", got.Error)
	}
	if len(exec.commands) != 4 {
		t.Fatalf("command count = %d, want lock, snapshot, mutation, rollback", len(exec.commands))
	}
	if !strings.Contains(exec.commands[3], "sha256sum --strict -c checksums.sha256") {
		t.Fatalf("rollback did not verify snapshot checksums:\n%s", exec.commands[3])
	}
}

func TestApplyDeb822RepairExecutionRollsBackVerificationFailure(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoLabelOutputs: []string{
			"DEB822_REPAIR_APPLIED|docker-ce|fingerprint=9DC858229FC7DD38854AE2D88D81803C0EBFCD88\n",
			"Err:1 https://download.docker.com/linux/debian bookworm InRelease\nNO_PUBKEY 0000000000000000\n",
		},
		runSudoLabelErrors: []error{
			nil,
			errors.New("exit status 100"),
		},
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if got.Applied {
		t.Fatalf("verification-failed repair was applied: %#v", got)
	}
	if !got.RolledBack {
		t.Fatalf("repair did not roll back after verification failure: %#v", got)
	}
	if got.Error == nil ||
		!strings.Contains(got.Error.Error(), "post-repair Deb822 APT verification failed") {
		t.Fatalf("error = %v, want verification failure", got.Error)
	}
	if len(exec.commands) != 5 {
		t.Fatalf(
			"command count = %d, want lock, snapshot, mutation, verification, rollback",
			len(exec.commands),
		)
	}
	if !strings.Contains(exec.commands[4], "sha256sum --strict -c checksums.sha256") {
		t.Fatalf("rollback did not verify snapshot checksums:\n%s", exec.commands[4])
	}
}

func TestApplyDeb822RepairExecutionReportsRollbackFailure(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoErrors: []error{
			nil,
			errors.New("snapshot checksum verification failed"),
		},
		runSudoLabelOutputs: []string{
			"DEB822_REPAIR_ERROR|fingerprint_mismatch|profile=docker-ce\n",
		},
		runSudoLabelErrors: []error{
			errors.New("exit status 22"),
		},
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if got.Applied {
		t.Fatalf("failed repair was applied: %#v", got)
	}
	if got.RolledBack {
		t.Fatalf("rollback failure was marked rolled back: %#v", got)
	}
	if got.Error == nil ||
		!strings.Contains(got.Error.Error(), "targeted Deb822 rollback also failed") {
		t.Fatalf("error = %v, want rollback failure", got.Error)
	}
	if len(exec.commands) != 4 {
		t.Fatalf(
			"command count = %d, want lock, snapshot, mutation, rollback",
			len(exec.commands),
		)
	}
}

func TestHasDeb822RepairAppliedMarker(t *testing.T) {
	profile := dockerDeb822Profile(t)
	validFingerprint := profile.ExpectedFingerprints[0]

	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name: "Exact valid marker",
			output: "DEB822_REPAIR_APPLIED|docker-ce|fingerprint=" +
				validFingerprint + "\n",
			want: true,
		},
		{
			name: "Valid marker among ordinary lines",
			output: "starting repair\n" +
				"DEB822_REPAIR_APPLIED|docker-ce|fingerprint=" +
				validFingerprint + "\n" +
				"cleanup complete\n",
			want: true,
		},
		{
			name: "Prefix spoofing is rejected",
			output: "prefix-DEB822_REPAIR_APPLIED|docker-ce|fingerprint=" +
				validFingerprint + "\n",
			want: false,
		},
		{
			name: "Wrong profile is rejected",
			output: "DEB822_REPAIR_APPLIED|microsoft-vscode|fingerprint=" +
				validFingerprint + "\n",
			want: false,
		},
		{
			name: "Unpinned fingerprint is rejected",
			output: "DEB822_REPAIR_APPLIED|docker-ce|fingerprint=" +
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n",
			want: false,
		},
		{
			name:   "Empty fingerprint is rejected",
			output: "DEB822_REPAIR_APPLIED|docker-ce|fingerprint=\n",
			want:   false,
		},
		{
			name: "Marker embedded in another line is rejected",
			output: "error: DEB822_REPAIR_APPLIED|docker-ce|fingerprint=" +
				validFingerprint,
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := hasDeb822RepairAppliedMarker(test.output, profile)
			if got != test.want {
				t.Fatalf(
					"hasDeb822RepairAppliedMarker(%q) = %t, want %t",
					test.output,
					got,
					test.want,
				)
			}
		})
	}
}

func TestApplyDeb822RepairExecutionRejectsInvalidMutationMarkers(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	profile := dockerDeb822Profile(t)

	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "Missing marker",
			output: "repair finished without success record\n",
		},
		{
			name: "Prefix spoofing",
			output: "prefix-DEB822_REPAIR_APPLIED|docker-ce|fingerprint=" +
				profile.ExpectedFingerprints[0] + "\n",
		},
		{
			name: "Wrong profile",
			output: "DEB822_REPAIR_APPLIED|microsoft-vscode|fingerprint=" +
				profile.ExpectedFingerprints[0] + "\n",
		},
		{
			name: "Unpinned fingerprint",
			output: "DEB822_REPAIR_APPLIED|docker-ce|fingerprint=" +
				"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exec := &fakeExecutor{
				runSudoOutputs: []string{
					"",
					"",
				},
				runSudoLabelOutputs: []string{
					test.output,
				},
			}

			got := ApplyDeb822RepairExecution(exec, request)

			if got.Applied {
				t.Fatalf("invalid marker repair was applied: %#v", got)
			}
			if !got.Snapshot.Created {
				t.Fatalf("snapshot = %#v, want created snapshot", got.Snapshot)
			}
			if !got.RolledBack {
				t.Fatalf("invalid marker repair did not roll back: %#v", got)
			}
			if got.Error == nil ||
				!strings.Contains(
					got.Error.Error(),
					"valid DEB822_REPAIR_APPLIED marker",
				) {
				t.Fatalf("error = %v, want invalid marker failure", got.Error)
			}
			if len(exec.commands) != 4 {
				t.Fatalf(
					"command count = %d, want lock, snapshot, mutation, rollback",
					len(exec.commands),
				)
			}
			if !strings.Contains(
				exec.commands[3],
				"sha256sum --strict -c checksums.sha256",
			) {
				t.Fatalf(
					"rollback did not verify snapshot checksums:\n%s",
					exec.commands[3],
				)
			}
		})
	}
}

func TestApplyDeb822RepairExecutionRollsBackOnVerificationMarkers(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	profile := dockerDeb822Profile(t)
	successMarker := "DEB822_REPAIR_APPLIED|docker-ce|fingerprint=" +
		profile.ExpectedFingerprints[0] + "\n"

	verificationMarkers := []string{
		"NO_PUBKEY 0000000000000000",
		"BADSIG example",
		"EXPKEYSIG example",
		"Failed to fetch example",
	}

	for _, marker := range verificationMarkers {
		t.Run(marker, func(t *testing.T) {
			exec := &fakeExecutor{
				runSudoOutputs: []string{
					"",
					"",
				},
				runSudoLabelOutputs: []string{
					successMarker,
					"Hit:1 repository\n" + marker + "\n",
				},
			}

			got := ApplyDeb822RepairExecution(exec, request)

			if got.Applied {
				t.Fatalf("verification-marker repair was applied: %#v", got)
			}
			if !got.RolledBack {
				t.Fatalf(
					"verification-marker repair did not roll back: %#v",
					got,
				)
			}
			if got.Error == nil ||
				!strings.Contains(
					got.Error.Error(),
					"repository trust or fetch errors were reported",
				) {
				t.Fatalf("error = %v, want verification marker failure", got.Error)
			}
			if len(exec.commands) != 5 {
				t.Fatalf(
					"command count = %d, want lock, snapshot, mutation, verification, rollback",
					len(exec.commands),
				)
			}
		})
	}
}

func TestApplyDeb822RepairExecutionRollsBackMutationFailureWithoutOutput(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
			"",
		},
		runSudoLabelErrors: []error{
			errors.New("exit status 22"),
		},
	}

	got := ApplyDeb822RepairExecution(exec, request)

	if got.Applied {
		t.Fatalf("failed repair was applied: %#v", got)
	}
	if !got.RolledBack {
		t.Fatalf(
			"repair did not roll back after mutation failure: %#v",
			got,
		)
	}
	if got.Error == nil ||
		!strings.Contains(got.Error.Error(), "exit status 22") {
		t.Fatalf("error = %v, want mutation execution failure", got.Error)
	}
	if strings.Contains(got.Error.Error(), "fingerprint_mismatch") {
		t.Fatalf("error falsely claims fingerprint mismatch: %v", got.Error)
	}
	if len(exec.commands) != 4 {
		t.Fatalf(
			"command count = %d, want lock, snapshot, mutation, rollback",
			len(exec.commands),
		)
	}
}

func TestApplyDeb822RepairExecutionBuildsHardenedScopedMutationCommand(t *testing.T) {
	request := validDockerDeb822ExecutionRequest(t)
	profile := dockerDeb822Profile(t)
	exec := &fakeExecutor{
		runSudoOutputs: []string{
			"",
		},
		runSudoLabelOutputs: []string{
			"DEB822_REPAIR_APPLIED|docker-ce|fingerprint=" +
				profile.ExpectedFingerprints[0] + "\n",
			"Hit:1 repository\n",
		},
	}

	got := ApplyDeb822RepairExecution(exec, request)
	if !got.Applied {
		t.Fatalf("repair was not applied: %#v", got)
	}

	mutationCommand := exec.commands[2]

	requiredFragments := []string{
		"curl -fsSL --proto '=https' --tlsv1.2",
		`export GNUPGHOME="$TEMP_DIR/gnupg"`,
		`chmod 0700 "$GNUPGHOME"`,
		`mv -f "$KEYRING_TMP" "$KEYRING_PATH"`,
		`mv -f "$SOURCE_TMP" "$SOURCE_FILE"`,
		"EXPECTED_FINGERPRINTS=(",
		"RENDERED_SOURCE=" + shellQuote(request.RenderedSource),
		"KEYRING_PATH=" + shellQuote(request.KeyringPath),
		"SOURCE_FILE=" + shellQuote(request.SourceFile),
	}

	for _, fragment := range requiredFragments {
		if !strings.Contains(mutationCommand, fragment) {
			t.Fatalf(
				"mutation command missing required fragment %q:\n%s",
				fragment,
				mutationCommand,
			)
		}
	}

	for _, fingerprint := range request.ExpectedFingerprints {
		if !strings.Contains(mutationCommand, shellQuote(fingerprint)) {
			t.Fatalf(
				"mutation command missing request fingerprint %q:\n%s",
				fingerprint,
				mutationCommand,
			)
		}
	}

	for _, target := range request.SnapshotTargets {
		if !strings.Contains(exec.commands[1], shellQuote(target)) {
			t.Fatalf(
				"snapshot command missing exact request target %q:\n%s",
				target,
				exec.commands[1],
			)
		}
	}
}

package repohealer

import (
	"strings"
	"testing"
)

func blockedDockerDeb822RepairAction() RepairAction {
	action := dockerDeb822RepairAction()
	action.Eligible = false
	action.RequiresConsent = false
	return action
}

func readyDockerDeb822Inspection(
	action RepairAction,
	profile VendorProfile,
) Deb822RepairInspection {
	rendered, err := RenderAPTDeb822Source(profile, SourceRenderInput{
		Architecture: action.Target.Architecture,
		Distribution: action.Target.Distribution,
		Version:      action.Target.Version,
		Codename:     action.Target.Codename,
	})
	if err != nil {
		panic(err)
	}

	return Deb822RepairInspection{
		ActionID:    action.ID,
		ProfileID:   profile.ID,
		ProfileName: profile.DisplayName,
		SourceFile:  action.SourceFile,
		KeyringPath: profile.KeyringPath,
		SnapshotTargets: []string{
			action.SourceFile,
			profile.KeyringPath,
		},
		RenderedSource: rendered,
		Ready:          true,
	}
}

func TestBuildDeb822RepairExecutionRequestBuildsBoundRequest(t *testing.T) {
	action := blockedDockerDeb822RepairAction()
	profile := dockerDeb822Profile(t)
	inspection := readyDockerDeb822Inspection(action, profile)

	got, err := BuildDeb822RepairExecutionRequest(
		inspection,
		action,
		profile,
	)
	if err != nil {
		t.Fatalf("BuildDeb822RepairExecutionRequest() error = %v", err)
	}

	if got.ActionID != action.ID {
		t.Fatalf("action ID = %q, want %q", got.ActionID, action.ID)
	}
	if got.FindingCode != action.FindingCode {
		t.Fatalf("finding code = %q, want %q", got.FindingCode, action.FindingCode)
	}
	if got.ProfileID != profile.ID {
		t.Fatalf("profile ID = %q, want %q", got.ProfileID, profile.ID)
	}
	if got.ProfileDisplayName != profile.DisplayName {
		t.Fatalf(
			"profile display name = %q, want %q",
			got.ProfileDisplayName,
			profile.DisplayName,
		)
	}
	if got.RepositoryURL != action.RepositoryURL {
		t.Fatalf(
			"repository URL = %q, want %q",
			got.RepositoryURL,
			action.RepositoryURL,
		)
	}
	if got.SourceFile != action.SourceFile {
		t.Fatalf("source file = %q, want %q", got.SourceFile, action.SourceFile)
	}
	if got.SourceFormat != SourceFormatDeb822 {
		t.Fatalf("source format = %q, want %q", got.SourceFormat, SourceFormatDeb822)
	}
	if got.KeyringPath != profile.KeyringPath {
		t.Fatalf("keyring path = %q, want %q", got.KeyringPath, profile.KeyringPath)
	}
	if got.RenderedSource != inspection.RenderedSource {
		t.Fatalf("rendered source = %q, want %q", got.RenderedSource, inspection.RenderedSource)
	}
	if !sameOrderedStrings(got.SnapshotTargets, inspection.SnapshotTargets) {
		t.Fatalf(
			"snapshot targets = %#v, want %#v",
			got.SnapshotTargets,
			inspection.SnapshotTargets,
		)
	}
	if !sameOrderedStrings(got.ExpectedFingerprints, profile.ExpectedFingerprints) {
		t.Fatalf(
			"expected fingerprints = %#v, want %#v",
			got.ExpectedFingerprints,
			profile.ExpectedFingerprints,
		)
	}
	if got.Target != action.Target {
		t.Fatalf("target = %#v, want %#v", got.Target, action.Target)
	}
}

func TestBuildDeb822RepairExecutionRequestCopiesSlicesDefensively(t *testing.T) {
	action := blockedDockerDeb822RepairAction()
	profile := dockerDeb822Profile(t)
	inspection := readyDockerDeb822Inspection(action, profile)

	got, err := BuildDeb822RepairExecutionRequest(
		inspection,
		action,
		profile,
	)
	if err != nil {
		t.Fatalf("BuildDeb822RepairExecutionRequest() error = %v", err)
	}

	inspection.SnapshotTargets[0] = "/tmp/changed.sources"
	profile.ExpectedFingerprints[0] = "CHANGED"

	if got.SnapshotTargets[0] != action.SourceFile {
		t.Fatalf("request snapshot target was not copied: %#v", got.SnapshotTargets)
	}
	if got.ExpectedFingerprints[0] == "CHANGED" {
		t.Fatalf(
			"request fingerprints were not copied: %#v",
			got.ExpectedFingerprints,
		)
	}
}

func TestBuildDeb822RepairExecutionRequestRejectsUnsafeBindings(t *testing.T) {
	baseAction := blockedDockerDeb822RepairAction()
	baseProfile := dockerDeb822Profile(t)
	baseInspection := readyDockerDeb822Inspection(baseAction, baseProfile)

	tests := []struct {
		name       string
		mutate     func(*Deb822RepairInspection, *RepairAction, *VendorProfile)
		wantReason string
	}{
		{
			name: "Inspection not ready",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				inspection.Ready = false
				inspection.BlockReason = "source validation failed"
			},
			wantReason: "inspection is not ready",
		},
		{
			name: "Non Deb822 action",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				action.SourceFormat = SourceFormatAPTList
			},
			wantReason: "is not Deb822",
		},
		{
			name: "Action made eligible",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				action.Eligible = true
			},
			wantReason: "must remain blocked",
		},
		{
			name: "Action made consent bearing",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				action.RequiresConsent = true
			},
			wantReason: "must remain blocked",
		},
		{
			name: "Incomplete action binding",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				action.SourceFile = ""
			},
			wantReason: "action binding is incomplete",
		},
		{
			name: "Profile mismatch",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				action.ProfileID = "microsoft-vscode"
			},
			wantReason: "does not match verified profile",
		},
		{
			name: "Keyring mismatch",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				action.KeyringPath = "/etc/apt/keyrings/other.gpg"
			},
			wantReason: "does not match verified profile keyring path",
		},
		{
			name: "Repository mismatch",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				action.RepositoryURL = "https://download.docker.com/linux/debian/extra"
			},
			wantReason: "is not exact for profile",
		},
		{
			name: "Source path outside approved directory",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				action.SourceFile = "/tmp/docker.sources"
			},
			wantReason: "is outside /etc/apt/sources.list.d",
		},
		{
			name: "Inspection action mismatch",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				inspection.ActionID = "different-action"
			},
			wantReason: "inspection does not match",
		},
		{
			name: "Inspection profile mismatch",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				inspection.ProfileID = "different-profile"
			},
			wantReason: "inspection does not match",
		},
		{
			name: "Inspection source mismatch",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				inspection.SourceFile = "/etc/apt/sources.list.d/other.sources"
			},
			wantReason: "inspection does not match",
		},
		{
			name: "Inspection keyring mismatch",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				inspection.KeyringPath = "/etc/apt/keyrings/other.gpg"
			},
			wantReason: "inspection does not match",
		},
		{
			name: "Missing rendered replacement",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				inspection.RenderedSource = ""
			},
			wantReason: "has no rendered replacement source",
		},
		{
			name: "Invalid rendered replacement",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				inspection.RenderedSource = strings.Replace(
					inspection.RenderedSource,
					"Signed-By: "+profile.KeyringPath,
					"Signed-By: /etc/apt/keyrings/other.gpg",
					1,
				)
			},
			wantReason: "inspection rendered replacement source is invalid",
		},
		{
			name: "Snapshot scope mismatch",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				inspection.SnapshotTargets = []string{
					action.SourceFile,
					"/etc/apt/keyrings/other.gpg",
				}
			},
			wantReason: "snapshot targets do not match",
		},
		{
			name: "Missing fingerprints",
			mutate: func(inspection *Deb822RepairInspection, action *RepairAction, profile *VendorProfile) {
				profile.ExpectedFingerprints = nil
			},
			wantReason: "has no pinned signing-key fingerprints",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inspection := baseInspection
			inspection.SnapshotTargets = append(
				[]string(nil),
				baseInspection.SnapshotTargets...,
			)

			action := baseAction
			profile := baseProfile
			profile.ExpectedFingerprints = append(
				[]string(nil),
				baseProfile.ExpectedFingerprints...,
			)

			test.mutate(&inspection, &action, &profile)

			got, err := BuildDeb822RepairExecutionRequest(
				inspection,
				action,
				profile,
			)
			if err == nil {
				t.Fatalf(
					"unsafe execution request unexpectedly succeeded: %#v",
					got,
				)
			}
			if !strings.Contains(err.Error(), test.wantReason) {
				t.Fatalf(
					"error = %q, want it to contain %q",
					err.Error(),
					test.wantReason,
				)
			}
			if got.ActionID != "" ||
				got.FindingCode != "" ||
				got.ProfileID != "" ||
				got.ProfileDisplayName != "" ||
				got.RepositoryURL != "" ||
				got.SourceFile != "" ||
				got.SourceFormat != SourceFormatUnknown ||
				got.KeyringPath != "" ||
				got.RenderedSource != "" ||
				len(got.SnapshotTargets) != 0 ||
				got.Target != (TargetFacts{}) ||
				len(got.ExpectedFingerprints) != 0 {
				t.Fatalf(
					"blocked request must be empty, got %#v",
					got,
				)
			}
		})
	}
}

package repohealer

import "strings"

type Deb822RepairInspection struct {
	ActionID        string
	ProfileID       string
	ProfileName     string
	SourceFile      string
	KeyringPath     string
	SnapshotTargets []string
	RenderedSource  string
	Ready           bool
	BlockReason     string
}

func InspectApprovedDeb822Repair(
	exec Executor,
	action RepairAction,
	profile VendorProfile,
) Deb822RepairInspection {
	inspection := Deb822RepairInspection{
		ActionID:    action.ID,
		ProfileID:   profile.ID,
		ProfileName: profile.DisplayName,
		SourceFile:  action.SourceFile,
		KeyringPath: profile.KeyringPath,
	}

	prepared, err := ReadAndPrepareDeb822Repair(exec, action, profile)
	if err != nil {
		inspection.BlockReason = strings.TrimSpace(err.Error())
		return inspection
	}

	inspection.ProfileID = prepared.ProfileID
	inspection.SourceFile = prepared.SourceFile
	inspection.KeyringPath = prepared.KeyringPath
	inspection.SnapshotTargets = append(
		[]string(nil),
		prepared.SnapshotTargets...,
	)
	inspection.RenderedSource = prepared.RenderedSource
	inspection.Ready = true

	return inspection
}

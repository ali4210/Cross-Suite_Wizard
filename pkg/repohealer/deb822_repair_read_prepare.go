package repohealer

func ReadAndPrepareDeb822Repair(
	exec Executor,
	action RepairAction,
	profile VendorProfile,
) (PreparedDeb822Repair, error) {
	document, err := ReadApprovedDeb822Source(exec, action)
	if err != nil {
		return PreparedDeb822Repair{}, err
	}

	return PrepareDeb822Repair(action, profile, document)
}

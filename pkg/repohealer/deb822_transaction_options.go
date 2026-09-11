package repohealer

import "time"

type deb822RepairExecutionOptions struct {
	snapshotRoot       string
	temporaryRoot      string
	verificationScript string
	now                func() time.Time
}

func defaultDeb822RepairExecutionOptions() deb822RepairExecutionOptions {
	return deb822RepairExecutionOptions{
		snapshotRoot:       defaultAPTSnapshotRoot,
		temporaryRoot:      "/var/tmp",
		verificationScript: defaultAPTVerificationScript,
		now:                time.Now,
	}
}

func normalizeDeb822RepairExecutionOptions(
	options deb822RepairExecutionOptions,
) deb822RepairExecutionOptions {
	defaults := defaultDeb822RepairExecutionOptions()

	if options.snapshotRoot == "" {
		options.snapshotRoot = defaults.snapshotRoot
	}
	if options.temporaryRoot == "" {
		options.temporaryRoot = defaults.temporaryRoot
	}
	if options.verificationScript == "" {
		options.verificationScript = defaults.verificationScript
	}
	if options.now == nil {
		options.now = defaults.now
	}

	return options
}

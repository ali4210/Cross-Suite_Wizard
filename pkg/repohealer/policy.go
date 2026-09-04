package repohealer

type Policy struct {
	Mode              Mode
	CollectJournal    bool
	KnownVendorsOnly  bool
	RequireConsent    bool
	VerifyAfterRepair bool
	AllowMutation     bool
}

func DefaultDiagnosticPolicy() Policy {
	return Policy{
		Mode:              ModeDiagnose,
		CollectJournal:    true,
		KnownVendorsOnly:  true,
		RequireConsent:    true,
		VerifyAfterRepair: true,
		AllowMutation:     false,
	}
}

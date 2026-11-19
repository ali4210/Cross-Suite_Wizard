package repohealer

import "fmt"

// RenderRPMRepoFile renders a vendor's .repo file content. gpgkey always points at the
// local file this pipeline installs after verifying its fingerprint
// (/etc/pki/rpm-gpg/RPM-GPG-KEY-<RPMRepoID> — see rpm_repair.go), never a bare vendor URL:
// dnf/zypper would otherwise fetch and prompt to trust that URL's key unprompted on first
// use, bypassing this pipeline's own fingerprint check entirely. gpgcheck is always 1 —
// there is no profile option to disable it, by design (see dnf.go/zypper.go's diagnose
// findings, which explicitly warn never to disable gpgcheck as a repair).
func RenderRPMRepoFile(profile VendorProfile) (string, error) {
	if profile.PackageManager != ManagerDNF &&
		profile.PackageManager != ManagerYUM &&
		profile.PackageManager != ManagerZypper {
		return "", fmt.Errorf("profile %q is not an RPM profile", profile.ID)
	}
	if profile.RPMRepoID == "" || profile.RPMBaseURL == "" {
		return "", fmt.Errorf("profile %q is missing RPMRepoID or RPMBaseURL", profile.ID)
	}

	return fmt.Sprintf(
		"[%s]\n"+
			"name=%s\n"+
			"baseurl=%s\n"+
			"enabled=1\n"+
			"gpgcheck=1\n"+
			"gpgkey=file://%s\n",
		profile.RPMRepoID,
		profile.DisplayName,
		profile.RPMBaseURL,
		profile.KeyringPath,
	), nil
}

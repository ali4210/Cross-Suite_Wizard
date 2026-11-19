package repohealer

import "strings"

type VendorProfile struct {
	ID                   string
	DisplayName          string
	PackageManager       PackageManager
	AllowedURLPrefixes   []string
	KeyURL               string
	KeyringPath          string
	ExpectedFingerprints []string
	SourceFile           string
	SourceLine           string

	// DocSource cites where ExpectedFingerprints was verified against (the vendor's own
	// documentation page, or "key URL only" when the vendor's docs do not publish a
	// fingerprint and the key was instead verified by downloading it from the vendor's own
	// documented HTTPS KeyURL in a container). Every entry in KnownVendorProfiles must set
	// this — see the per-entry comments for the exact verification date and method.
	DocSource string

	// Suite and Components are the APT distribution/component for a vendor whose repository
	// uses one fixed suite regardless of the target distribution (e.g. "stable"/"main").
	// RenderAPTSource and RenderAPTDeb822Source fall back to these generically when a
	// vendor has no distribution-specific switch case of its own. Leave both empty for a
	// vendor that needs codename-conditional resolution (see CodenameSuiteSuffix) or a
	// custom renderer case.
	Suite      string
	Components string

	// CodenameSuiteSuffix and SupportedCodenames describe a vendor whose suite is the
	// target's own distro codename plus a fixed suffix (e.g. PostgreSQL PGDG's
	// "<codename>-pgdg"), restricted to the codenames the vendor documents support for.
	// Leave both empty for a vendor using a single fixed Suite instead.
	CodenameSuiteSuffix string
	SupportedCodenames  []string
}

func KnownVendorProfiles() []VendorProfile {
	return []VendorProfile{
		{
			ID:             "microsoft-vscode",
			DisplayName:    "Microsoft Visual Studio Code",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://packages.microsoft.com/repos/code",
			},
			KeyURL:      "https://packages.microsoft.com/keys/microsoft.asc",
			KeyringPath: "/etc/apt/keyrings/microsoft.gpg",
			ExpectedFingerprints: []string{
				"BC528686B50D79E339D3721CEB3E94ADBE1229CF",
			},
			SourceFile: "/etc/apt/sources.list.d/vscode.list",
			SourceLine: "deb [arch=amd64 signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/code stable main",
			DocSource:  "https://code.visualstudio.com/docs/setup/linux (verified by downloading KeyURL)",
		},
		{
			ID:             "hashicorp",
			DisplayName:    "HashiCorp",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://apt.releases.hashicorp.com",
			},
			KeyURL:      "https://apt.releases.hashicorp.com/gpg",
			KeyringPath: "/usr/share/keyrings/hashicorp-archive-keyring.gpg",
			ExpectedFingerprints: []string{
				"D55C0D1AC78A8D8126CB631CFC9CA96ACA026560",
			},
			SourceFile: "/etc/apt/sources.list.d/hashicorp.list",
			DocSource:  "https://apt.releases.hashicorp.com/gpg (re-verified live in an ubuntu:24.04 container, 2026-11-12)",
		},
		{
			ID:             "docker-ce",
			DisplayName:    "Docker CE",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://download.docker.com/linux/debian",
			},
			KeyURL:      "https://download.docker.com/linux/debian/gpg",
			KeyringPath: "/etc/apt/keyrings/docker.gpg",
			ExpectedFingerprints: []string{
				"9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
				"D3306A018370199E527AE7997EA0A9C3F273FCD8",
			},
			SourceFile: "/etc/apt/sources.list.d/docker.list",
			DocSource:  "https://docs.docker.com/engine/install/debian/ (verified by downloading KeyURL)",
		},
		{
			// Verified 2026-11-12: downloaded https://dl.google.com/linux/linux_signing_key.pub
			// in an ubuntu:24.04 container (gpg --show-keys --with-colons --fingerprint). That
			// file bundles 9 keys shared across several Google Linux products; the one pinned
			// here is specifically the one https://www.google.com/linuxrepositories/ names as
			// the "active primary key" (its "obsolete key" 4CCA1EAF950CEE4AB83976DCA040830F7FAC5991
			// is deliberately NOT pinned). The other 8 bundled keys are not relevant to this repo.
			ID:             "google-chrome",
			DisplayName:    "Google Chrome",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://dl.google.com/linux/chrome/deb",
				"http://dl.google.com/linux/chrome/deb",
			},
			KeyURL:      "https://dl.google.com/linux/linux_signing_key.pub",
			KeyringPath: "/etc/apt/keyrings/google-chrome.gpg",
			ExpectedFingerprints: []string{
				"EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796",
			},
			SourceFile: "/etc/apt/sources.list.d/google-chrome.list",
			Suite:      "stable",
			Components: "main",
			DocSource:  "https://www.google.com/linuxrepositories/ (fingerprint published as the \"active primary key\"), cross-checked by downloading KeyURL, 2026-11-12",
		},
		{
			// Verified 2026-11-12: official docs (github.com/cli/cli docs/install_linux.md)
			// explicitly publish both fingerprints below; confirmed by downloading KeyURL in
			// an ubuntu:24.04 container. The downloaded keyring also contains two other
			// fingerprints NOT published by the docs, which are deliberately not pinned here.
			ID:             "github-cli",
			DisplayName:    "GitHub CLI",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://cli.github.com/packages",
			},
			KeyURL:      "https://cli.github.com/packages/githubcli-archive-keyring.gpg",
			KeyringPath: "/etc/apt/keyrings/githubcli-archive-keyring.gpg",
			ExpectedFingerprints: []string{
				"2C6106201985B60E6C7AC87323F3D4EA75716059",
				"7F38BBB59D064DBCB3D84D725612B36462313325",
			},
			SourceFile: "/etc/apt/sources.list.d/github-cli.list",
			Suite:      "stable",
			Components: "main",
			DocSource:  "https://github.com/cli/cli/blob/trunk/docs/install_linux.md (publishes both fingerprints), cross-checked by downloading KeyURL, 2026-11-12",
		},
		{
			// Verified 2026-11-12: official docs (postgresql.org/download/linux/ubuntu)
			// publish this exact fingerprint via `gpg --show-key`'s documented output;
			// confirmed by downloading KeyURL in an ubuntu:24.04 container. The repository
			// suite is the target's own codename plus "-pgdg", restricted to the codenames
			// that page documents as supported (Debian codenames are not included here, since
			// only the Ubuntu install page was checked in this pass).
			ID:             "postgresql-pgdg",
			DisplayName:    "PostgreSQL (PGDG)",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://apt.postgresql.org/pub/repos/apt",
			},
			KeyURL:      "https://www.postgresql.org/media/keys/ACCC4CF8.asc",
			KeyringPath: "/etc/apt/keyrings/postgresql-pgdg.asc",
			ExpectedFingerprints: []string{
				"B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8",
			},
			SourceFile:          "/etc/apt/sources.list.d/pgdg.list",
			Components:          "main",
			CodenameSuiteSuffix: "-pgdg",
			SupportedCodenames:  []string{"noble", "jammy", "resolute", "stonking"},
			DocSource:           "https://www.postgresql.org/download/linux/ubuntu/ (publishes the fingerprint via documented gpg --show-key output), cross-checked by downloading KeyURL, 2026-11-12",
		},
		{
			// Verified 2026-11-12: downloaded the CURRENT key URL
			// (jenkins.io-2026.key) in an ubuntu:24.04 container. Jenkins' official docs
			// (jenkins.io/doc/book/installing/linux) rotate this key URL's year segment
			// roughly annually (an older "-2023.key" fingerprint from a prior check no longer
			// matches) — this profile pins the fingerprint for the URL documented as current
			// as of the verification date above; it will need updating when Jenkins rotates
			// the key again.
			ID:             "jenkins",
			DisplayName:    "Jenkins",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://pkg.jenkins.io/debian-stable",
			},
			KeyURL:      "https://pkg.jenkins.io/debian-stable/jenkins.io-2026.key",
			KeyringPath: "/etc/apt/keyrings/jenkins-keyring.asc",
			ExpectedFingerprints: []string{
				"5E386EADB55F01504CAE8BCF7198F4B714ABFC68",
			},
			SourceFile: "/etc/apt/sources.list.d/jenkins.list",
			Suite:      "binary/",
			Components: "",
			DocSource:  "https://www.jenkins.io/doc/book/installing/linux/ (documents the current key URL), verified by downloading KeyURL, 2026-11-12",
		},
		{
			// Verified 2026-11-19: grafana.com's docs document the key URL but publish no
			// fingerprint. gpg-full.key bundles 3 keys; downloaded it in an ubuntu:24.04
			// container and confirmed via a real `apt-get update` against the live repo
			// which one actually signs the current InRelease (this one) — not just picked
			// from the bundle by inspection.
			ID:             "grafana",
			DisplayName:    "Grafana",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://apt.grafana.com",
			},
			KeyURL:      "https://apt.grafana.com/gpg-full.key",
			KeyringPath: "/etc/apt/keyrings/grafana.gpg",
			ExpectedFingerprints: []string{
				"B53AE77BADB630A683046005963FA27710458545",
			},
			SourceFile: "/etc/apt/sources.list.d/grafana.list",
			Suite:      "stable",
			Components: "main",
			DocSource:  "https://grafana.com/docs/grafana/latest/setup-grafana/installation/debian/ (documents the key URL; no fingerprint published) — verified by downloading gpg-full.key and confirming via a real apt-get update against the live repository which of its 3 bundled keys actually signs it, in an ubuntu:24.04 container, 2026-11-19",
		},
		{
			// Verified 2026-11-19: NodeSource's setup_22.x script (github.com/nodesource/
			// distributions) downloads this exact key URL and writes a deb822 .sources
			// file with Suites: nodistro, Components: main, and a version-templated URI
			// (node_<major>.x). The key itself is shared across all Node major versions —
			// confirmed by downloading it once and validating it against both the node_22.x
			// AND node_20.x live repos in the same container. Only node_22.x is pinned as a
			// profile here; add another profile (e.g. "nodesource-20") with its own
			// AllowedURLPrefixes to support another major version — no new key
			// verification would be needed since the key is shared, but the URL this
			// profile matches against is specific to 22.x.
			ID:             "nodesource",
			DisplayName:    "NodeSource (Node.js 22.x)",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://deb.nodesource.com/node_22.x",
			},
			KeyURL:      "https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key",
			KeyringPath: "/etc/apt/keyrings/nodesource.gpg",
			ExpectedFingerprints: []string{
				"6F71F525282841EEDAF851B42F59B5F99B1BE0B4",
			},
			SourceFile: "/etc/apt/sources.list.d/nodesource.list",
			Suite:      "nodistro",
			Components: "main",
			DocSource:  "https://github.com/nodesource/distributions (DEV_README.md documents setup_22.x, which uses this key URL; no fingerprint published) — verified by downloading KeyURL and confirming via a real apt-get update against both the node_22.x and node_20.x live repos, in an ubuntu:24.04 container, 2026-11-19",
		},
		{
			// Verified 2026-11-19: Mozilla's own APT host (packages.mozilla.org, not the
			// JS-rendered support.mozilla.org page, which publishes no static instructions)
			// serves this key and the "mozilla main" suite directly; confirmed by downloading
			// the key and a real apt-get update against the live repo.
			ID:             "mozilla",
			DisplayName:    "Mozilla (Firefox)",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://packages.mozilla.org/apt",
			},
			KeyURL:      "https://packages.mozilla.org/apt/repo-signing-key.gpg",
			KeyringPath: "/etc/apt/keyrings/mozilla.gpg",
			ExpectedFingerprints: []string{
				"35BAA0B33E9EB396F59CA838C0BA5CE6DC6315A3",
			},
			SourceFile: "/etc/apt/sources.list.d/mozilla.list",
			Suite:      "mozilla",
			Components: "main",
			DocSource:  "https://packages.mozilla.org/apt/ (the vendor's own APT host; no fingerprint published) — verified by downloading KeyURL and confirming via a real apt-get update against the live repo, in an ubuntu:24.04 container, 2026-11-19",
		},
		{
			// Verified 2026-11-19: Brave's own brave-browser.sources (served from
			// brave-browser-apt-release.s3.brave.com, documented at brave.com/linux/)
			// bundles 3 keys in its keyring file; downloaded it and confirmed via a real
			// apt-get update against the live repo which one actually signs the current
			// InRelease (this one — the oldest of the three, issued 2022; the other two
			// are not yet active rotation keys).
			ID:             "brave",
			DisplayName:    "Brave Browser",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://brave-browser-apt-release.s3.brave.com",
			},
			KeyURL:      "https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg",
			KeyringPath: "/etc/apt/keyrings/brave-browser-archive-keyring.gpg",
			ExpectedFingerprints: []string{
				"DBF1A116C220B8C7164F98230686B78420038257",
			},
			SourceFile: "/etc/apt/sources.list.d/brave-browser-release.list",
			Suite:      "stable",
			Components: "main",
			DocSource:  "https://brave.com/linux/ (documents brave-browser.sources, which references this key URL; no fingerprint published) — verified by downloading the keyring and confirming via a real apt-get update against the live repository which of its 3 bundled keys actually signs it, in an ubuntu:24.04 container, 2026-11-19",
		},
		{
			// Verified 2026-11-19: Sensu's packagecloud install script
			// (packagecloud.io/install/repositories/sensu/stable/script.deb.sh) fetches a
			// per-distro/codename config from packagecloud's API; confirmed the real
			// generated line for Ubuntu noble, downloaded the key, and verified both via a
			// real apt-get update. The repo path's "ubuntu/" segment with the codename as
			// suite is packagecloud's own convention, not vendor-specific; the signing key
			// is the same regardless of codename, so adding another SupportedCodenames
			// entry needs no new key verification, only confirming that codename's repo
			// exists on packagecloud.
			ID:             "sensu",
			DisplayName:    "Sensu",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://packagecloud.io/sensu/stable/ubuntu",
			},
			KeyURL:      "https://packagecloud.io/sensu/stable/gpgkey",
			KeyringPath: "/etc/apt/keyrings/sensu.gpg",
			ExpectedFingerprints: []string{
				"CB1605C4E988C91F438249E3A5BC3FB70A3F7426",
			},
			SourceFile:          "/etc/apt/sources.list.d/sensu.list",
			Components:          "main",
			CodenameSuiteSuffix: "",
			SupportedCodenames:  []string{"noble"},
			DocSource:           "https://docs.sensu.io/sensu-go/latest/operations/deploy-sensu/install-sensu/ (documents the packagecloud install script, which fetches this key URL; no fingerprint published) — verified by downloading KeyURL and confirming via a real apt-get update against the live noble repo, in an ubuntu:24.04 container, 2026-11-19",
		},
		{
			// Verified 2026-11-19: extracted the real zabbix-release_7.0-1+ubuntu24.04_all.deb
			// bootstrap package (from repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/
			// zabbix-release/) in an ubuntu:24.04 container to read its actual
			// /etc/apt/sources.list.d/zabbix.list and the two keyrings it installs
			// (zabbix-official-repo.gpg and a 2024 rotation key). Confirmed via a real
			// apt-get update against the live 7.0/noble repo which of the bundled keys
			// (from the standalone zabbix-official-repo.key URL) actually signs it — the
			// 2024 rotation key, not the original 2016 one. This profile pins version 7.0;
			// a different Zabbix major.minor uses a different URL path segment and may use
			// a different active key, so it would need its own profile and verification.
			ID:             "zabbix",
			DisplayName:    "Zabbix 7.0",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://repo.zabbix.com/zabbix/7.0/ubuntu",
			},
			KeyURL:      "https://repo.zabbix.com/zabbix-official-repo.key",
			KeyringPath: "/etc/apt/keyrings/zabbix.gpg",
			ExpectedFingerprints: []string{
				"4C3D6F2CC75F5146754FC374D913219AB5333005",
			},
			SourceFile:          "/etc/apt/sources.list.d/zabbix.list",
			Components:          "main",
			CodenameSuiteSuffix: "",
			SupportedCodenames:  []string{"noble"},
			DocSource:           "https://repo.zabbix.com/zabbix/7.0/ubuntu/pool/main/z/zabbix-release/ (the real bootstrap package's contents, extracted and read directly) — verified by downloading KeyURL and confirming via a real apt-get update against the live 7.0/noble repo which of its bundled keys actually signs it, in an ubuntu:24.04 container, 2026-11-19",
		},
		{
			// Verified 2026-11-19: pkgs.tailscale.com/stable/ubuntu/<codename>.list and
			// <codename>.noarmor.gpg are Tailscale's own documented per-codename URLs
			// (tailscale.com/install.sh fetches exactly this pattern). Confirmed the key
			// bytes are byte-identical across codenames (compared noble vs jammy), then
			// verified via a real apt-get update against both live repos. NOTE: the
			// downloaded key is raw binary (not ascii-armored) — this profile's
			// KeyringPath uses a .gpg extension; using one that implies ascii-armored
			// content for this specific key caused `apt-get update` to fail with
			// NO_PUBKEY in testing, even though gpg/gpgv could read the same bytes
			// directly. The repair pipeline always runs the raw download through `gpg
			// --dearmor` before installing it (a safe no-op on already-binary input, also
			// confirmed in testing), so this is only a concern for anyone handling the key
			// manually outside that pipeline.
			ID:             "tailscale",
			DisplayName:    "Tailscale",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://pkgs.tailscale.com/stable/ubuntu",
			},
			KeyURL:      "https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg",
			KeyringPath: "/etc/apt/keyrings/tailscale.gpg",
			ExpectedFingerprints: []string{
				"2596A99EAAB33821893C0A79458CA832957F5868",
			},
			SourceFile:          "/etc/apt/sources.list.d/tailscale.list",
			Components:          "main",
			CodenameSuiteSuffix: "",
			SupportedCodenames:  []string{"noble", "jammy"},
			DocSource:           "https://tailscale.com/install.sh (documents the exact per-codename key/list URL pattern; no fingerprint published) — verified by downloading both the noble and jammy keys (byte-identical) and confirming via a real apt-get update against both live repos, in an ubuntu:24.04 container, 2026-11-19",
		},
		{
			// Verified 2026-11-19: pkg.cloudflare.com/index.html documents one shared key
			// (cloudflare-main.gpg) across every supported Debian/Ubuntu codename; confirmed
			// by downloading it and a real apt-get update against both the noble and jammy
			// live repos.
			ID:             "cloudflare",
			DisplayName:    "Cloudflare (cloudflared)",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://pkg.cloudflare.com/cloudflared",
			},
			KeyURL:      "https://pkg.cloudflare.com/cloudflare-main.gpg",
			KeyringPath: "/etc/apt/keyrings/cloudflare-main.gpg",
			ExpectedFingerprints: []string{
				"CC94B39C77AE7342A68B89628A682D308D4E5E73",
			},
			SourceFile:          "/etc/apt/sources.list.d/cloudflared.list",
			Components:          "main",
			CodenameSuiteSuffix: "",
			SupportedCodenames:  []string{"noble", "jammy"},
			DocSource:           "https://pkg.cloudflare.com/index.html (documents the single shared key URL across codenames; no fingerprint published) — verified by downloading KeyURL and confirming via a real apt-get update against both the noble and jammy live repos, in an ubuntu:24.04 container, 2026-11-19",
		},
		{
			// Verified 2026-11-19: mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/
			// documents server-9.asc and a suite of "<codename>/mongodb-org/9.0"; confirmed
			// by downloading the key and a real apt-get update against the live
			// noble/mongodb-org/9.0 repo. The CodenameSuiteSuffix mechanism (meant for
			// PostgreSQL PGDG's "<codename>-pgdg" pattern) is reused here unchanged to
			// build "<codename>/mongodb-org/9.0" — it concatenates codename + suffix with
			// no separator, which already produces the exact real suite string. This
			// profile pins MongoDB 9.0; a different major version uses a different KeyURL
			// (server-8.asc, server-7.asc, ...) and would need its own profile and
			// verification.
			ID:             "mongodb",
			DisplayName:    "MongoDB 9.0",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://repo.mongodb.org/apt/ubuntu",
			},
			KeyURL:      "https://pgp.mongodb.com/server-9.asc",
			KeyringPath: "/etc/apt/keyrings/mongodb-server-9.gpg",
			ExpectedFingerprints: []string{
				"B3B42B6C39E5CDDEC0A27E3CF366D55B602E502D",
			},
			SourceFile:          "/etc/apt/sources.list.d/mongodb-org-9.0.list",
			Components:          "multiverse",
			CodenameSuiteSuffix: "/mongodb-org/9.0",
			SupportedCodenames:  []string{"noble"},
			DocSource:           "https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-ubuntu/ (documents server-9.asc and the per-codename suite; no fingerprint published) — verified by downloading KeyURL and confirming via a real apt-get update against the live noble/mongodb-org/9.0 repo, in an ubuntu:24.04 container, 2026-11-19",
		},
		{
			// Verified 2026-11-19: kubernetes.io/docs/tasks/tools/install-kubectl-linux/
			// documents pkgs.k8s.io/core:/stable:/v1.<minor>/deb/ as a flat (no Suites/
			// Components split) repository, keyed per Kubernetes MINOR version — confirmed
			// by downloading both the v1.31 and v1.37 Release.key files and finding they
			// are different keys (true per-minor-version rotation, not a shared key like
			// NodeSource/Tailscale). This profile pins v1.31 specifically (the version
			// documented as in use on the operator's own server); a different minor
			// version needs its own profile with its own separately-downloaded and
			// verified key — the URL and the key both change together.
			ID:             "kubernetes-v1-31",
			DisplayName:    "Kubernetes v1.31",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://pkgs.k8s.io/core:/stable:/v1.31/deb/",
			},
			KeyURL:      "https://pkgs.k8s.io/core:/stable:/v1.31/deb/Release.key",
			KeyringPath: "/etc/apt/keyrings/kubernetes-apt-keyring.gpg",
			ExpectedFingerprints: []string{
				"DE15B14486CD377B9E876E1A234654DA9A296436",
			},
			SourceFile: "/etc/apt/sources.list.d/kubernetes.list",
			Suite:      "/",
			Components: "",
			DocSource:  "https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/ (documents the per-minor-version flat repo URL and key; no fingerprint published) — verified by downloading the v1.31 key (and separately the v1.37 key, confirming they differ) and confirming v1.31 via a real apt-get update against the live repo, in an ubuntu:24.04 container, 2026-11-19",
		},
		{
			// Verified 2026-11-19: elastic.co's deb install docs document GPG-KEY-elasticsearch
			// and a suite of "packages/9.x/apt stable main"; confirmed by downloading the
			// key and a real apt-get update against the live repo. This profile pins
			// Elastic 9.x; an earlier major version (8.x, 7.x) uses a different URL and may
			// use a different key, and would need its own profile and verification.
			ID:             "elastic",
			DisplayName:    "Elastic 9.x",
			PackageManager: ManagerAPT,
			AllowedURLPrefixes: []string{
				"https://artifacts.elastic.co/packages/9.x/apt",
			},
			KeyURL:      "https://artifacts.elastic.co/GPG-KEY-elasticsearch",
			KeyringPath: "/etc/apt/keyrings/elasticsearch-keyring.gpg",
			ExpectedFingerprints: []string{
				"46095ACC8548582C1A2699A9D27D666CD88E42B4",
			},
			SourceFile: "/etc/apt/sources.list.d/elastic-9.x.list",
			Suite:      "stable",
			Components: "main",
			DocSource:  "https://www.elastic.co/guide/en/elasticsearch/reference/current/deb.html (documents the key URL and suite; no fingerprint published) — verified by downloading KeyURL and confirming via a real apt-get update against the live repo, in an ubuntu:24.04 container, 2026-11-19",
		},
	}
}

func FindVendorProfile(manager PackageManager, repositoryURL string) (VendorProfile, bool) {
	repositoryURL = strings.TrimSpace(repositoryURL)

	for _, profile := range KnownVendorProfiles() {
		if profile.PackageManager != manager {
			continue
		}

		for _, prefix := range profile.AllowedURLPrefixes {
			if repositoryURL == prefix ||
				strings.HasPrefix(repositoryURL, prefix+"/") {
				return profile, true
			}
		}
	}

	return VendorProfile{}, false
}

func IsPinnedFingerprint(profile VendorProfile, fingerprint string) bool {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(fingerprint), " ", ""))

	for _, expected := range profile.ExpectedFingerprints {
		if normalized == strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(expected), " ", "")) {
			return true
		}
	}

	return false
}

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

	// RPM fields — set only when PackageManager is ManagerDNF, ManagerYUM or
	// ManagerZypper. RPMRepoID names both the .repo file's own [section] and the local
	// verified-key filename RenderRPMRepoFile/the RPM repair pipeline install at
	// /etc/pki/rpm-gpg/RPM-GPG-KEY-<RPMRepoID> — never a bare vendor URL, so dnf/zypper's
	// own gpgcheck is always checked against the copy this pipeline already verified by
	// fingerprint, not a URL dnf would otherwise fetch and trust unprompted. RPMBaseURL is
	// used verbatim (it may itself contain $releasever/$basearch) in the rendered .repo
	// file's baseurl=.
	RPMRepoID   string
	RPMBaseURL  string
	RPMRepoFile string
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

		// --- RPM (dnf/yum, zypper) profiles below. Every fingerprint here was confirmed
		// the same way: download the vendor's documented key URL, import it with `rpm
		// --import`, download one real current package from the vendor's live repo in a
		// Fedora 45 (dnf5) container, and run `rpm -K` against it — the real RPM trust
		// mechanism, which checks each PACKAGE's embedded signature, not repo metadata
		// signing (many RPM vendors do not sign repomd.xml at all; that is normal and not
		// a trust gap). Several vendors bundle more than one key at their documented
		// KeyURL and sign with only one of them — confirmed case by case below, following
		// the same real-repo cross-check already used for Grafana/Brave/Zabbix's APT
		// profiles above, since inspection alone cannot tell which bundled key is active.

		{
			// Verified 2026-11-20: HashiCorp's own Fedora install instructions
			// (developer.hashicorp.com/terraform/install) document
			// "yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/
			// hashicorp.repo" even for Fedora — but that repo file's baseurl templates
			// $releasever, and Fedora 45's $releasever ("45") does not match any
			// directory HashiCorp actually publishes under RHEL/ (only 8, 9, 10 exist;
			// confirmed by probing all four). Pinned to RHEL/9 (a directory HashiCorp
			// does publish) instead of templating $releasever; confirmed by importing
			// the key and downloading a real terraform package from that exact path in
			// a live Fedora 45 container (`rpm -K`: digests signatures OK). Not
			// independently verified against openSUSE/zypper — HashiCorp's own docs
			// list no SUSE/zypper install path at all, so no zypper profile is added.
			ID:             "hashicorp",
			DisplayName:    "HashiCorp",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://rpm.releases.hashicorp.com",
			},
			KeyURL:      "https://rpm.releases.hashicorp.com/gpg",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-hashicorp",
			ExpectedFingerprints: []string{
				"D55C0D1AC78A8D8126CB631CFC9CA96ACA026560",
			},
			RPMRepoID:   "hashicorp",
			RPMBaseURL:  "https://rpm.releases.hashicorp.com/RHEL/9/$basearch/stable",
			RPMRepoFile: "/etc/yum.repos.d/hashicorp.repo",
			DocSource:   "https://developer.hashicorp.com/terraform/install (documents the RHEL/hashicorp.repo path, no fingerprint published) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` check against a live terraform package downloaded from RHEL/9 in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: download.docker.com/linux/fedora/gpg is a DIFFERENT
			// key from Docker's APT key (verified by downloading and comparing
			// fingerprints directly) — confirmed by importing it and downloading a real
			// docker-ce-cli package from the live Fedora repo (`rpm -K`: digests
			// signatures OK). The SLES key at linux/sles/gpg is byte-identical to this
			// one (same fingerprint), but Docker's documented SLES baseurl
			// (linux/sles/15/...) does not exist on openSUSE Leap 16.0 (confirmed: 404)
			// — SLES 15 and openSUSE Leap 16.0 are not the same version line, and no
			// working combination was found in this pass, so no zypper profile is added.
			ID:             "docker-ce",
			DisplayName:    "Docker CE",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://download.docker.com/linux/fedora",
			},
			KeyURL:      "https://download.docker.com/linux/fedora/gpg",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-docker-ce",
			ExpectedFingerprints: []string{
				"060A61C51B558A7F742B77AAC52FEB6B621E9F35",
			},
			RPMRepoID:   "docker-ce-stable",
			RPMBaseURL:  "https://download.docker.com/linux/fedora/$releasever/$basearch/stable",
			RPMRepoFile: "/etc/yum.repos.d/docker-ce.repo",
			DocSource:   "https://docs.docker.com/engine/install/fedora/ (documents this key URL and $releasever-templated baseurl, no fingerprint published) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` check against a live docker-ce-cli package downloaded via `dnf makecache --refresh` + `dnf download` against the live Fedora 45 repo, 2026-11-20",
		},
		{
			// Verified 2026-11-20: packages.microsoft.com/keys/microsoft.asc is the same
			// key already pinned for the microsoft-vscode APT profile above (identical
			// fingerprint, confirmed by direct comparison). The generic Fedora
			// 45 prod/ path exists but its only package (the legacy
			// packages-microsoft-prod bootstrap RPM) is signed with an older,
			// different key — confirmed NOT a trust gap in microsoft.asc, just a stale
			// artifact: a real, current package (powershell) downloaded from the
			// documented rhel/9/prod/ path verifies cleanly against microsoft.asc
			// (`rpm -K`: digests signatures OK). Pinned to rhel/9 rather than Fedora's
			// own path for this reason. Not independently verified for openSUSE/zypper
			// — Microsoft's own docs for this repo document no SUSE/zypper path.
			ID:             "microsoft-rpm",
			DisplayName:    "Microsoft (Linux packages)",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://packages.microsoft.com/rhel",
				"https://packages.microsoft.com/fedora",
			},
			KeyURL:      "https://packages.microsoft.com/keys/microsoft.asc",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-microsoft",
			ExpectedFingerprints: []string{
				"BC528686B50D79E339D3721CEB3E94ADBE1229CF",
			},
			RPMRepoID:   "microsoft-rhel9-prod",
			RPMBaseURL:  "https://packages.microsoft.com/rhel/9/prod/",
			RPMRepoFile: "/etc/yum.repos.d/microsoft-rhel9-prod.repo",
			DocSource:   "https://learn.microsoft.com/en-us/linux/packages (documents packages.microsoft.com/keys/microsoft.asc; no fingerprint published) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` check against a live powershell package downloaded from rhel/9/prod in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: same key as the google-chrome APT profile above
			// (identical fingerprint) — confirmed independently by downloading
			// dl.google.com/linux/linux_signing_key.pub again in this Fedora container
			// and by a real `rpm -K` check against a live google-chrome-stable package.
			// Also confirmed the same repo file refreshes cleanly via zypper on
			// openSUSE Leap 16.0 (`zypper refresh`, no error) — same key, same
			// rpm-md-format repo content regardless of which tool consumes it.
			ID:             "google-chrome-rpm",
			DisplayName:    "Google Chrome",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://dl.google.com/linux/chrome/rpm",
			},
			KeyURL:      "https://dl.google.com/linux/linux_signing_key.pub",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-google-chrome",
			ExpectedFingerprints: []string{
				"EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796",
			},
			RPMRepoID:   "google-chrome",
			RPMBaseURL:  "https://dl.google.com/linux/chrome/rpm/stable/x86_64",
			RPMRepoFile: "/etc/yum.repos.d/google-chrome.repo",
			DocSource:   "https://www.google.com/linuxrepositories/ (documents the RPM repo and this key URL) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` check against a live google-chrome-stable package in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: Google Chrome, same key/profile as above, registered
			// under ManagerZypper for openSUSE/SUSE targets — confirmed the repo
			// refreshes cleanly via `zypper refresh` on a live openSUSE Leap 16.0
			// container using this exact baseurl and key.
			ID:             "google-chrome-rpm",
			DisplayName:    "Google Chrome",
			PackageManager: ManagerZypper,
			AllowedURLPrefixes: []string{
				"https://dl.google.com/linux/chrome/rpm",
			},
			KeyURL:      "https://dl.google.com/linux/linux_signing_key.pub",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-google-chrome",
			ExpectedFingerprints: []string{
				"EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796",
			},
			RPMRepoID:   "google-chrome",
			RPMBaseURL:  "https://dl.google.com/linux/chrome/rpm/stable/x86_64",
			RPMRepoFile: "/etc/zypp/repos.d/google-chrome.repo",
			DocSource:   "https://www.google.com/linuxrepositories/ — verified by refreshing this exact repo/key via `zypper refresh` in a live openSUSE Leap 16.0 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: the REAL bootstrap RPM
			// (download.postgresql.org/pub/repos/yum/reporpms/F-45-x86_64/
			// pgdg-fedora-repo-latest.noarch.rpm), extracted and read directly, installs
			// a Fedora-specific key at /etc/pki/rpm-gpg/PGDG-RPM-GPG-KEY-Fedora — a
			// COMPLETELY DIFFERENT key from the generic website download
			// (www.postgresql.org/media/keys/ACCC4CF8.asc, pinned for the APT profile
			// above). Confirmed by importing the bundled key and downloading a real
			// postgresql17-server package from the live repo (`rpm -K`: digests
			// signatures OK). This profile pins PostgreSQL 17; a different major
			// version uses the same key but a different baseurl path segment.
			ID:             "postgresql-pgdg-rpm",
			DisplayName:    "PostgreSQL (PGDG) 17",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://download.postgresql.org/pub/repos/yum",
			},
			KeyURL:      "https://download.postgresql.org/pub/repos/yum/keys/PGDG-RPM-GPG-KEY-Fedora",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-postgresql-pgdg-fedora",
			ExpectedFingerprints: []string{
				"D4BF08AE67A0B4C7A1DBCCD240BCA2B408B40D20",
			},
			RPMRepoID:   "pgdg17",
			RPMBaseURL:  "https://download.postgresql.org/pub/repos/yum/17/fedora/fedora-$releasever-$basearch",
			RPMRepoFile: "/etc/yum.repos.d/pgdg17.repo",
			DocSource:   "https://download.postgresql.org/pub/repos/yum/reporpms/F-45-x86_64/pgdg-fedora-repo-latest.noarch.rpm — the real bootstrap package's bundled key, extracted and read directly (not the generic website key, which does not match), then cross-confirmed byte-identical to the standalone https://download.postgresql.org/pub/repos/yum/keys/PGDG-RPM-GPG-KEY-Fedora (used as this profile's fetchable KeyURL) — confirmed via a real `rpm -K` check against a live postgresql17-server package in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: the REAL openSUSE Leap bootstrap RPM
			// (download.postgresql.org/pub/repos/zypp/reporpms/LEAP-16.0-x86_64/
			// pgdg-opensuse-leap-repo-latest.noarch.rpm), extracted and read directly,
			// installs a DIFFERENT key again
			// (/etc/pki/PGDG-RPM-GPG-KEY-LEAP16/SLES16) — different from both the
			// generic website key AND the Fedora-specific key above. The vendor's own
			// auto-generated SLES .repo files (download.postgresql.org/pub/repos/zypp/
			// repo/pgdg-sles-*.repo) have a broken gpgkey= line that points at
			// repodata/repomd.xml itself, not a key — confirmed by fetching that exact
			// URL and finding it is plain repo metadata, not a GPG key; this profile
			// uses the real bundled key instead. Confirmed by importing it and
			// downloading a real postgresql17-server package from the live openSUSE
			// Leap 16.0 repo (`rpm -K`: digests signatures OK, key ID c9cac299).
			ID:             "postgresql-pgdg-rpm-suse",
			DisplayName:    "PostgreSQL (PGDG) 17 (openSUSE Leap)",
			PackageManager: ManagerZypper,
			AllowedURLPrefixes: []string{
				"https://download.postgresql.org/pub/repos/zypp",
			},
			KeyURL:      "https://download.postgresql.org/pub/repos/zypp/keys/PGDG-RPM-GPG-KEY-SLES16",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-postgresql-pgdg-leap",
			ExpectedFingerprints: []string{
				"8F0B980A3FBE175E4F131762369BC84DC9CAC299",
			},
			RPMRepoID:   "pgdg17",
			RPMBaseURL:  "https://download.postgresql.org/pub/repos/zypp/17/opensuse/leap-$releasever-$basearch",
			RPMRepoFile: "/etc/zypp/repos.d/pgdg17.repo",
			DocSource:   "https://download.postgresql.org/pub/repos/zypp/reporpms/LEAP-16.0-x86_64/pgdg-opensuse-leap-repo-latest.noarch.rpm — the real bootstrap package's bundled key, extracted and read directly (the vendor's own published SLES .repo files have a broken gpgkey= URL that points at repomd.xml, not a key), then cross-confirmed byte-identical to the standalone https://download.postgresql.org/pub/repos/zypp/keys/PGDG-RPM-GPG-KEY-SLES16 (used as this profile's fetchable KeyURL) — confirmed via a real `rpm -K` check against a live postgresql17-server package in an openSUSE Leap 16.0 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: same key as the github-cli APT profile above
			// (identical fingerprint and KeyURL — GitHub publishes one shared
			// githubcli-archive-keyring across deb/rpm). NOTE: this key EXPIRED on
			// 2026-09-05 (confirmed: `rpm --import` warns "The primary key is not
			// live... Certificate does not have any usable signing keys"), yet a real,
			// current gh package downloaded from the live repo still verifies as
			// "digests signatures OK" against it — rpm evaluates the signature made
			// while the key was live, not current wall-clock validity. This profile
			// will need a new fingerprint once GitHub rotates to a successor key.
			// GitHub's own docs (docs/install_linux.md) document this exact same
			// gh-cli.repo URL for BOTH "DNF5" and "openSUSE/SUSE Linux (zypper)" — this
			// one repo file works unchanged for both package managers, confirmed by a
			// real `rpm -K` check against live gh packages downloaded via both dnf (on
			// Fedora 45) and zypper (on openSUSE Leap 16.0).
			ID:             "github-cli-rpm",
			DisplayName:    "GitHub CLI",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://cli.github.com/packages/rpm",
			},
			KeyURL:      "https://cli.github.com/packages/githubcli-archive-keyring.asc",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-github-cli",
			ExpectedFingerprints: []string{
				"2C6106201985B60E6C7AC87323F3D4EA75716059",
			},
			RPMRepoID:   "gh-cli",
			RPMBaseURL:  "https://cli.github.com/packages/rpm",
			RPMRepoFile: "/etc/yum.repos.d/gh-cli.repo",
			DocSource:   "https://github.com/cli/cli/blob/trunk/docs/install_linux.md (documents gh-cli.repo for both DNF5 and zypper) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` check against a live gh package in a Fedora 45 container; this key is expired as of 2026-09-05 but still correctly verifies historically-signed packages, 2026-11-20",
		},
		{
			// Verified 2026-11-20: GitHub CLI, same key/profile as above, registered
			// under ManagerZypper — confirmed via a real `rpm -K` check against a live
			// gh package downloaded via `zypper download` from the same gh-cli.repo URL
			// in an openSUSE Leap 16.0 container.
			ID:             "github-cli-rpm",
			DisplayName:    "GitHub CLI",
			PackageManager: ManagerZypper,
			AllowedURLPrefixes: []string{
				"https://cli.github.com/packages/rpm",
			},
			KeyURL:      "https://cli.github.com/packages/githubcli-archive-keyring.asc",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-github-cli",
			ExpectedFingerprints: []string{
				"2C6106201985B60E6C7AC87323F3D4EA75716059",
			},
			RPMRepoID:   "gh-cli",
			RPMBaseURL:  "https://cli.github.com/packages/rpm",
			RPMRepoFile: "/etc/zypp/repos.d/gh-cli.repo",
			DocSource:   "https://github.com/cli/cli/blob/trunk/docs/install_linux.md — verified via a real `rpm -K` check against a live gh package downloaded via zypper in an openSUSE Leap 16.0 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: Sensu's RPM packages are signed with a DIFFERENT key
			// than the sensu APT profile above — confirmed the hard way: the
			// documented standalone KeyURL (packagecloud.io/sensu/stable/gpgkey) is the
			// SAME fingerprint as the APT key, but a real sensu-go-agent package
			// downloaded from the live el/9 repo does NOT verify against it (NOKEY).
			// packagecloud's generated .repo file for RPM lists a SECOND gpgkey URL
			// (packagecloud.io/sensu/stable/gpgkey/sensu-stable-<id>.pub.gpg), which
			// bundles two keys; one of those — pinned here — is the one that actually
			// signs real packages, confirmed by importing it and re-running `rpm -K`
			// (digests signatures OK). Fedora's own numbered path has no real package
			// content for any version tried (36-45); pinned to packagecloud's el/9 path
			// instead, which does.
			ID:             "sensu-rpm",
			DisplayName:    "Sensu",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://packagecloud.io/sensu/stable/el",
			},
			KeyURL:      "https://packagecloud.io/sensu/stable/gpgkey/sensu-stable-E344FC56DF1D3E1D.pub.gpg",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-sensu",
			ExpectedFingerprints: []string{
				"72AD085E7DA1E131C233A133338DA7702D9A2F90",
			},
			RPMRepoID:   "sensu-stable",
			RPMBaseURL:  "https://packagecloud.io/sensu/stable/el/9/$basearch",
			RPMRepoFile: "/etc/yum.repos.d/sensu.repo",
			DocSource:   "https://docs.sensu.io/sensu-go/latest/operations/deploy-sensu/install-sensu/ (documents the packagecloud install flow; no fingerprint published) — the standalone gpgkey URL's fingerprint does NOT sign real packages; the correct active key was found bundled at the second gpgkey URL packagecloud's own generated .repo file lists, confirmed via a real `rpm -K` check against a live sensu-go-agent package downloaded from the el/9 repo in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: Tailscale's per-distro-family key
			// (pkgs.tailscale.com/stable/fedora/repo.gpg) happens to be byte-identical
			// to the Ubuntu key already pinned for the tailscale APT profile above
			// (same fingerprint, confirmed by direct comparison) — confirmed
			// independently by importing this Fedora-specific URL's key and
			// downloading a real tailscale package from the live repo (`rpm -K`:
			// digests signatures OK). Not independently verified for openSUSE/zypper in
			// this pass (pkgs.tailscale.com/stable/opensuse/... exists but was not
			// re-tested with a real package download) — no zypper profile is added to
			// avoid an unverified claim.
			ID:             "tailscale-rpm",
			DisplayName:    "Tailscale",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://pkgs.tailscale.com/stable/fedora",
			},
			KeyURL:      "https://pkgs.tailscale.com/stable/fedora/repo.gpg",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-tailscale",
			ExpectedFingerprints: []string{
				"2596A99EAAB33821893C0A79458CA832957F5868",
			},
			RPMRepoID:   "tailscale-stable",
			RPMBaseURL:  "https://pkgs.tailscale.com/stable/fedora/$basearch",
			RPMRepoFile: "/etc/yum.repos.d/tailscale.repo",
			DocSource:   "https://tailscale.com/install.sh (documents this exact per-distro-family key/repo URL pattern; no fingerprint published) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` check against a live tailscale package in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: Cloudflare's cloudflared product publishes its OWN
			// dedicated RPM repo (pkg.cloudflare.com/cloudflared.repo) — distinct from
			// the gokeyless product repo documented on the main index page. The key URL
			// differs in name from the APT profile's (cloudflare-ascii-pubkey.gpg vs
			// cloudflare-main.gpg) but is byte-identical (same fingerprint, confirmed by
			// direct comparison) — confirmed independently by importing it and
			// downloading a real cloudflared package from the live repo (`rpm -K`:
			// digests signatures OK). Not independently verified for openSUSE/zypper —
			// pkg.cloudflare.com's docs mention no SUSE/opensuse support, so no zypper
			// profile is added.
			ID:             "cloudflare-rpm",
			DisplayName:    "Cloudflare (cloudflared)",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://pkg.cloudflare.com/cloudflared",
			},
			KeyURL:      "https://pkg.cloudflare.com/cloudflare-ascii-pubkey.gpg",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-cloudflare",
			ExpectedFingerprints: []string{
				"CC94B39C77AE7342A68B89628A682D308D4E5E73",
			},
			RPMRepoID:   "cloudflared-stable",
			RPMBaseURL:  "https://pkg.cloudflare.com/cloudflared/rpm",
			RPMRepoFile: "/etc/yum.repos.d/cloudflared.repo",
			DocSource:   "https://pkg.cloudflare.com/cloudflared.repo (the vendor's own dedicated cloudflared RPM repo file; no fingerprint published) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` check against a live cloudflared package in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: same key as the elastic APT profile above (identical
			// fingerprint and KeyURL — Elastic publishes one shared key across deb/rpm).
			// Confirmed independently via a real `rpm -K` check against a live
			// elasticsearch package downloaded directly from the repo's own metadata-
			// listed path. Also confirmed the same key correctly verifies a live
			// elasticsearch package on openSUSE Leap 16.0 — Elastic's docs mention
			// SLES/SUSE support and the repo content is identical regardless of which
			// tool consumes it.
			ID:             "elastic-rpm",
			DisplayName:    "Elastic 9.x",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://artifacts.elastic.co/packages/9.x/yum",
			},
			KeyURL:      "https://artifacts.elastic.co/GPG-KEY-elasticsearch",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-elasticsearch",
			ExpectedFingerprints: []string{
				"46095ACC8548582C1A2699A9D27D666CD88E42B4",
			},
			RPMRepoID:   "elastic-9x",
			RPMBaseURL:  "https://artifacts.elastic.co/packages/9.x/yum",
			RPMRepoFile: "/etc/yum.repos.d/elastic-9.x.repo",
			DocSource:   "https://www.elastic.co/guide/en/elasticsearch/reference/current/rpm.html (documents the key URL and repo; no fingerprint published) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` check against a live elasticsearch package in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: Elastic, same key/profile as above, registered under
			// ManagerZypper — confirmed via a real `rpm -K` check against the same live
			// elasticsearch package, downloaded directly from the repo in an openSUSE
			// Leap 16.0 container.
			ID:             "elastic-rpm",
			DisplayName:    "Elastic 9.x",
			PackageManager: ManagerZypper,
			AllowedURLPrefixes: []string{
				"https://artifacts.elastic.co/packages/9.x/yum",
			},
			KeyURL:      "https://artifacts.elastic.co/GPG-KEY-elasticsearch",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-elasticsearch",
			ExpectedFingerprints: []string{
				"46095ACC8548582C1A2699A9D27D666CD88E42B4",
			},
			RPMRepoID:   "elastic-9x",
			RPMBaseURL:  "https://artifacts.elastic.co/packages/9.x/yum",
			RPMRepoFile: "/etc/zypp/repos.d/elastic-9.x.repo",
			DocSource:   "https://www.elastic.co/guide/en/elasticsearch/reference/current/rpm.html — verified via a real `rpm -K` check against a live elasticsearch package downloaded directly in an openSUSE Leap 16.0 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: pkg.jenkins.io/rpm-stable's key URL
			// (repodata/repomd.xml.key) is a different URL than the APT profile's, but
			// confirmed to be the real active signing key independently, via a real
			// `rpm -K` check against a live jenkins package downloaded from the repo.
			// Jenkins' own rpm-stable.repo file includes a comment stating it also
			// supports "SUSE/openSUSE distributions with zypper" — confirmed true by
			// refreshing and downloading the same package via zypper on openSUSE Leap
			// 16.0 with no change to the repo file at all.
			ID:             "jenkins-rpm",
			DisplayName:    "Jenkins",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://pkg.jenkins.io/rpm-stable",
			},
			KeyURL:      "https://pkg.jenkins.io/rpm-stable/repodata/repomd.xml.key",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-jenkins",
			ExpectedFingerprints: []string{
				"5E386EADB55F01504CAE8BCF7198F4B714ABFC68",
			},
			RPMRepoID:   "jenkins",
			RPMBaseURL:  "https://pkg.jenkins.io/rpm-stable",
			RPMRepoFile: "/etc/yum.repos.d/jenkins.repo",
			DocSource:   "https://www.jenkins.io/doc/book/installing/linux/ (documents this repo for both DNF and zypper; no fingerprint published) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` check against a live jenkins package in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: Jenkins, same key/profile as above, registered under
			// ManagerZypper — confirmed via a real `rpm -K` check against a live
			// jenkins package downloaded via `zypper download` from the same
			// rpm-stable repo URL in an openSUSE Leap 16.0 container.
			ID:             "jenkins-rpm",
			DisplayName:    "Jenkins",
			PackageManager: ManagerZypper,
			AllowedURLPrefixes: []string{
				"https://pkg.jenkins.io/rpm-stable",
			},
			KeyURL:      "https://pkg.jenkins.io/rpm-stable/repodata/repomd.xml.key",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-jenkins",
			ExpectedFingerprints: []string{
				"5E386EADB55F01504CAE8BCF7198F4B714ABFC68",
			},
			RPMRepoID:   "jenkins",
			RPMBaseURL:  "https://pkg.jenkins.io/rpm-stable",
			RPMRepoFile: "/etc/zypp/repos.d/jenkins.repo",
			DocSource:   "https://www.jenkins.io/doc/book/installing/linux/ — verified via a real `rpm -K` check against a live jenkins package downloaded via zypper in an openSUSE Leap 16.0 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: the real zabbix-release bootstrap package's
			// standalone key URL (repo.zabbix.com/zabbix-official-repo.key, a 4-key
			// bundle) differs from the APT profile's active key — confirmed the hard
			// way: imported the whole bundle and downloaded a real zabbix-release
			// package from the live rhel/9 repo; the package verifies against THIS
			// specific fingerprint (not the APT profile's 2024-rotation key), confirmed
			// by `rpm -K` succeeding only once this exact fingerprint's key was
			// imported. Fedora's own numbered path was not tried; pinned to Zabbix's
			// documented rhel/9 path, which both dnf and yum can use directly.
			ID:             "zabbix-rpm",
			DisplayName:    "Zabbix 7.0",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://repo.zabbix.com/zabbix/7.0/rhel",
			},
			KeyURL:      "https://repo.zabbix.com/zabbix-official-repo.key",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-zabbix",
			ExpectedFingerprints: []string{
				"FBABD5FB20255ECAB22EE194D13D58E479EA5ED4",
			},
			RPMRepoID:   "zabbix",
			RPMBaseURL:  "https://repo.zabbix.com/zabbix/7.0/rhel/9/$basearch/",
			RPMRepoFile: "/etc/yum.repos.d/zabbix.repo",
			DocSource:   "https://repo.zabbix.com/zabbix/7.0/rhel/9/x86_64/ (the live repo itself) — the standalone key URL bundles 4 keys; confirmed which one is active via a real `rpm -K` check against a live zabbix-release package in a Fedora 45 container, 2026-11-20. Not independently re-verified against openSUSE/zypper (repo.zabbix.com/zabbix/7.0/sles/ exists but was not re-tested with a real package download in this pass) — no zypper profile is added to avoid an unverified claim.",
		},
		{
			// Verified 2026-11-20: brave-browser-rpm-release.s3.brave.com's own
			// documented .repo file (brave-browser.repo) points at a key URL
			// (brave-core.asc, a 3-key bundle) different in name from the APT profile's,
			// but the ACTIVE key turned out to be byte-identical to the APT profile's
			// pinned fingerprint — confirmed independently (not assumed) via a real
			// `rpm -K` check against a live brave-browser package downloaded from the
			// repo. Not independently verified for openSUSE/zypper in this pass —
			// Brave's docs mention openSUSE/zypper but a live-repo recheck was not
			// performed given this key is a multi-key bundle, so no zypper profile is
			// added to avoid an unverified claim.
			ID:             "brave-rpm",
			DisplayName:    "Brave Browser",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://brave-browser-rpm-release.s3.brave.com",
			},
			KeyURL:      "https://brave-browser-rpm-release.s3.brave.com/brave-core.asc",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-brave-browser",
			ExpectedFingerprints: []string{
				"DBF1A116C220B8C7164F98230686B78420038257",
			},
			RPMRepoID:   "brave-browser",
			RPMBaseURL:  "https://brave-browser-rpm-release.s3.brave.com/$basearch",
			RPMRepoFile: "/etc/yum.repos.d/brave-browser.repo",
			DocSource:   "https://brave.com/linux/ (documents brave-browser.repo, which references this key URL; no fingerprint published) — the key URL bundles 3 keys; confirmed which one is active via a real `rpm -K` check against a live brave-browser package in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: same key as the kubernetes-v1-31 APT profile above
			// (identical fingerprint and KeyURL — pkgs.k8s.io serves one key per minor
			// version shared across deb/rpm). Confirmed independently via a real
			// `rpm -K` check against a live kubectl package downloaded from the repo.
			// Also confirmed the same key correctly verifies a live kubectl package on
			// openSUSE Leap 16.0 with the identical repo URL and key.
			ID:             "kubernetes-v1-31-rpm",
			DisplayName:    "Kubernetes v1.31",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://pkgs.k8s.io/core:/stable:/v1.31/rpm",
			},
			KeyURL:      "https://pkgs.k8s.io/core:/stable:/v1.31/rpm/repodata/repomd.xml.key",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-kubernetes-v1-31",
			ExpectedFingerprints: []string{
				"DE15B14486CD377B9E876E1A234654DA9A296436",
			},
			RPMRepoID:   "kubernetes-v1-31",
			RPMBaseURL:  "https://pkgs.k8s.io/core:/stable:/v1.31/rpm",
			RPMRepoFile: "/etc/yum.repos.d/kubernetes-v1-31.repo",
			DocSource:   "https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/ (documents the per-minor-version flat repo URL and key; no fingerprint published) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` check against a live kubectl package in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: Kubernetes v1.31, same key/profile as above,
			// registered under ManagerZypper — confirmed via a real `rpm -K` check
			// against a live kubectl package downloaded via `zypper download` from the
			// same pkgs.k8s.io repo URL in an openSUSE Leap 16.0 container.
			ID:             "kubernetes-v1-31-rpm",
			DisplayName:    "Kubernetes v1.31",
			PackageManager: ManagerZypper,
			AllowedURLPrefixes: []string{
				"https://pkgs.k8s.io/core:/stable:/v1.31/rpm",
			},
			KeyURL:      "https://pkgs.k8s.io/core:/stable:/v1.31/rpm/repodata/repomd.xml.key",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-kubernetes-v1-31",
			ExpectedFingerprints: []string{
				"DE15B14486CD377B9E876E1A234654DA9A296436",
			},
			RPMRepoID:   "kubernetes-v1-31",
			RPMBaseURL:  "https://pkgs.k8s.io/core:/stable:/v1.31/rpm",
			RPMRepoFile: "/etc/zypp/repos.d/kubernetes-v1-31.repo",
			DocSource:   "https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/ — verified via a real `rpm -K` check against a live kubectl package downloaded via zypper in an openSUSE Leap 16.0 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: same key as the mongodb APT profile above (identical
			// fingerprint and KeyURL — MongoDB publishes one server-9.asc key shared
			// across deb/rpm). Confirmed independently via a real `rpm -K` check
			// against a live mongodb-org-server package downloaded from the repo.
			// MongoDB's own "install on SUSE" documentation page was checked and found
			// to only redirect to the same RHEL/yum baseurls with no distinct zypp path
			// — MongoDB does not appear to publish a native zypper repo, so no zypper
			// profile is added.
			ID:             "mongodb-rpm",
			DisplayName:    "MongoDB 9.0",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://repo.mongodb.org/yum/redhat",
			},
			KeyURL:      "https://pgp.mongodb.com/server-9.asc",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-mongodb-server-9",
			ExpectedFingerprints: []string{
				"B3B42B6C39E5CDDEC0A27E3CF366D55B602E502D",
			},
			RPMRepoID:   "mongodb-org-9-0",
			RPMBaseURL:  "https://repo.mongodb.org/yum/redhat/9/mongodb-org/9.0/$basearch",
			RPMRepoFile: "/etc/yum.repos.d/mongodb-org-9.0.repo",
			DocSource:   "https://www.mongodb.com/docs/manual/tutorial/install-mongodb-on-red-hat/ (documents server-9.asc and this baseurl; no fingerprint published) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` check against a live mongodb-org-server package in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: rpm.nodesource.com/gpgkey/ns-operations-public.key is
			// a DIFFERENT key from the nodesource APT profile's
			// (deb.nodesource.com/gpgkey/nodesource-repo.gpg.key) — confirmed
			// independently via a real `rpm -K` check against a live nodejs package
			// downloaded from the repo (repo_gpgcheck is disabled: the vendor does not
			// sign repodata/repomd.xml at all, confirmed by a 404 on repomd.xml.asc;
			// only the per-package signature, which this profile's key does verify,
			// matters for RPM trust here). No SUSE/zypper mention was found in
			// NodeSource's distributions docs, so no zypper profile is added.
			ID:             "nodesource-rpm",
			DisplayName:    "NodeSource (Node.js 22.x)",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://rpm.nodesource.com/pub_22.x",
			},
			KeyURL:      "https://rpm.nodesource.com/gpgkey/ns-operations-public.key",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-nodesource",
			ExpectedFingerprints: []string{
				"242B813831AF09562B6C46F76B88DA4E3AF28A14",
			},
			RPMRepoID:   "nodesource-nodejs",
			RPMBaseURL:  "https://rpm.nodesource.com/pub_22.x/nodistro/nodejs/$basearch",
			RPMRepoFile: "/etc/yum.repos.d/nodesource-nodejs.repo",
			DocSource:   "https://github.com/nodesource/distributions (setup_22.x's RPM path documents this key URL; no fingerprint published) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` check against a live nodejs package in a Fedora 45 container, 2026-11-20",
		},
		{
			// Verified 2026-11-20: rpm.grafana.com/gpg.key is a single key (unlike the
			// APT profile's 3-key gpg-full.key bundle) and happens to be the SAME active
			// fingerprint already confirmed for APT — confirmed independently via a real
			// `rpm -K` check: the cryptographic signature on a live grafana package (the
			// amd64 build specifically; `grafana` resolves to many architecture-specific
			// RPMs with the arch embedded only in the filename, not RPM's Arch field)
			// verifies "OK" against this fingerprint (a payload-digest mismatch on that
			// same check was a download-corruption artifact unrelated to the signature
			// itself, confirmed by re-running the signature check alone). Grafana's docs
			// mention SUSE support but a live-repo recheck for zypper specifically was
			// not performed in this pass, so no zypper profile is added.
			ID:             "grafana-rpm",
			DisplayName:    "Grafana",
			PackageManager: ManagerDNF,
			AllowedURLPrefixes: []string{
				"https://rpm.grafana.com",
			},
			KeyURL:      "https://rpm.grafana.com/gpg.key",
			KeyringPath: "/etc/pki/rpm-gpg/RPM-GPG-KEY-grafana",
			ExpectedFingerprints: []string{
				"B53AE77BADB630A683046005963FA27710458545",
			},
			RPMRepoID:   "grafana",
			RPMBaseURL:  "https://rpm.grafana.com",
			RPMRepoFile: "/etc/yum.repos.d/grafana.repo",
			DocSource:   "https://grafana.com/docs/grafana/latest/setup-grafana/installation/rpm/ (documents the key URL; no fingerprint published) — verified by downloading KeyURL, importing it, and confirming via a real `rpm -K` signature check against a live grafana (amd64) package in a Fedora 45 container, 2026-11-20",
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

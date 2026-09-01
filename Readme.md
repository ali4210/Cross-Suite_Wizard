# Cross-SSH (Universal Infrastructure Utility)

`cross-ssh` is a zero-dependency, cross-platform CLI tool engineered to bridge SSH passwordless configuration, diagnostic probing, and streaming file/folder transfers seamlessly across Linux (Debian, Ubuntu, RHEL, CentOS), macOS, and Windows environments.

---

## Key Capabilities

* **Universal Passwordless SSH Engine:** Automates Ed25519 key generation, remote OS fingerprinting, POSIX file permissions (`0700`/`0600`), and Windows `administrators_authorized_keys` ACL handling.
* **Local Identity Auto-Registration:** Automatically updates local `~/.ssh/config` so standard `ssh user@host` works without manual flags.
* **Bidirectional File & Directory Engine:** Supports single file SFTP copy alongside zero-disk streaming folder zip/unzip extraction.
* **Telnet & TCP Diagnostic Prober:** Rapidly checks remote port states and captures service banners prior to establishing SSH sessions.
* **Single Binary Execution:** Compiles to statically-linked binaries with zero system dependencies.

---

## Quick Installation

### Linux & macOS (One-Line Installer)
```bash
curl -fsSL [https://raw.githubusercontent.com/yourusername/cross-ssh/main/install.sh](https://raw.githubusercontent.com/yourusername/cross-ssh/main/install.sh) | bash


Usage Examples
1. Bootstrap Passwordless SSH Setup
Bash
cross-ssh -host 192.168.0.202 -user saleem -pass "RemotePassword" -bootstrap
2. Run Diagnostic TCP/Telnet Port Probe
Bash
cross-ssh -host 192.168.0.202 -port 22 -probe
3. Upload File or Directory
Bash
cross-ssh -host 192.168.0.202 -user saleem -upload ./myfolder -dest /home/saleem/target_folder
4. Download Remote File or Directory
Bash
cross-ssh -host 192.168.0.202 -user saleem -download /var/log/syslog -dest ./downloaded_syslog.log
EOF


---

### => Step 3: Commit and Push to GitHub

Initialize git, commit your files, and push to your open-source repository:

```bash
git init
git add .
git commit -m "feat: complete initial release of cross-ssh engine"
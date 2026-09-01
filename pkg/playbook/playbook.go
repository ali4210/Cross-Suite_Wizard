package playbook

import (
	"bufio"

	"cross-ssh/pkg/osdetect"
	"golang.org/x/crypto/ssh"
)

// ShowPlaybookRunnerMenu acts as the package entry point for Hub 5
func ShowPlaybookRunnerMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS) {
	ShowPresetsMenu(reader, client, targetOS)
}
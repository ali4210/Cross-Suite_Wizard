package compliance

import (
	"bufio"

	"cross-ssh/pkg/osdetect"
	"golang.org/x/crypto/ssh"
)

func ShowComplianceAuditorMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS) {
	AuditCompliance(reader, client, targetOS, "")
}
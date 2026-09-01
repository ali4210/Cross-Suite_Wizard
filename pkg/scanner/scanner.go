package scanner

import (
	"bufio"

	"cross-ssh/pkg/osdetect"
	"golang.org/x/crypto/ssh"
)

func ShowVulnerabilityScannerMenu(reader *bufio.Reader, client *ssh.Client, targetOS osdetect.TargetOS, host string) {
	ShowScannerMenu(reader, client, targetOS, host)
}
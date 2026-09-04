package repohealer

import (
	"regexp"
	"strconv"
	"strings"
)

type APTSourceReference struct {
	SourceFile    string
	LineNumber    int
	SourceLine    string
	RepositoryURL string
	KeyringPath   string
}

var aptSignedByPattern = regexp.MustCompile(
	`(?i)\bsigned-by\s*=\s*([^\s\]]+)`,
)

func ParseAPTListSourceReference(line string) (APTSourceReference, bool) {
	trimmed := strings.TrimSpace(line)

	firstSeparator := strings.Index(trimmed, ":")
	if firstSeparator < 1 {
		return APTSourceReference{}, false
	}

	sourceFile := strings.TrimSpace(trimmed[:firstSeparator])
	remainder := trimmed[firstSeparator+1:]

	secondSeparator := strings.Index(remainder, ":")
	if secondSeparator < 1 {
		return APTSourceReference{}, false
	}

	lineNumberText := strings.TrimSpace(remainder[:secondSeparator])
	sourceLine := strings.TrimSpace(remainder[secondSeparator+1:])

	lineNumber, err := strconv.Atoi(lineNumberText)
	if err != nil || lineNumber < 1 {
		return APTSourceReference{}, false
	}

	if !strings.HasPrefix(sourceLine, "deb ") &&
		!strings.HasPrefix(sourceLine, "deb-src ") {
		return APTSourceReference{}, false
	}

	signedByMatch := aptSignedByPattern.FindStringSubmatch(sourceLine)
	if len(signedByMatch) != 2 {
		return APTSourceReference{}, false
	}

	keyringPath := strings.TrimSpace(signedByMatch[1])
	repositoryURL := extractRepositoryURL(sourceLine)

	if sourceFile == "" || sourceLine == "" ||
		keyringPath == "" || repositoryURL == "" {
		return APTSourceReference{}, false
	}

	return APTSourceReference{
		SourceFile:    sourceFile,
		LineNumber:    lineNumber,
		SourceLine:    sourceLine,
		RepositoryURL: repositoryURL,
		KeyringPath:   keyringPath,
	}, true
}

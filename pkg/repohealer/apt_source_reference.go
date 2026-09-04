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

var aptListSourceReferencePattern = regexp.MustCompile(
	`^(.+):([0-9]+):(deb(?:-src)?[[:space:]]+\[[^]]*signed-by[[:space:]]*=[[:space:]]*([^][[:space:]]+)[^]]*\][[:space:]]+.+)$`,
)

func ParseAPTListSourceReference(line string) (APTSourceReference, bool) {
	match := aptListSourceReferencePattern.FindStringSubmatch(strings.TrimSpace(line))
	if len(match) != 4 {
		return APTSourceReference{}, false
	}

	lineNumber, err := strconv.Atoi(match[2])
	if err != nil || lineNumber < 1 {
		return APTSourceReference{}, false
	}

	sourceLine := strings.TrimSpace(match[3])
	keyringPath := strings.TrimSpace(match[4])
	repositoryURL := extractRepositoryURL(sourceLine)

	if match[1] == "" || sourceLine == "" || keyringPath == "" || repositoryURL == "" {
		return APTSourceReference{}, false
	}

	return APTSourceReference{
		SourceFile:    strings.TrimSpace(match[1]),
		LineNumber:    lineNumber,
		SourceLine:    sourceLine,
		RepositoryURL: repositoryURL,
		KeyringPath:   keyringPath,
	}, true
}

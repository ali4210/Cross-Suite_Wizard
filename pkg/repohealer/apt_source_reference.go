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
	SourceFormat  SourceFormat
}

var aptSignedByPattern = regexp.MustCompile(
	`(?i)\bsigned-by\s*=\s*([^\s\]]+)`,
)

var deb822SignedByPattern = regexp.MustCompile(
	`(?im)^signed-by:\s*([^\s#]+)\s*$`,
)

var deb822URIPattern = regexp.MustCompile(
	`(?im)^uris:\s*(https?://[^\s]+)\s*$`,
)

var aptRepositoryURLPattern = regexp.MustCompile(
	`^https?://[^\s\]]+$`,
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
		keyringPath == "" || !isValidAPTRepositoryURL(repositoryURL) {
		return APTSourceReference{}, false
	}

	return APTSourceReference{
		SourceFile:    sourceFile,
		LineNumber:    lineNumber,
		SourceLine:    sourceLine,
		RepositoryURL: repositoryURL,
		KeyringPath:   keyringPath,
		SourceFormat:  SourceFormatAPTList,
	}, true
}

func ParseAPTDeb822SourceReference(
	sourceFile string,
	stanzaStartLine int,
	stanza string,
) (APTSourceReference, bool) {
	sourceFile = strings.TrimSpace(sourceFile)
	stanza = strings.TrimSpace(stanza)

	if sourceFile == "" || stanzaStartLine < 1 || stanza == "" {
		return APTSourceReference{}, false
	}

	signedByMatch := deb822SignedByPattern.FindStringSubmatch(stanza)
	if len(signedByMatch) != 2 {
		return APTSourceReference{}, false
	}

	uriMatch := deb822URIPattern.FindStringSubmatch(stanza)
	if len(uriMatch) != 2 {
		return APTSourceReference{}, false
	}

	keyringPath := strings.TrimSpace(signedByMatch[1])
	repositoryURL := strings.TrimSpace(uriMatch[1])

	if keyringPath == "" || !isValidAPTRepositoryURL(repositoryURL) {
		return APTSourceReference{}, false
	}

	return APTSourceReference{
		SourceFile:    sourceFile,
		LineNumber:    stanzaStartLine,
		SourceLine:    stanza,
		RepositoryURL: repositoryURL,
		KeyringPath:   keyringPath,
		SourceFormat:  SourceFormatDeb822,
	}, true
}

func isValidAPTRepositoryURL(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if strings.Contains(value, "[") ||
		strings.Contains(value, "]") ||
		strings.Contains(value, "(") ||
		strings.Contains(value, ")") {
		return false
	}
	return aptRepositoryURLPattern.MatchString(value)
}

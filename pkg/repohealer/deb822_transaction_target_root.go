package repohealer

import (
	"fmt"
	"path/filepath"
	"strings"
)

func resolveDeb822ExecutionTargetPath(
	targetRoot string,
	logicalPath string,
) (string, error) {
	targetRoot = strings.TrimSpace(targetRoot)
	if targetRoot == "" {
		return logicalPath, nil
	}

	cleanRoot := filepath.Clean(targetRoot)
	if !filepath.IsAbs(cleanRoot) ||
		cleanRoot == string(filepath.Separator) {
		return "", fmt.Errorf(
			"Deb822 execution target root must be an absolute non-root path",
		)
	}

	cleanLogical := filepath.Clean(logicalPath)
	if !filepath.IsAbs(cleanLogical) ||
		cleanLogical == string(filepath.Separator) {
		return "", fmt.Errorf(
			"Deb822 execution logical path must be absolute and non-root",
		)
	}

	relative := strings.TrimPrefix(
		cleanLogical,
		string(filepath.Separator),
	)
	if relative == "" ||
		relative == "." ||
		relative == ".." ||
		strings.HasPrefix(
			relative,
			".."+string(filepath.Separator),
		) {
		return "", fmt.Errorf(
			"Deb822 execution logical path is unsafe",
		)
	}

	resolved := filepath.Join(cleanRoot, relative)
	relativeResolved, err := filepath.Rel(cleanRoot, resolved)
	if err != nil ||
		relativeResolved == "." ||
		relativeResolved == ".." ||
		strings.HasPrefix(
			relativeResolved,
			".."+string(filepath.Separator),
		) {
		return "", fmt.Errorf(
			"Deb822 execution resolved target path escapes target root",
		)
	}

	return resolved, nil
}

package repohealer

import (
	"path/filepath"
	"testing"
)

func TestResolveDeb822ExecutionTargetPathUsesLogicalPathWithoutTargetRoot(
	t *testing.T,
) {
	logical := "/etc/apt/sources.list.d/docker.sources"

	got, err := resolveDeb822ExecutionTargetPath("", logical)
	if err != nil {
		t.Fatalf("resolveDeb822ExecutionTargetPath() error = %v", err)
	}
	if got != logical {
		t.Fatalf("path = %q, want %q", got, logical)
	}
}

func TestResolveDeb822ExecutionTargetPathMapsUnderTargetRoot(t *testing.T) {
	root := t.TempDir()
	logical := "/etc/apt/sources.list.d/docker.sources"

	got, err := resolveDeb822ExecutionTargetPath(root, logical)
	if err != nil {
		t.Fatalf("resolveDeb822ExecutionTargetPath() error = %v", err)
	}

	want := filepath.Join(
		root,
		"etc",
		"apt",
		"sources.list.d",
		"docker.sources",
	)
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func TestResolveDeb822ExecutionTargetPathRejectsUnsafeRootsAndPaths(
	t *testing.T,
) {
	tests := []struct {
		name        string
		targetRoot  string
		logicalPath string
	}{
		{
			name:        "Relative target root",
			targetRoot:  "relative-root",
			logicalPath: "/etc/apt/sources.list.d/docker.sources",
		},
		{
			name:        "Root target root",
			targetRoot:  "/",
			logicalPath: "/etc/apt/sources.list.d/docker.sources",
		},
		{
			name:        "Relative logical path",
			targetRoot:  t.TempDir(),
			logicalPath: "etc/apt/sources.list.d/docker.sources",
		},
		{
			name:        "Root logical path",
			targetRoot:  t.TempDir(),
			logicalPath: "/",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := resolveDeb822ExecutionTargetPath(
				test.targetRoot,
				test.logicalPath,
			); err == nil {
				t.Fatal("unsafe root or logical path unexpectedly resolved")
			}
		})
	}
}

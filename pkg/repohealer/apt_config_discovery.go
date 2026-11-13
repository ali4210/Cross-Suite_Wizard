package repohealer

import "strings"

// DiscoverAPTConfigFiles runs the same read-only grep/find probes APTAdapter.Diagnose already
// uses to find every currently-configured APT source file and its referenced keyring, and
// returns the de-duplicated union of both as a flat list of absolute paths. It is used by
// Option 9's "Save a checkpoint now" to snapshot the APT configuration footprint without
// requiring a prior Diagnose run or a specific pending finding/action to snapshot against.
func DiscoverAPTConfigFiles(exec Executor) ([]string, error) {
	const script = `
set +e
echo '=== APT_SOURCES ==='
grep -RIn --include='*.list' --include='*.sources' \
  -E '^[[:space:]]*(deb|Types:|URIs:|Suites:|Components:|Architectures:|Signed-By:)' \
  /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null

echo '=== DEB822_SOURCES ==='
find /etc/apt/sources.list.d -maxdepth 1 -type f -name '*.sources' -print0 2>/dev/null \
  | while IFS= read -r -d '' source_file; do
      printf '%s\n' '--- DEB822_FILE_BEGIN ---'
      printf '%s\n' "$source_file"
      cat "$source_file"
      printf '%s\n' '--- DEB822_FILE_END ---'
    done
`
	inventory, err := exec.RunSudo(script)
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var files []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		files = append(files, path)
	}

	for _, line := range strings.Split(inventory, "\n") {
		reference, ok := ParseAPTListSourceReference(line)
		if !ok {
			continue
		}
		add(reference.SourceFile)
		add(reference.KeyringPath)
	}

	for _, document := range ParseAPTDeb822Inventory(inventory) {
		for _, stanza := range document.Stanzas {
			reference, ok := ParseAPTDeb822SourceReference(
				document.SourceFile,
				stanza.StartLine,
				stanza.Content,
			)
			if !ok {
				continue
			}
			add(reference.SourceFile)
			add(reference.KeyringPath)
		}
	}

	return files, nil
}

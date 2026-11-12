package repohealer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// defaultHomebrewSnapshotRoot lives under the invoking user's home directory, not
// /var/lib/cross-suite, because Homebrew refuses to run as root — every command here goes
// through Executor.Run (the non-root channel), never RunSudo.
const defaultHomebrewSnapshotRoot = "$HOME/.cross-suite/homebrew-snapshots"

var homebrewSnapshotIDPattern = regexp.MustCompile(`^brew-[0-9TZ]+-[0-9a-f]+$`)

// CreateHomebrewSnapshot captures the current Homebrew state — every installed formula,
// cask, tap, and (if present) VS Code extension — to a Brewfile via `brew bundle dump`.
// This is Homebrew's own standard snapshot mechanism; restoring it (RestoreHomebrewSnapshot)
// re-installs anything the Brewfile lists that's missing, the same semantics `brew bundle`
// always has. It does not (and cannot) undo an in-place `brew cleanup`, since that only
// removes old cached downloads/versions that are gone once removed — a Brewfile only
// captures *which* formulae/taps are present, not their old binaries.
func CreateHomebrewSnapshot(exec Executor) (Snapshot, error) {
	now := time.Now().UTC()
	id, err := newHomebrewSnapshotID(now)
	if err != nil {
		return Snapshot{CreatedAt: now, Created: false}, fmt.Errorf("create Homebrew snapshot ID: %w", err)
	}

	dir := defaultHomebrewSnapshotRoot + "/" + id
	path := dir + "/Brewfile"

	script := fmt.Sprintf(`set -eu
mkdir -p %s
brew bundle dump --force --file=%s
`, shellQuote(dir), shellQuote(path))

	out, err := exec.Run(script)
	if err != nil {
		return Snapshot{ID: id, Path: path, CreatedAt: now, Created: false}, fmt.Errorf("brew bundle dump failed: %w: %s", err, strings.TrimSpace(out))
	}

	return Snapshot{ID: id, Path: path, CreatedAt: now, Created: true}, nil
}

// RestoreHomebrewSnapshot replays a captured Brewfile via `brew bundle install`, which
// installs anything the snapshot lists that's currently missing. It does not uninstall
// formulae/taps added after the snapshot was taken — the same behavior `brew bundle`
// always has; this is not a limitation introduced here.
func RestoreHomebrewSnapshot(exec Executor, snapshot Snapshot) error {
	if !snapshot.Created || snapshot.Path == "" {
		return fmt.Errorf("cannot restore: no valid Homebrew snapshot is available")
	}
	if !homebrewSnapshotIDPattern.MatchString(snapshot.ID) {
		return fmt.Errorf("invalid Homebrew snapshot id %q", snapshot.ID)
	}

	script := fmt.Sprintf(`set -eu
test -f %s
brew bundle install --file=%s
`, shellQuote(snapshot.Path), shellQuote(snapshot.Path))

	out, err := exec.Run(script)
	if err != nil {
		return fmt.Errorf("brew bundle install failed: %w: %s", err, strings.TrimSpace(out))
	}
	return nil
}

// ListHomebrewSnapshots enumerates every Brewfile snapshot under defaultHomebrewSnapshotRoot,
// newest first.
func ListHomebrewSnapshots(exec Executor) ([]Snapshot, error) {
	script := fmt.Sprintf(`set +e
ROOT=%s
[ -d "$ROOT" ] || exit 0
for d in "$ROOT"/*/; do
	[ -d "$d" ] || continue
	id="$(basename "$d")"
	[ -f "$d/Brewfile" ] || continue
	printf 'SNAPSHOT|%%s|%%s\n' "$id" "$d/Brewfile"
done
`, shellQuote(defaultHomebrewSnapshotRoot))

	out, err := exec.Run(script)
	if err != nil {
		return nil, err
	}

	var snapshots []Snapshot
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "SNAPSHOT|") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 || !homebrewSnapshotIDPattern.MatchString(parts[1]) {
			continue
		}
		snapshots = append(snapshots, Snapshot{ID: parts[1], Path: parts[2], Created: true})
	}

	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].ID > snapshots[j].ID })
	return snapshots, nil
}

func newHomebrewSnapshotID(now time.Time) (string, error) {
	randomBytes := make([]byte, 12)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("brew-%s-%s", now.UTC().Format("20060102T150405Z"), hex.EncodeToString(randomBytes)), nil
}

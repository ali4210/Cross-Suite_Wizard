package repohealer

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

const defaultAPTSnapshotRoot = "/var/lib/cross-suite/snapshots"

func CreateAPTFileSnapshot(exec Executor, files []string) (Snapshot, error) {
	now := time.Now().UTC()

	snapshotID, err := newAPTFileSnapshotID(now)
	if err != nil {
		return Snapshot{
			CreatedAt: now,
			Created:   false,
		}, fmt.Errorf("create APT snapshot ID: %w", err)
	}

	return createAPTFileSnapshotAtRoot(
		exec,
		files,
		defaultAPTSnapshotRoot,
		now,
		snapshotID,
	)
}

func newAPTFileSnapshotID(now time.Time) (string, error) {
	randomBytes := make([]byte, 12)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	return fmt.Sprintf(
		"apt-%s-%s",
		now.UTC().Format("20060102T150405Z"),
		hex.EncodeToString(randomBytes),
	), nil
}

func createAPTFileSnapshotAtRoot(
	exec Executor,
	files []string,
	snapshotRoot string,
	now time.Time,
	snapshotID string,
) (Snapshot, error) {
	snapshotRoot = strings.TrimSpace(snapshotRoot)
	snapshotID = strings.TrimSpace(snapshotID)

	if err := validateAPTFileSnapshotRoot(snapshotRoot); err != nil {
		return Snapshot{
			ID:        snapshotID,
			CreatedAt: now,
			Created:   false,
		}, err
	}

	if err := validateAPTFileSnapshotID(snapshotID); err != nil {
		return Snapshot{
			ID:        snapshotID,
			CreatedAt: now,
			Created:   false,
		}, err
	}

	snapshotPath := path.Join(snapshotRoot, snapshotID)
	if path.Dir(snapshotPath) != strings.TrimRight(snapshotRoot, "/") {
		return Snapshot{
				ID:        snapshotID,
				Path:      snapshotPath,
				CreatedAt: now,
				Created:   false,
			}, fmt.Errorf(
				"invalid APT snapshot path %q outside root %q",
				snapshotPath,
				snapshotRoot,
			)
	}

	targets := shellArray(files)

	script := fmt.Sprintf(`
set -eu

SNAPSHOT_ROOT=%s
SNAPSHOT_DIR=%s
TARGETS=(%s)

install -d -m 0700 "$SNAPSHOT_ROOT"
mkdir -m 0700 "$SNAPSHOT_DIR"
install -d -m 0700 "$SNAPSHOT_DIR/files"

cat > "$SNAPSHOT_DIR/manifest.txt" <<'MANIFEST'
snapshot_id=%s
created_at=%s
scope=targeted-apt-files
MANIFEST

chmod 0600 "$SNAPSHOT_DIR/manifest.txt"

for target in "${TARGETS[@]}"; do
	relative="${target#/}"
	metadata="$SNAPSHOT_DIR/files/${relative}.meta"
	content="$SNAPSHOT_DIR/files/${relative}.content"

	mkdir -p "$(dirname "$metadata")"

	if [ -e "$target" ]; then
		printf 'present\n' > "$metadata"
		stat -c '%%a' "$target" >> "$metadata"
		cp -a "$target" "$content"
	else
		printf 'absent\n' > "$metadata"
	fi

	chmod 0600 "$metadata"
	if [ -f "$content" ]; then
		chmod 0600 "$content"
	fi
done

(
	cd "$SNAPSHOT_DIR"

	sha256sum manifest.txt

	if find files -type f -print -quit | grep -q .; then
		find files -type f -print0 \
			| sort -z \
			| xargs -0 sha256sum
	fi
) > "$SNAPSHOT_DIR/checksums.sha256"

chmod 0600 "$SNAPSHOT_DIR/checksums.sha256"
`,
		shellQuote(snapshotRoot),
		shellQuote(snapshotPath),
		targets,
		snapshotID,
		now.UTC().Format(time.RFC3339),
	)

	_, err := exec.RunSudo(script)
	if err != nil {
		return Snapshot{
			ID:        snapshotID,
			Path:      snapshotPath,
			CreatedAt: now,
			Created:   false,
		}, err
	}

	return Snapshot{
		ID:        snapshotID,
		Path:      snapshotPath,
		CreatedAt: now,
		Created:   true,
	}, nil
}

func validateAPTFileSnapshotRoot(snapshotRoot string) error {
	if snapshotRoot == "" {
		return fmt.Errorf("APT snapshot root is empty")
	}

	cleaned := path.Clean(snapshotRoot)
	if !strings.HasPrefix(cleaned, "/") || cleaned == "/" {
		return fmt.Errorf("APT snapshot root %q must be an absolute non-root path", snapshotRoot)
	}

	return nil
}

func validateAPTFileSnapshotID(snapshotID string) error {
	if snapshotID == "" {
		return fmt.Errorf("APT snapshot ID is empty")
	}

	if snapshotID == "." ||
		snapshotID == ".." ||
		strings.Contains(snapshotID, "/") ||
		strings.Contains(snapshotID, "\\") {
		return fmt.Errorf("APT snapshot ID %q is invalid", snapshotID)
	}

	if !strings.HasPrefix(snapshotID, "apt-") {
		return fmt.Errorf(
			"APT snapshot ID %q must begin with %q",
			snapshotID,
			"apt-",
		)
	}

	return nil
}

func RestoreAPTFileSnapshot(exec Executor, snapshot Snapshot, files []string) error {
	return restoreAPTFileSnapshot(exec, snapshot, files, true)
}

func restoreAPTFileSnapshot(
	exec Executor,
	snapshot Snapshot,
	files []string,
	runAPTUpdate bool,
) error {
	if !snapshot.Created || snapshot.Path == "" {
		return fmt.Errorf("cannot restore: no valid targeted APT snapshot is available")
	}

	targets := shellArray(files)
	postRestoreVerification := ""
	if runAPTUpdate {
		postRestoreVerification = `
apt-get update 2>&1 || true`
	}

	script := fmt.Sprintf(`
set -eu

SNAPSHOT_DIR=%s
TARGETS=(%s)

test -d "$SNAPSHOT_DIR/files"
test -f "$SNAPSHOT_DIR/manifest.txt"
test -f "$SNAPSHOT_DIR/checksums.sha256"

if ! (
	cd "$SNAPSHOT_DIR"
	sha256sum --strict -c checksums.sha256
); then
	echo "ROLLBACK_ERROR|snapshot_checksum_verification_failed"
	exit 30
fi

for target in "${TARGETS[@]}"; do
	relative="${target#/}"
	metadata="$SNAPSHOT_DIR/files/${relative}.meta"
	content="$SNAPSHOT_DIR/files/${relative}.content"

	if [ ! -f "$metadata" ]; then
		echo "ROLLBACK_ERROR|missing_snapshot_metadata|$target"
		exit 31
	fi

	state="$(sed -n '1p' "$metadata")"

	if [ "$state" = "present" ]; then
		mode="$(sed -n '2p' "$metadata")"
		if ! printf '%%s\n' "$mode" | grep -Eq '^[0-7]{3,4}$'; then
			echo "ROLLBACK_ERROR|invalid_snapshot_mode|$target|$mode"
			exit 34
		fi

		if [ ! -f "$content" ]; then
			echo "ROLLBACK_ERROR|missing_snapshot_content|$target"
			exit 33
		fi

		mkdir -p "$(dirname "$target")"
		cp -a "$content" "$target"
		chmod "$mode" "$target"
	elif [ "$state" = "absent" ]; then
		rm -f "$target"
	else
		echo "ROLLBACK_ERROR|invalid_snapshot_state|$target|$state"
		exit 32
	fi
done
%s
`,
		shellQuote(snapshot.Path),
		targets,
		postRestoreVerification,
	)

	_, err := exec.RunSudo(script)
	return err
}

func shellArray(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, shellQuote(value))
	}
	return strings.Join(quoted, " ")
}

func shellQuote(value string) string {
	return strconv.Quote(value)
}

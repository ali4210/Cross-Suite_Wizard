package repohealer

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func CreateAPTFileSnapshot(exec Executor, files []string) (Snapshot, error) {
	now := time.Now().UTC()
	id := "apt-" + now.Format("20060102T150405Z")
	path := "/var/lib/cross-suite/snapshots/" + id

	targets := shellArray(files)

	script := fmt.Sprintf(`
set -eu

SNAPSHOT_DIR=%s
TARGETS=(%s)

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
		shellQuote(path),
		targets,
		id,
		now.Format(time.RFC3339),
	)

	_, err := exec.RunSudo(script)
	if err != nil {
		return Snapshot{
			ID:        id,
			Path:      path,
			CreatedAt: now,
			Created:   false,
		}, err
	}

	return Snapshot{
		ID:        id,
		Path:      path,
		CreatedAt: now,
		Created:   true,
	}, nil
}

func RestoreAPTFileSnapshot(exec Executor, snapshot Snapshot, files []string) error {
	if !snapshot.Created || snapshot.Path == "" {
		return fmt.Errorf("cannot restore: no valid targeted APT snapshot is available")
	}

	targets := shellArray(files)

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

	state="$(cat "$metadata")"

	if [ "$state" = "present" ]; then
		if [ ! -f "$content" ]; then
			echo "ROLLBACK_ERROR|missing_snapshot_content|$target"
			exit 33
		fi

		mkdir -p "$(dirname "$target")"
		cp -a "$content" "$target"
	elif [ "$state" = "absent" ]; then
		rm -f "$target"
	else
		echo "ROLLBACK_ERROR|invalid_snapshot_state|$target|$state"
		exit 32
	fi
done

apt-get update 2>&1 || true
`,
		shellQuote(snapshot.Path),
		targets,
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

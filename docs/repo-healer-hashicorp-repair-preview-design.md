# HashiCorp APT repair preview and guarded apply design

## Status

Design only. This document does not authorize or implement a repair.

## Goal

Define a safe repair workflow for the allowlisted HashiCorp classic APT
repository when the read-only APT-list Doctor reports that the expected
pinned signing fingerprint is absent.

The workflow must never repair arbitrary repositories, trust arbitrary
keys, or write files before explicit operator approval.

## Supported profile

- Profile ID: `hashicorp`
- Repository URL: `https://apt.releases.hashicorp.com`
- Source file: `/etc/apt/sources.list.d/hashicorp.list`
- Keyring path: `/usr/share/keyrings/hashicorp-archive-keyring.gpg`
- Key URL: `https://apt.releases.hashicorp.com/gpg`
- Expected full signing fingerprint:
  `D55C0D1AC78A8D8126CB631CFC9CA96ACA026560`

## Preconditions

A repair preview may be created only when all conditions hold:

- The discovered action is blocked, not eligible, and does not require
  repair consent yet.
- The action uses classic APT `.list` source format.
- The action exactly matches the HashiCorp profile ID, repository URL,
  source-file path, and keyring path.
- The source and keyring are regular files, not symlinks.
- The source and keyring are owned by root and are not group- or
  world-writable.
- The read-only Doctor report is `blocked` specifically because the
  expected pinned fingerprint is absent.
- The target is Linux with APT and provides `gpg`.
- No APT/dpkg package-manager lock is active.

Any failed precondition must produce a blocked preview result and no
network request or filesystem write.

## Preview behavior

The preview is read-only and non-networking. It may inspect target files
and construct a deterministic local plan, but it must not download key
material or contact the vendor key URL. It must not change the target
source file, target keyring, APT configuration, packages, cache, locks,
snapshots, or audit log.

The preview must display:

- Profile ID and repository URL.
- Existing source-file metadata and SHA-256 hash.
- Existing keyring metadata and SHA-256 hash.
- Source line currently bound to the repository.
- Official pinned key URL.
- Full expected signing fingerprint.
- The requirement that apply download the official key URL and verify the
  exact full pinned fingerprint before any write.
- The keyring path, owner, and mode that apply would install.
- The fact that the final keyring SHA-256 hash and size are determined
  only after approved download and fingerprint validation.
- Whether the source file requires any rewrite.
- Exact planned writes, limited to the keyring and only if needed.
- Planned verification commands:
  - read-only Doctor re-run;
  - `apt-get update`.
- Planned rollback scope:
  - source file;
  - keyring file.

A preview must clearly state:

```text
PREVIEW ONLY: no system changes were made.
```

## Explicit approval

Applying a preview requires a fresh, explicit operator confirmation after
the complete preview is displayed.

Approval must bind to:

- Profile ID.
- Repository URL.
- Source-file path.
- Keyring path.
- Expected fingerprint.
- Existing source/keyring SHA-256 hashes.
- Proposed keyring SHA-256 hash.
- Preview creation timestamp or nonce.

If target metadata or hashes change after preview, approval becomes
invalid and a fresh Doctor plus preview is required.

## Apply safeguards

The apply workflow must:

1. Revalidate all preview preconditions.
2. Verify APT/dpkg is not locked.
3. Create a targeted snapshot of the source and keyring.
4. Download the key only over HTTPS with constrained protocol settings.
5. Verify the full pinned fingerprint before writing any target file.
6. Create a temporary keyring in a private directory.
7. Install the keyring atomically as root-owned mode `0644`.
8. Never follow symlinks for source, keyring, temporary, or snapshot
   paths.
9. Rewrite the source file only if the exact profile source binding is
   missing or incorrect and the approved preview explicitly includes it.
10. Re-run the Doctor and `apt-get update`.
11. Automatically restore the snapshot if download, fingerprint check,
    install, Doctor verification, or APT verification fails.
12. Return a result identifying one of:
    - repaired and verified;
    - failed and rolled back;
    - failed and rollback also failed;
    - refused before mutation.

## Audit requirements

After an apply attempt, record a structured redacted audit event that
includes:

- Action/profile ID.
- Approved target paths.
- Old and new SHA-256 hashes.
- Expected fingerprint.
- Consent binding/nonce.
- Apply outcome.
- Verification outcome.
- Rollback outcome.

Do not record private credentials, complete sensitive source contents,
or downloaded key material.

## Acceptance criteria

### Preview tests

- Valid blocked fixture produces a preview with no target mutation.
- Unknown URL, source path, keyring path, format, or fingerprint blocks
  preview with no network request or write.
- Symlink, unsafe owner, unsafe mode, missing tool, and active APT lock
  block preview.
- Preview performs no network request and no target write.
- Preview output is stable and redacts sensitive data.

### Apply tests

- Declined approval produces no mutation.
- Changed source/keyring hashes invalidate approval.
- Correct approval writes only the approved target file paths.
- Fingerprint mismatch writes nothing.
- Download or install failure restores the snapshot.
- Doctor or `apt-get update` verification failure restores the snapshot.
- Successful repair returns a ready Doctor report and successful APT
  verification.
- No action can repair a non-allowlisted repository.

### Live fixture evidence

- Use only the disposable blocked fixture snapshot.
- Capture before/after source and keyring hashes, metadata, and APT-list
  inventory.
- Test preview first.
- Test a declined approval.
- Test a successful repair only after all unit and integration tests pass.
- Restore the blocked snapshot after each mutation-path test.

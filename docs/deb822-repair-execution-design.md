# Deb822 APT Repair Execution Design

## Status

This document is a design and test-planning artifact only.

It does not enable Deb822 repair execution. Current Deb822 behavior remains inspection-only.

## Goal

Define a fail-closed execution path for a known-vendor, single-profile Deb822 APT source repair.

The path may repair only:

- One already-diagnosed and explicitly selected `.sources` file.
- One exact allowlisted vendor repository profile.
- One dedicated profile keyring path.
- One canonical Deb822 replacement rendered from verified target facts.

## Non-goals

This design does not permit:

- Repairing unknown repositories.
- Repairing multiple Deb822 stanzas in one source file.
- Rewriting a source file that contains unrelated repositories.
- Converting `.list` sources to `.sources`.
- Converting `.sources` files to `.list`.
- Repairing paths outside `/etc/apt/sources.list.d/`.
- Following symbolic links.
- Repairing a source file with unsafe ownership or permissions.
- Disabling APT signature, HTTPS, certificate, or Release-file verification.
- Importing keys from keyservers.
- Using unpinned signing keys.
- Logging raw source content, key content, or raw command output in audit records.

## Preconditions

A Deb822 execution request is eligible for consideration only when all conditions are true:

- The original diagnosis contains a known APT repair finding.
- The action ID, finding code, repository URL, source path, source line, source format, profile ID, and keyring path still match the diagnosis.
- The action source format is `apt-deb822`.
- The source file is a direct child of `/etc/apt/sources.list.d/`.
- The source file name ends with `.sources`.
- The file is root-owned, group-owned by root, a regular file, not a symbolic link, readable by root, no larger than the configured source-size limit, and not group/world writable.
- The source document contains exactly one non-comment Deb822 stanza.
- The source document URI equals the profile allowlist exactly.
- The source document `Signed-By` path equals the profile keyring path exactly.
- The source document does not contain duplicate fields, multi-value URIs, multi-value signed-by paths, or malformed field lines.
- The target facts can render a canonical Deb822 source for the profile.
- No APT or dpkg package-manager lock is active.

## Confirmation binding

Inspection is read-only and never authorizes a repair.

Execution requires a new explicit operator confirmation after displaying:

- Action ID.
- Vendor profile ID and display name.
- Approved source file path.
- Expected keyring path.
- Canonical rendered Deb822 replacement.
- Full pinned fingerprint list.
- Exact snapshot targets.
- Statement that `apt-get update` will run after replacement.
- Statement that a persistent targeted rollback will occur if execution or verification fails.

The confirmation must bind to an immutable execution request containing:

- Action ID.
- Finding code.
- Profile ID.
- Repository URL.
- Source file.
- Source format.
- Keyring path.
- Rendered Deb822 source.
- Snapshot target list.
- Target facts.
- Expected fingerprint list.

Any mismatch or refreshed diagnosis invalidates the confirmation and requires a new inspection and confirmation.

## Execution sequence

1. Rebuild or revalidate the selected action against the current diagnosis.
2. Resolve the action to its exact trusted vendor profile.
3. Perform a fresh read-only source-file inspection immediately before mutation.
4. Validate source file path, ownership, type, size, permissions, and symlink status.
5. Validate the raw Deb822 document against the trusted profile.
6. Render the canonical replacement Deb822 source using current target facts.
7. Check APT and dpkg lock state.
8. Create a unique persistent checksum-verified snapshot of only:
   - The approved `.sources` file.
   - The approved profile keyring file.
9. Download the key only from the profile key URL using HTTPS with the existing TLS restrictions.
10. Verify the downloaded key matches at least one full pinned fingerprint in the profile.
11. Dearmor the key into a temporary file.
12. Create a temporary replacement keyring in the keyring destination directory.
13. Create a temporary replacement `.sources` file in the approved source-file directory.
14. Validate both staged temporary files are non-empty and have root ownership with mode `0644`.
15. Atomically rename the staged keyring into the approved keyring path.
16. Atomically rename the staged Deb822 file into the approved source path.
17. Run `apt-get update`.
18. If mutation or verification fails, restore only the persistent snapshot targets using checksum verification.
19. Emit a sanitized audit event without raw source, key, or command output.

## Failure handling

The executor must fail closed.

- Failure before snapshot creation: no live file is changed.
- Snapshot creation failure: no repair script is run.
- Key download or fingerprint mismatch: no live file is changed.
- Temporary-file creation or validation failure: no live file is changed.
- Failure after one or both atomic renames: invoke persistent snapshot rollback.
- `apt-get update` failure: invoke persistent snapshot rollback.
- Snapshot checksum validation failure: do not restore; report rollback failure.
- Rollback failure: report the original failure and rollback failure together.

## Test plan

Before enabling execution, add tests for:

- A valid Docker Deb822 execution request reaches a staged execution payload.
- A valid VS Code Deb822 execution request reaches a staged execution payload.
- Blocked, unknown, stale, mismatched, or non-Deb822 actions execute zero commands.
- A changed source path, repository URL, profile ID, keyring path, source line, or source format invalidates execution binding.
- A source reader rejection executes no snapshot or mutation command.
- A multi-stanza source file executes no snapshot or mutation command.
- A malformed source document executes no snapshot or mutation command.
- An unsupported Docker target executes no snapshot or mutation command.
- An active APT/dpkg lock blocks before snapshot creation.
- A snapshot failure blocks before key download or source mutation.
- A fingerprint mismatch triggers persistent rollback only after a snapshot exists.
- The repair script stages both files in their destination directories.
- The script uses same-filesystem atomic renames for both targets.
- A repair-script failure triggers persistent rollback.
- An `apt-get update` failure triggers persistent rollback.
- Audit JSON does not contain raw source content, key content, fingerprint command output, or raw error output.
- The existing classic `.list` repair flow remains unchanged.
- The existing inspection-only UI never reaches this executor unless a new explicit Deb822 confirmation flow is introduced.

## Rollout gate

Do not enable `RepairAction.Eligible` for Deb822 actions until all execution-path tests pass, the new explicit confirmation binding exists, and the UI displays the exact rendered replacement before confirmation.

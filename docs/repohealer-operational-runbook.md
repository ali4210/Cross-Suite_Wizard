# Repo Healer Operational Runbook

## Purpose

Repo Healer repairs allowlisted APT repository trust configurations. It is designed to repair only known vendor profiles after explicit operator approval.

The engine supports classic APT `.list` sources and strictly validated single-stanza Deb822 `.sources` documents.

## Supported scope

Repo Healer supports only:

- Known, allowlisted APT vendor profiles.
- Exact approved repository URLs.
- Exact profile-bound signing-key URLs and pinned GPG fingerprints.
- Classic APT `.list` source repairs.
- One-stanza Deb822 `.sources` documents that pass strict validation.
- Targeted repair of the approved source file and approved keyring path.

Repo Healer rejects:

- Arbitrary repositories or arbitrary signing keys.
- Unrecognized vendor profiles.
- Repository URL extensions outside the exact allowlisted profile scope.
- Multi-stanza Deb822 source documents.
- Malformed Deb822 documents.
- Markdown-wrapped or non-HTTPS source URLs.
- Unapproved paths, nested source paths, and non-`.sources` Deb822 files.
- Unsafe source-file ownership, permissions, symlinks, invalid reader envelopes, or oversized source content.
- Requests that differ from the inspected action, profile, source path, keyring path, rendered replacement, snapshot scope, or pinned fingerprints.

## Required remote prerequisites

The managed Linux target must provide:

- SSH access for the operator.
- A working privileged-execution path through `sudo`.
- APT and `apt-get`.
- `curl`, `gpg`, `fuser`, `sha256sum`, `mktemp`, `install`, `cp`, `mv`, and standard POSIX/GNU shell utilities.
- Network access to the allowlisted vendor key URL over HTTPS.
- Permission to create targeted snapshots below `/var/lib/cross-suite/snapshots`.

## Deb822 execution flow

A Deb822 repair never executes directly from the planner action.

```text
Blocked planner action
→ safe source inspection
→ strict document validation
→ canonical replacement rendering
→ immutable execution request
→ fresh explicit yes/y approval
→ APT/dpkg lock check
→ targeted snapshot
→ key retrieval and fingerprint verification
→ atomic keyring and source replacement
→ apt-get update verification
→ checksum-verified rollback on failure
```

The planner action remains blocked and non-consent-bearing. It is an inspection entry point, not a direct mutation authorization.

## Operator procedure

1. Run Repo Healer diagnosis for the target.
2. Select the relevant known-vendor repair action.
3. For a Deb822 action, review the inspection output:
   - Action and profile.
   - Source file and keyring path.
   - Canonical replacement.
   - Exact two-file snapshot scope.
4. Confirm that the displayed repository and target configuration are expected.
5. Type only `yes` or `y` when prompted to approve the exact reviewed Deb822 repair.
6. Review the final result:
   - Applied successfully.
   - Declined.
   - Blocked before execution.
   - Failed with rollback completed.
   - Failed with rollback not completed.
7. Record the displayed audit metadata and snapshot location for operational follow-up.

## Rollback failure procedure

If the repair result reports rollback was not completed:

1. Stop further automated repository repairs for the affected target.
2. Preserve the snapshot path shown in the result.
3. Do not delete, modify, or recreate the snapshot directory.
4. Inspect the failure using a privileged operator session.
5. Verify the snapshot integrity before any manual restore:

   ```bash
   sudo sh -c '
   cd /var/lib/cross-suite/snapshots/<snapshot-id> &&
   sha256sum --strict -c checksums.sha256
   '
   ```

6. If checksums pass, restore only the affected source and keyring using the Repo Healer restore mechanism or an equivalent reviewed procedure.
7. Run:

   ```bash
   sudo apt-get update
   ```

8. If checksums fail, treat the snapshot as untrusted. Do not restore from it. Recover repository configuration from a separately verified source and investigate storage integrity.
9. Preserve relevant audit metadata, snapshot identifiers, and APT error summaries for incident review.

## Disposable-host release validation

Perform these tests on disposable targets before production rollout:

- Valid known-vendor Deb822 repair.
- Valid classic `.list` repair.
- APT/dpkg lock active before repair.
- Wrong `Signed-By` path.
- Wrong repository URL.
- Multi-stanza Deb822 source.
- Symlinked source file.
- Unsafe ownership or permissions.
- Missing source file.
- Key retrieval failure.
- Pinned fingerprint mismatch.
- Forced `apt-get update` verification failure.
- Snapshot checksum validation failure during restore.
- Explicit `yes` and `y` approval.
- All non-approval responses.

For each run, record the initial source/keyring state, final state, snapshot information, approval response, repair result, and `apt-get update` outcome.

## Release checklist

- [ ] `go test -count=1 ./pkg/repohealer` passes.
- [ ] `go test -count=1 ./pkg/playbook` passes.
- [ ] `go vet ./pkg/repohealer ./pkg/playbook` passes.
- [ ] `go test -count=1 -race ./pkg/repohealer` passes.
- [ ] `go test -count=1 -race ./pkg/playbook` passes.
- [ ] Focused GitHub Actions Repo Healer workflow passes.
- [ ] Disposable-host validation matrix is completed and recorded.
- [ ] Rollback-failure procedure is reviewed by an operator.
- [ ] Supported scope and limitations are communicated to users.
- [ ] The tag is created only after validation evidence is complete.

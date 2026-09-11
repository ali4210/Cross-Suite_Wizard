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

## Execution policy

Deb822 inspection remains available by default, but Deb822 mutation is disabled unless an operator explicitly enables it for an approved maintenance window.

Set the policy only in the process environment that launches Cross-Suite:

```bash
export CROSS_SUITE_DEB822_REPAIR_ENABLED=true
```

Any other value, including an unset value, blank value, `false`, `1`, or `yes`, keeps Deb822 execution disabled. When disabled, Repo Healer returns a visible blocked result and runs no privileged repair command, snapshot, or mutation.

Disable the policy after the maintenance window:

```bash
unset CROSS_SUITE_DEB822_REPAIR_ENABLED
```

## Execution audit

Repo Healer persists one redacted JSON Lines audit record for each completed Deb822 approval or execution outcome, including declined, blocked, applied, and failed results.

Configure the operator-local audit path with:

```bash
export CROSS_SUITE_DEB822_AUDIT_PATH="$HOME/.local/state/cross-suite/repohealer-deb822-audit.jsonl"
```

If the variable is unset or blank, Repo Healer uses:

```text
/var/log/cross-suite/repohealer-deb822-audit.jsonl
```

For interactive development and ordinary user sessions, prefer a user-local path. The default `/var/log/cross-suite/` path generally requires a privileged or specially configured service account.

On Unix, Repo Healer creates the audit directory with mode `0700` and creates the audit file with mode `0600`. The format is JSON Lines: one newline-terminated JSON object per completed decision or execution result.

Audit records include the timestamp, result status, action/profile identifiers, approved source and keyring paths, attempt/applied/rollback state, snapshot metadata, and a controlled failure category.

Audit records intentionally exclude raw command output, verification output, rendered source content, raw error or reason text, credentials, passwords, tokens, key material, and environment values.

If the audit record cannot be written, Repo Healer prints a warning. Audit persistence failure does not change the completed repair result or trigger additional target-host activity.

Inspect a user-local audit log with:

```bash
tail -n 20 "$CROSS_SUITE_DEB822_AUDIT_PATH"
jq . "$CROSS_SUITE_DEB822_AUDIT_PATH"
stat -c '%a %U:%G %n' "$CROSS_SUITE_DEB822_AUDIT_PATH"
```

## Doctor preflight

Before Repo Healer reads a selected Deb822 source or offers a preview, it runs a local Doctor preflight report for the selected action.

Doctor v1 is local-only and read-only. It does not connect to the target, invoke `sudo`, create snapshots, write source or keyring files, download keys, or run `apt-get update`.

A future remote Doctor probe may use the existing non-interactive labeled sudo transport only for a fixed read-only metadata script. Such a probe must not read source or keyring contents, create temporary files, create snapshots, modify files, download keys, or run `apt-get update`.

Doctor reports `READY`, `WARNING`, `BLOCKED`, or `UNSUPPORTED` and checks the selected action's source format, required binding fields, verified vendor profile, repository URL binding, keyring binding, approved Deb822 source-path scope, target-facts match, local execution-policy state, and local audit-path readiness.

`READY` and `WARNING` allow the tool to continue to remote Deb822 inspection and preview. `BLOCKED` and `UNSUPPORTED` stop before remote source inspection. `WARNING` may still prevent apply; for example, a disabled execution policy allows preview but not mutation.

## Preview and apply flow

Deb822 repair begins in preview mode. Preview validates the inspected source and the exact bound repair request, then displays the approved source file, keyring path, snapshot scope, pinned signing-key fingerprints, and rendered Deb822 replacement.

Preview mode does not invoke privileged commands, create a target snapshot, modify a source or keyring file, download a key, or run `apt-get update`. Preview remains available even when Deb822 repair execution policy is disabled.

After the preview, Repo Healer exits without changes unless the operator enters exactly `a` to proceed to apply confirmation. Values such as an empty response, `p`, `q`, `no`, `yes`, or `apply` exit after preview and do not reach the apply-confirmation prompt.

After entering `a`, the operator must still enter explicit approval (`yes` or `y`) for the displayed repair. Mutation remains disabled unless the local process environment also contains:

```bash
export CROSS_SUITE_DEB822_REPAIR_ENABLED=true
```

This produces three separate controls for a real repair:

1. A safe and bound inspection/request.
2. An explicit preview-to-apply selection followed by typed approval.
3. A local operator execution-policy opt-in.

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

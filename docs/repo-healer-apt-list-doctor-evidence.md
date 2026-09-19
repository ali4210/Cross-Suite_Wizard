# Repo Healer APT-list Doctor operational evidence

## Scope

This document records acceptance evidence for the read-only HashiCorp
classic APT `.list` Doctor.

The Doctor inspects only an already discovered, blocked, trusted
HashiCorp APT-list action. It does not repair repositories, import keys,
rewrite source files, refresh package indexes, create snapshots, append
audits, or change target configuration.

## Trust contract

The supported profile is:

- Profile ID: `hashicorp`
- Repository URL: `https://apt.releases.hashicorp.com`
- Source file: `/etc/apt/sources.list.d/hashicorp.list`
- Keyring path: `/usr/share/keyrings/hashicorp-archive-keyring.gpg`
- Expected full signing fingerprint:
  `D55C0D1AC78A8D8126CB631CFC9CA96ACA026560`

A missing-key finding is bound to a Doctor-only action only when all of
the following match:

- The source is classic APT `.list` format.
- The repository URL is the exact trusted HashiCorp URL.
- The source-file path is the exact profile path.
- The `signed-by` keyring path is the exact profile path.
- The APT `NO_PUBKEY` ID is 16 hexadecimal characters and matches the
  suffix of the pinned full fingerprint.
- Exactly one distinct trusted candidate matches.

The resulting action is blocked, non-consent-bearing, and contains no
repair commands, verification commands, rollback steps, or snapshot
targets.

## Exit-code contract

| Overall status | Exit code |
|---|---:|
| `ready` | 0 |
| `warning` | 10 |
| `blocked` | 20 |
| `unsupported` | 30 |
| `unknown` | 40 |

## Blocked fixture acceptance

Environment:

- Controller: Kali Linux.
- Target: disposable ParrotOS VM.
- Invocation: Hub 5 -> Universal Repository Healer -> mode 4.
- Test profile: HashiCorp classic APT-list repository.

Observed diagnostic evidence:

```text
NO_PUBKEY FC9CA96ACA026560
```

The trusted missing-key binding surfaced exactly one blocked Doctor
target:

```text
apt-keyring-repair-hashicorp
```

The Doctor reported:

```text
Overall: blocked
Remote HashiCorp APT-list Doctor exit code: 20
```

The source file and keyring were present, regular, root-owned, and
safely permissioned. The Doctor identified the expected signing
fingerprint as absent from the pinned keyring.

The blocked fixture’s verified hashes were:

```text
/etc/apt/sources.list.d/hashicorp.list
d55859d4e3e3b198904c1f896cf7a8a18228e077380839457d650502fc0fcd85

/usr/share/keyrings/hashicorp-archive-keyring.gpg
801d1c66a9076c9990fac4bcf90f649e273cb36c6a212981b145404fcdb57ad1
```

Before/after checks confirmed no source/keyring content, ownership,
mode, size, or timestamp changes, and no APT-list inventory changes.

## Input-safety acceptance

On the blocked fixture:

- Selecting `0` at the Doctor target prompt canceled safely.
- Selecting `99` was rejected as invalid.
- Both paths reported that no system changes were made.
- The same source/keyring hashes and APT-list inventory remained
  unchanged after the interaction tests.

## Ready-fixture preparation evidence

A snapshot-protected disposable ParrotOS fixture was manually prepared
with official vendor key material. This fixture preparation was not
performed by Repo Healer.

The downloaded HashiCorp key was inspected before installation and
contained the pinned full fingerprint:

```text
D55C0D1AC78A8D8126CB631CFC9CA96ACA026560
```

After fixture preparation:

- The keyring was root-owned and mode `0644`.
- `apt-get update` successfully fetched HashiCorp repository metadata
  and packages.
- No `NO_PUBKEY FC9CA96ACA026560` error was reported.

The ready fixture’s source/keyring hashes were:

```text
/etc/apt/sources.list.d/hashicorp.list
d55859d4e3e3b198904c1f896cf7a8a18228e077380839457d650502fc0fcd85

/usr/share/keyrings/hashicorp-archive-keyring.gpg
866ebcac7aa40ad5d862fa020665eb4769028d0f95a7657517aee2612e5ad7c5
```

## Current limitation

Hub 5 mode 4 intentionally accepts only a discovered blocked
HashiCorp APT-list Doctor action. Once the ready fixture passes
`apt-get update`, no blocked `NO_PUBKEY` action is generated and mode 4
does not offer a target.

This is expected safety behavior. The ready condition is currently
validated through direct keyring inspection and successful APT
repository refresh, not via the blocked-action interactive menu.

## Non-goals

The APT-list Doctor does not:

- Download or import signing keys.
- Rewrite APT source files.
- Run repair commands.
- Create snapshots or append audit records.
- Alter packages, locks, cache, or repository configuration.
- Accept arbitrary repositories or unpinned keys.

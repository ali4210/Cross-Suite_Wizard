# Repo Healer Operational Evidence

This directory records repeatable validation evidence for the Repo Healer engine.

For each test run, capture:

- Date and commit SHA.
- Controller OS and target OS/version/architecture.
- SSH user and privilege model; do not store passwords, keys, tokens, IP addresses, or private hostnames.
- Initial repository-source and keyring checksum baseline.
- Menu path and selected Doctor action.
- Doctor report and exit code.
- Final checksum baseline.
- Confirmation that Doctor mode created no source/keyring changes and no unexpected artifacts.
- Expected and actual outcome.
- Recovery or VM-snapshot reference when testing a repair path.

Do not store credentials, private addresses, tokens, or sensitive repository URLs.

# Security Policy

Please do not publish router credentials, subscription links, support session codes, logs or customer data in a public issue.

Report a vulnerability through the repository's private security-advisory form. Include only the minimum reproduction needed and replace real credentials, domains and user data with placeholders.

Supported security fixes currently target the newest preview release. Older preview builds may be replaced rather than patched in place.

The following values are expected to be public and are not credentials:

- the HTTPS support endpoint;
- the relay SSH hostname and port;
- the pinned SSH host-key fingerprint;
- package repository and release URLs.

Private keys, API tokens, router passwords, subscription tokens and live support revocation tokens must never be committed.

Every public release must pass the repository source-policy check, dependency audit, unit tests, packaged smoke test, SHA-256 generation, SBOM generation, and GitHub provenance attestation. Authenticode signing is applied only after a trusted signing provider approves the project; local self-signed builds are not official releases.

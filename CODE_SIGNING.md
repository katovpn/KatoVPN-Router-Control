# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).

KatoVPN Router Control is preparing an application for the SignPath Foundation open-source signing program. Until acceptance and workflow integration are complete, release notes explicitly identify binaries as unsigned. Self-signed certificates are not used for official releases.

## Roles

- Committers and reviewers: [KatoVPN organization members](https://github.com/orgs/katovpn/people)
- Signing approvers: [KatoVPN organization owners](https://github.com/orgs/katovpn/people?query=role%3Aowner)

All maintainers and signing approvers must use multi-factor authentication for GitHub and SignPath. Changes from non-committers require review. Every signing request requires explicit approval by a signing approver.

## Build and release rules

- Only artifacts built from a version tag in this public repository may be submitted for signing.
- The signing workflow may sign only `KatoVPN-Router-Control-v*.exe` produced by the repository release workflow.
- Windows CompanyName, ProductName, FileDescription, OriginalFilename, and product/file versions are fixed by the version-controlled metadata file.
- Release builds use pinned dependencies, run the source-policy scanner, dependency audit, unit tests, JavaScript/Python checks, and packaged smoke test.
- Each release publishes SHA-256, a CycloneDX SBOM, and GitHub provenance. Signing does not replace these checks.
- The SignPath private key remains in its managed HSM and is never available to project maintainers.
- A signed artifact is never modified after signing. A changed artifact requires a new build and signing approval.

## Privacy

See the [privacy policy](PRIVACY.md). The application has no telemetry. It connects only to the router and services described there as part of user-requested operations.

## Current status

Trusted Authenticode signing is **pending SignPath Foundation acceptance**. GitHub artifact attestations prove build origin but are not Authenticode signatures and do not guarantee immediate SmartScreen or antivirus reputation.

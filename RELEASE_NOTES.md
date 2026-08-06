# KatoVPN Router Control v0.4.3-preview

This is a portable Windows preview for compatible OpenWrt routers. Python and an installer are not required on the recipient computer.

Existing Wi-Fi networks now have one **Edit** action for the network name, optional new password, radio module, and RU/CN country code. Leaving the password empty keeps the current password, which is never read or returned by the application. The router arms a two-minute rollback before applying the change.

The release includes the executable, SHA-256 checksum, CycloneDX SBOM, and GitHub build-provenance attestations. Clean Nikki installation and full OpenWrt restore remain disabled until their representative-hardware pilot is complete.

## Signature status

This preview is not yet Authenticode-signed. The project is being prepared for the free SignPath Foundation open-source signing program. A GitHub attestation proves where the build came from but does not replace a Windows publisher signature or guarantee an immediate clean SmartScreen/VirusTotal reputation.

Verify the downloaded checksum and provenance before running the file.

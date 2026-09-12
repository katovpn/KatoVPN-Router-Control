# Changelog

## Unreleased — automatic KatoVPN setup

- Remove AdBlock management from Router Control (UI, package inspection, installer, and API); leave existing router-side packages and third-party DNS settings unchanged.

- Add one setup action for clean routers and manually installed Nikki, using a fresh assessment instead of treating any existing subscription as a managed KatoVPN configuration.
- Recognize nonstandard external network settings read-only and show a general compatibility warning; setup does not rewrite third-party services or OpenWrt network settings.
- Keep package updates separate, preserve configuration backups/rollback, and serialize router jobs across browser tabs.
- Add automatic setup state and UI regression coverage to the GitHub checks.
- Source candidate only: physical-router checks and release gates remain open; no new executable is included.

## v0.4.3-preview — 2026-08-06

- Added HTTPS fallbacks for router public-IP, location, and provider detection.
- Replaced the per-network password action with one guarded Wi-Fi editor for SSID, optional password, radio module, and RU/CN country code; leaving the password empty preserves the existing key without reading it.
- Corrected installed/current status handling for Nikki, Mihomo, and AdBlock.
- Renamed Firmware to Maintenance and moved temporary support above backups.
- Completed the representative-router support pilot, including external login, manual revoke, relay cleanup, and temporary router-key removal.
- Added a safe one-hour fallback for OpenWrt builds without the BusyBox `timeout` applet.
- Updated pinned dependencies and the PyInstaller bootloader.
- Added Windows product/version metadata, an explicit as-invoker manifest, and no-UPX builds.
- Added public-source policy checks, dependency audit, SHA-256, CycloneDX SBOM, and GitHub provenance release controls.

## v0.4.2-preview — 2026-08-06

- Initial public source preview.

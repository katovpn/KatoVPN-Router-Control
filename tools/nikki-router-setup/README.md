# KatoVPN Router Control

Local desktop-style control application for a KatoVPN OpenWrt router. The current release is `v0.4.3-preview` for Windows and is built as one self-contained executable.

## Current interface

- The welcome screen defaults to `192.168.11.1` and asks for router address, SSH port, username, and password.
- **Home** shows OpenWrt compatibility, public IP, country flag, location/provider, and VPN subscription state/expiry checked from the installed HTTPS link. A valid 200+ MiB router receives the readiness point even when 512 MiB is still recommended.
- **Internet** lists Wi-Fi access points with detected 2.4/5/6 GHz radio labels, can create an access point or edit its name, optional password, radio, and RU/CN country code, can change the private LAN IP, and can change the router administrator password with a two-minute router-side rollback.
- **Maintenance** presents Nikki, Mihomo, and optional AdBlock as installed modules, keeps the current subscription URL editable, provides the one-hour temporary KatoVPN support flow, and manages Nikki settings backups.
- **Logs** combines Nikki App Log, Mihomo Core Log, and matching OpenWrt events into one sanitized VPN journal; the selected line count applies to each source. A separate button creates a diagnostic report as `.txt`.
- An existing subscription URL can be replaced in place without package updates. If Nikki/Mihomo are absent, the validated URL is staged only in the current app session for the future clean-install flow.

The local UI binds only to `127.0.0.1` and protects its API with a random in-memory token. SSH credentials and staged subscription URLs exist only in process memory until logout or application exit. The installed subscription URL is shown only inside that authenticated loopback session so it can be edited; it is not written to the app log or local disk.

## Compatibility contract

Read-only dashboard access is allowed even when installation requirements fail. A fresh Nikki installation requires:

- OpenWrt/compatible build 24.10 or newer;
- `firewall4`, nftables, UCI, and `opkg` or `apk`;
- at least 200 MiB usable RAM reported by OpenWrt, with 512 MiB recommended;
- a writable overlay and enough free space for the selected packages before installation;
- working router DNS, clock, and HTTPS internet;
- an exact official Nikki package set for the release branch and architecture.

The dashboard does not present an OpenWrt partition size as the router's marketed flash capacity: NOR/NAND/eMMC/UBI layouts make that comparison unreliable. Install-only space checks are hidden after Nikki and Mihomo are present. The authoritative decision is the package-manager dry run immediately before installation or update.

The preferred install plan registers Nikki's signed official feed. If the router cannot reach it but the PC can, the fallback downloads exact official packages through the desktop connection and uploads them to `/tmp`. Both paths require a package-manager dry run and backup before changes. Blanket `opkg upgrade` and `apk upgrade` are forbidden.

## Enabled operations and safety boundary

The preview enables targeted Nikki/Mihomo updates, installed-profile configuration, Wi-Fi creation and full access-point editing, private LAN IP changes, router administrator password changes, optional AdBlock installation, Nikki backup create/restore/delete, and sanitized log export. An existing Wi-Fi password is preserved when the edit form leaves the password empty; the app never reads it from the router. Wi-Fi, LAN, and router-password mutations require a pinned SSH fingerprint and arm a two-minute rollback on the router before applying the change; success is confirmed only after the app reconnects and verifies the new values.

AdBlock is optional and is offered only to a 512-MB-class router (at least 448 MiB reported by OpenWrt). The app refreshes package metadata, verifies all three official packages (`adblock`, `luci-app-adblock`, `luci-i18n-adblock-ru`), performs a dry run, and installs only those packages. It never runs a blanket package upgrade.

Clean Nikki installation and full OpenWrt backup/restore remain disabled until a representative-router hardware pilot validates package recovery and reboot behavior. Wi-Fi/LAN rollback paths are implemented and unit-tested but must still receive their first wired live pilot before production distribution.

Temporary support is implemented fail-closed. The desktop creates an outbound reverse SSH tunnel that forwards only the connected router's SSH endpoint; it does not install NetBird/Tailscale or open Dropbear on WAN. A separate support public key is appended with an exact session marker and forced through a remaining-lease `timeout`, so an already-open shell cannot outlive the hour. Both a detached timer and a persistent OpenWrt cron cleanup remove that key after one hour, including after a router reboot. Manual stop, logout, and process exit close the tunnel, revoke the relay lease, and attempt immediate key removal.

The preview contains no relay secret. Its bundled `profile/support-relay.json` currently enables the public `https://router-support.katovpn.app/v1` broker with only a public HTTPS URL and pinned SSH host-key fingerprint. DNS-only A, free Let's Encrypt TLS, public lease create/revoke, an external operator connection, manual revoke, temporary-key removal, and zero-session cleanup were verified on 2026-08-06. Routers without a BusyBox `timeout` applet use a PID/start-time guarded one-hour cleanup fallback. Treat this KatoVPN-branded hostname as temporary and replace it with a separate neutral domain later.

A Nikki settings backup can restore UCI, profiles, subscriptions, and mixin data. It cannot reinstall or downgrade Nikki/Mihomo package binaries. Full firmware-image flashing is outside this application's scope.

## Run from source

```powershell
python tools/nikki-router-setup/app.py
```

## Build the Windows executable

```powershell
& tools/nikki-router-setup/build.ps1
```

The artifact is written to the ignored path:

`operations/tmp/nikki-router-setup/KatoVPN-Router-Control-v0.4.3-preview.exe`

Send the user only this `.exe`. Python, PowerShell modules, the source tree, and an adjacent asset folder are not required: PyInstaller embeds the Python runtime, web UI, profile template, and logo. The build is currently unsigned, so Windows SmartScreen may show an unknown-publisher warning.

The executable contains explicit Windows product/version metadata and is built without UPX. The public release workflow also publishes SHA-256, an SBOM, and GitHub build provenance. Authenticode signing remains pending acceptance into a trusted signing service; a self-signed certificate is intentionally not used because Windows treats it like an unsigned application.

The Windows executable cannot run on macOS. A future macOS `.app`/`.dmg` should be built from the same Python core and web UI on macOS.

## Process lifecycle

- The application keeps a private browser-session stream while a tab is open.
- Closing the last tab stops the local process after a four-second reload grace period.
- A page reload reconnects without starting a second process.
- If a router job is active, the process waits for it to reach a terminal result before exiting.
- If temporary support is active, logout, manual shutdown, or last-tab process exit closes the relay and removes the temporary key; the router timer remains the independent fallback.
- An abandoned launch exits after two minutes if no browser connects.

## Test

```powershell
python -m unittest discover -s tools/tests -p "test_*router*.py" -v
node --check tools/nikki-router-setup/web/app.js
```

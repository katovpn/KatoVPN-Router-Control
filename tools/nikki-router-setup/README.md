# KatoVPN Router Control

Local desktop-style control application for a KatoVPN OpenWrt router. The current release is `v0.4.3-preview` for Windows and is built as one self-contained executable.

Public download: `https://github.com/katovpn/KatoVPN-Router-Control/releases/tag/v0.4.3-preview`.

## Current interface

### Automatic setup source candidate (unreleased)

The primary subscription action is **Настроить**. It freshly checks the router,
installs a missing VPN module or brings an existing Nikki installation to the
KatoVPN configuration. A subscription URL alone is not proof that Nikki is
configured correctly. Proven managed setups use the separate subscription refresh
path without a package update. The assessment appears as generic setup status;
protocol and service details belong in diagnostics.

Active additional DNS/proxy services and nonstandard OpenWrt DNS settings produce
a compatibility warning. Detection is conservative and does not establish that
every additional service is a conflict, nor guarantee detection of arbitrary
custom scripts. Setup does not edit third-party service configuration, DHCP,
network or firewall UCI packages. Nikki settings are backed up before changes;
settings rollback does not undo package installation.

Individual router links use the exact `katorouter-ru` User-Agent for both desktop
validation and Nikki refresh. The selected country remains owned by the server's
device-link settings. A successful local setup verification does not by itself
prove end-to-end connectivity from every LAN client. Physical-router acceptance
and the existing release gates are still required before publishing this candidate.

### Existing control surfaces

- The welcome screen defaults to `192.168.11.1` and asks for router address, SSH port, username, and password.
- **Home** shows OpenWrt compatibility, public IP, country flag, location/provider, and VPN subscription state/expiry checked from the installed HTTPS link. A valid 200+ MiB router receives the readiness point even when 512 MiB is still recommended.
- **Internet** lists Wi-Fi access points with detected 2.4/5/6 GHz radio labels, can create an access point or edit its name, optional password, radio, and RU/CN country code, can change the private LAN IP, and can change the router administrator password with a two-minute router-side rollback.
- **Maintenance** presents Nikki and Mihomo as one VPN module, keeps package updates separate from automatic setup, keeps the current subscription URL editable, provides the one-hour temporary KatoVPN support flow, and manages Nikki settings backups.
- **Logs** combines Nikki App Log, Mihomo Core Log, and matching OpenWrt events into one sanitized VPN journal; the selected line count applies to each source. A separate button creates a diagnostic report as `.txt`.
- An existing managed subscription URL can be replaced in place without package updates. Manual or drifted Nikki settings are normalized by automatic setup after backup; a clean router uses the same setup action to install the module.

The local UI binds only to `127.0.0.1` and protects its API with a random in-memory token. SSH credentials and staged subscription URLs exist only in process memory until logout or application exit. The installed subscription URL is shown only inside that authenticated loopback session so it can be edited; it is not written to the app log or local disk.

## Compatibility contract

Read-only dashboard access is allowed even when installation requirements fail. A fresh Nikki installation requires:

- OpenWrt/compatible build 24.10 or newer;
- `firewall4`, nftables, UCI, and either OpenWrt package manager (`opkg` or `apk`);
- at least 200 MiB usable RAM reported by OpenWrt, with 512 MiB recommended;
- a writable overlay and enough free space for the selected packages before installation;
- working router DNS, clock, and HTTPS internet;
- an exact official Nikki package set for the release branch and architecture.

The dashboard does not present an OpenWrt partition size as the router's marketed flash capacity: NOR/NAND/eMMC/UBI layouts make that comparison unreliable. Linux reserves part of RAM for the kernel and hardware, so the UI maps usable `MemTotal` to the standard physical class (for example, 478 MiB is shown as 512 MiB and 228 MiB as 256 MiB) while retaining the usable value for diagnostics and safety checks. Install-only space checks are hidden after Nikki and Mihomo are present. The authoritative decision is the package-manager dry run immediately before installation or update.

The clean-install action reads the exact compatible versions from Nikki's official HTTPS index and follows the package manager shipped by the router. On `opkg`, it downloads the exact `mihomo-meta`, `nikki`, and `luci-app-nikki` IPKs and runs one complete `opkg --noaction` transaction with explicit prerequisites. On `apk`, it uses Nikki's official `packages.adb` repository with `--no-cache` and runs `apk add --simulate` before the matching install transaction. The no-cache flag is required for one-shot external repositories on apk-tools 3.x; without it apk may look only for a cached copy of the supplied index and falsely report all Nikki packages as missing. Both paths verify the installed versions and runtime files before importing and verifying the KatoVPN profile. Runtime DNS verification supports `ss`, BusyBox `netstat`, and `/proc/net/udp*` because a valid minimal OpenWrt image may not ship the `ss` utility. Blanket `opkg upgrade` and `apk upgrade` are forbidden.

## Enabled operations and safety boundary

The source pilot enables clean VPN-module installation, a unified targeted Nikki/Mihomo update action, installed-profile configuration, Wi-Fi creation and full access-point editing, private LAN IP changes, router administrator password changes, Nikki backup create/restore/delete, and sanitized log export. An existing Wi-Fi password is preserved when the edit form leaves the password empty; the app never reads it from the router. Wi-Fi, LAN, and router-password mutations require a pinned SSH fingerprint and arm a two-minute rollback on the router before applying the change; success is confirmed only after the app reconnects and verifies the new values.

Router Control does not manage AdBlock. Existing router-side ad blocking and third-party DNS services are left unchanged; network compatibility warnings remain available.

Clean VPN-module installation is enabled in the source build for the representative-router pilot. Full OpenWrt backup/restore remains disabled until reboot and recovery behavior is validated. Package installation is not rolled back by a settings backup; if packages install but profile verification fails, the UI reports that distinction and leaves the verified packages available for a retry.

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

The GitHub-built `v0.4.3-preview` executable has SHA-256 `89347c315f27b7beeef44830a6572c5c937985a794e63f88984af1db6b20d90c`; verify the adjacent checksum and GitHub attestations rather than relying on a copied filename.

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
node --test tools/tests/test_setup_ui.js
```

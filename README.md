# KatoVPN Router Control

Portable Windows utility for inspecting and configuring a compatible OpenWrt router through SSH. The interface runs only on the local computer and opens in the default browser.

Current version: **v0.4.3-preview**.

Current preview capabilities:

- read-only OpenWrt, internet, Wi-Fi, Nikki, Mihomo and subscription diagnostics;
- guarded Nikki/Mihomo updates and KatoVPN profile installation;
- Wi-Fi creation plus full SSID/optional-password/radio/country editing, LAN IP changes, and router-password changes with timed rollback;
- Nikki backup management and sanitized VPN log export;
- optional one-hour support tunnel with independent router/server expiry and explicit manual disconnect.

## Download

Preview builds are published on the [GitHub Releases](https://github.com/katovpn/KatoVPN-Router-Control/releases) page with a SHA-256 checksum, CycloneDX SBOM, and GitHub build-provenance attestation. Verify an attestation with:

```powershell
gh attestation verify .\KatoVPN-Router-Control-v0.4.3-preview.exe -R katovpn/KatoVPN-Router-Control
```

The current preview is not yet Authenticode-signed. Do not treat GitHub provenance as a Windows publisher signature. The repository is prepared for a SignPath Foundation application as documented in [CODE_SIGNING.md](CODE_SIGNING.md); a self-signed certificate is intentionally not used because Windows treats it like an unsigned binary.

## Safety

- Router credentials and subscription URLs are kept in process memory and are not written to disk or application logs.
- Existing Wi-Fi passwords are never read; an empty password in the editor preserves the current key.
- The local API binds only to `127.0.0.1` and uses a random in-memory session token.
- The repository contains no infrastructure inventory, private keys, API tokens or customer data.
- The support endpoint and SSH host-key fingerprint in `profile/support-relay.json` are public connection metadata, not secrets.
- Clean Nikki installation and full OpenWrt restore remain preview-gated.
- The representative-router support pilot passed external operator login, manual disconnect, relay cleanup, and temporary-key removal.

## Run from source

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r tools\nikki-router-setup\requirements.txt
.\.venv\Scripts\python.exe tools\nikki-router-setup\app.py
```

## Tests

```powershell
python -m unittest discover -s tools\tests -p "test_*router*.py" -v
node --check tools\nikki-router-setup\web\app.js
```

## Portable build

```powershell
& tools\nikki-router-setup\build.ps1
```

The build produces one portable `.exe`; Python is not required on the recipient's computer. The executable includes Windows product/version metadata and is built without UPX. Public release builds run in GitHub Actions from a version tag.

## Privacy and code signing

- [Privacy policy](PRIVACY.md)
- [Security policy](SECURITY.md)
- [Code signing policy](CODE_SIGNING.md)
- [MIT license](LICENSE)

More implementation details are in [tools/nikki-router-setup/README.md](tools/nikki-router-setup/README.md).

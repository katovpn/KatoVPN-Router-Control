# KatoVPN Router Control

Portable Windows utility for inspecting and configuring a compatible OpenWrt router through SSH. The interface runs only on the local computer and opens in the default browser.

Current preview capabilities:

- read-only OpenWrt, internet, Wi-Fi, Nikki, Mihomo and subscription diagnostics;
- guarded Nikki/Mihomo updates and KatoVPN profile installation;
- Wi-Fi, LAN IP and router-password changes with timed rollback;
- Nikki backup management and sanitized VPN log export;
- optional one-hour support tunnel with independent router/server expiry.

## Safety

- Router credentials and subscription URLs are kept in process memory and are not written to disk or application logs.
- The local API binds only to `127.0.0.1` and uses a random in-memory session token.
- The repository contains no infrastructure inventory, private keys, API tokens or customer data.
- The support endpoint and SSH host-key fingerprint in `profile/support-relay.json` are public connection metadata, not secrets.
- Clean Nikki installation, full OpenWrt restore and the final representative-router support pilot remain preview-gated.

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

The build produces one portable `.exe`; Python is not required on the recipient's computer. Public binary releases are intentionally kept separate from source validation until the signing and release-integrity workflow is complete.

More implementation details are in [tools/nikki-router-setup/README.md](tools/nikki-router-setup/README.md).

# Privacy policy

KatoVPN Router Control does not include telemetry, advertising identifiers, analytics, or background data collection.

## Data kept locally

- Router address, SSH username/password, temporary support credentials, and a staged subscription URL are held only in application memory.
- The local interface binds to `127.0.0.1` and requires a random in-memory token.
- Closing the application, logging out, or closing the final browser tab clears the local session. Router-side backups explicitly created by the user remain on the router.
- Exported diagnostic files are created locally. The application sanitizes secret-like values, but users should still review a file before sharing it.

## Network connections

Connections occur only as part of functionality requested by the person operating the application:

- SSH to the router address entered by the user;
- HTTPS requests needed to check router internet/public-IP information and official OpenWrt, Nikki, Mihomo, or subscription resources;
- links opened by the user to KatoVPN support or account pages;
- when **Allow connection** is pressed, a one-hour support lease at the public KatoVPN relay and an outbound SSH tunnel that forwards only the selected router SSH endpoint.

Public-IP providers receive the router's public source IP and standard HTTPS request metadata. Subscription providers receive the request needed to validate the URL supplied or already configured by the user. The support relay receives lease/tunnel metadata, but not the router password or subscription URL.

No router access is opened on WAN. Temporary support uses a separate public key and independent expiry; manual disconnect, application exit, or lease expiry closes the tunnel and removes the temporary key.

## Public metadata

The bundled support URL and pinned SSH host-key fingerprint are public connection metadata. They are not credentials. Private relay implementation, infrastructure inventory, customer data, passwords, subscription tokens, and private keys are not part of this repository or application package.

Questions: [@katovpn_help](https://t.me/katovpn_help)

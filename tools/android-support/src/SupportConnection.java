package app.katovpn.support;

import android.os.SystemClock;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import com.jcraft.jsch.*;
import java.io.*;
import java.net.URL;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONObject;

final class SupportConnection {
    interface Consent { boolean confirm(String fingerprint) throws InterruptedException; }

    final String host, user;
    final int port;
    private final String api, relayPin;
    private final BooleanSupplier cancelled;
    private final SocketFactory forwardSockets;
    private final JSch routerSsh = new JSch();
    private final JSch relaySsh = new JSch();
    private final AtomicReference<Network> lanNetwork = new AtomicReference<>();
    private Session router, relay;
    private RelayEndpoint relayEndpoint;
    private String leaseId, revokeToken, cleanup, routerPin;
    private boolean leaseRequestUnconfirmed;
    private volatile boolean forwardReady;
    volatile long deadline;

    SupportConnection(String host, int port, String user, JSONObject config, Network wifi,
                      BooleanSupplier cancelled) throws Exception {
        if (!SupportPolicy.isLocalIpv4(host) || port < 1 || port > 65535 || !user.matches("[A-Za-z0-9_.-]{1,32}"))
            throw new IOException("Проверьте локальный IP, порт и логин роутера.");
        this.host = host;
        this.port = port;
        this.user = user;
        lanNetwork.set(wifi);
        this.cancelled = cancelled;
        forwardSockets = lanSockets(true);
        api = config.getString("api_url");
        relayPin = config.getString("relay_host_key_sha256");
        if (!api.startsWith("https://") || !relayPin.matches("SHA256:[A-Za-z0-9+/]{43}"))
            throw new IOException("Неверная конфигурация сервера поддержки.");
        JSch.setConfig("signature.ed25519", "com.jcraft.jsch.bc.SignatureEd25519");
    }

    void login(byte[] password, Consent consent) throws Exception {
        router = routerSsh.getSession(user, host, port);
        router.setSocketFactory(lanSockets(false));
        pin(router, fingerprint -> {
            if (!consent.confirm(fingerprint)) return false;
            routerPin = fingerprint;
            return true;
        });
        router.setConfig("PreferredAuthentications", "password");
        try {
            router.setPassword(password);
            router.connect(10000);
        } catch (JSchException e) {
            String message = String.valueOf(e.getMessage());
            if (message.contains("HostKey") || message.contains("hostkey")) {
                throw new IOException("SSH-ключ не подтверждён или изменился. Проверьте, что телефон подключён к нужному роутеру.");
            }
            if (message.startsWith("Auth")) throw new IOException("Роутер не принял логин или пароль SSH.");
            throw new IOException("Не удалось установить SSH-соединение. Проверьте адрес и порт роутера.");
        } finally {
            Arrays.fill(password, (byte) 0);
            router.setPassword((byte[]) null);
        }
        router.setServerAliveInterval(15000);
        router.setServerAliveCountMax(2);
    }

    String start() throws Exception {
        checkCancelled();
        long routerTime = Long.parseLong(run("set -e; [ \"$(id -u)\" = 0 ]; [ -d /etc/dropbear ]; "
            + "[ -x /etc/init.d/cron ]; ls /etc/rc.d/S*cron >/dev/null; command -v timeout >/dev/null; date +%s").trim());
        if (Math.abs(routerTime - now()) > 300) throw new IOException("Часы телефона и роутера расходятся.");

        KeyPair key = KeyPair.genKeyPair(relaySsh, KeyPair.RSA, 3072);
        try {
            ByteArrayOutputStream privateKey = new ByteArrayOutputStream();
            key.writePrivateKey(privateKey);
            byte[] raw = privateKey.toByteArray();
            try { relaySsh.addIdentity("temporary-support", raw, null, null); }
            finally { Arrays.fill(raw, (byte) 0); privateKey.reset(); }
            String publicKey = keyLine("ssh-rsa", key.getPublicKeyBlob());
            leaseRequestUnconfirmed = true;
            JSONObject lease = request("POST", "/support/sessions", new JSONObject()
                .put("client_public_key", publicKey).put("duration_seconds", 3600), null);
            String id = match(lease, "session_id", "[A-Za-z0-9_-]{8,64}");
            String token = match(lease, "revoke_token", "[A-Za-z0-9._~-]{24,256}");
            leaseId = id;
            revokeToken = token;
            leaseRequestUnconfirmed = false;
            checkCancelled();
            long expiry = lease.getLong("expires_at");
            long phone = now();
            if (expiry < phone + 60 || expiry > phone + 3720) throw new IOException("Неверный срок доступа.");
            long routerNow = Long.parseLong(run("date +%s").trim());
            long stopAt = Math.min(expiry, Math.min(phone, routerNow) + 3600);
            if (!SupportPolicy.validExpiry(phone, routerNow, stopAt)) throw new IOException("Не удалось согласовать таймер доступа.");
            deadline = SystemClock.elapsedRealtime() + (stopAt - phone) * 1000;
            String supportKey = supportKey(lease.getString("support_public_key"));
            relayEndpoint = new RelayEndpoint(lease);
            String code = match(lease, "code", "[A-Z0-9-]{6,32}");
            String address = match(lease, "support_server", "[A-Za-z0-9.-]{1,253}");
            int supportPort = port(lease, "support_port");
            try { relay = connectRelay(deadline); }
            catch (JSchException e) { throw new IOException("Не удалось открыть SSH-соединение с сервером поддержки."); }
            checkCancelled();
            installKey(id, stopAt, supportKey);
            checkCancelled();
            if (SystemClock.elapsedRealtime() >= deadline) throw new IOException("Срок доступа истёк.");
            try { openForward(relay); }
            catch (JSchException e) { throw new IOException("Сервер поддержки не открыл порт туннеля."); }
            checkCancelled();
            if (SystemClock.elapsedRealtime() >= deadline) throw new IOException("Срок доступа истёк.");
            forwardReady = true;
            return "Код: " + code + "\nСервер: " + address + "\nПорт: " + supportPort + "\nЛогин роутера: " + user;
        } finally {
            key.dispose();
        }
    }

    boolean loggedIn() { return router != null && router.isConnected(); }

    boolean networkLost(Network network) {
        Network selected = lanNetwork.get();
        return network.equals(selected) && lanNetwork.compareAndSet(selected, null);
    }

    boolean active() {
        return relay != null && relay.isConnected() && routerReachable(deadline);
    }

    boolean restore(ConnectivityManager networks, long limit) {
        if (!allowed(limit)) return false;
        forwardReady = false;
        lanNetwork.set(null);
        for (Network candidate : networks.getAllNetworks()) {
            if (!allowed(limit)) return false;
            if (isWifi(networks, candidate) && matchesRouter(candidate, limit)
                && isWifi(networks, candidate) && allowed(limit)) {
                lanNetwork.set(candidate);
                break;
            }
        }
        if (lanNetwork.get() == null || !allowed(limit)) return false;
        if (relay != null && relay.isConnected()) {
            forwardReady = true;
            return true;
        }
        if (relay != null) relay.disconnect();
        relay = null;
        Session replacement = null;
        try {
            replacement = connectRelay(limit);
            if (!allowed(limit) || lanNetwork.get() == null) return false;
            openForward(replacement);
            if (!allowed(limit) || lanNetwork.get() == null) return false;
            relay = replacement;
            forwardReady = true;
            return true;
        } catch (JSchException | IOException e) {
            return false;
        } finally {
            if (replacement != null && relay != replacement) replacement.disconnect();
        }
    }

    private static boolean isWifi(ConnectivityManager networks, Network network) {
        NetworkCapabilities capabilities = networks.getNetworkCapabilities(network);
        return capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
    }

    private boolean routerReachable(long limit) {
        Network selected = lanNetwork.get();
        if (selected == null || SystemClock.elapsedRealtime() >= limit) return false;
        try (Socket ignored = connectSocket(selected, host, port, timeout(limit, 1000))) {
            return selected == lanNetwork.get();
        } catch (IOException e) {
            lanNetwork.compareAndSet(selected, null);
            return false;
        }
    }

    private boolean matchesRouter(Network network, long limit) {
        Session probe = null;
        boolean[] matched = {false};
        try {
            probe = new JSch().getSession(user, host, port);
            probe.setSocketFactory(new SocketFactory() {
                public Socket createSocket(String address, int sshPort) throws IOException {
                    return connectSocket(network, address, sshPort, timeout(limit, 2500));
                }
                public InputStream getInputStream(Socket socket) throws IOException { return socket.getInputStream(); }
                public OutputStream getOutputStream(Socket socket) throws IOException { return socket.getOutputStream(); }
            });
            pin(probe, fingerprint -> {
                matched[0] = fingerprint.equals(routerPin);
                return false; // Stop the handshake after verifying possession of the pinned key.
            });
            probe.connect(timeout(limit, 2500));
        } catch (JSchException | IOException ignored) {
            // Host-key rejection is expected because this probe never authenticates.
        } finally {
            if (probe != null) probe.disconnect();
        }
        return matched[0];
    }

    private SocketFactory lanSockets(boolean forwarding) {
        return new SocketFactory() {
            public Socket createSocket(String address, int sshPort) throws IOException {
                Network selected = lanNetwork.get();
                if (selected == null || (forwarding && (!forwardReady || !allowed(deadline))))
                    throw new IOException("Временный доступ недоступен.");
                int connectTimeout = forwarding ? timeout(deadline, 8000) : 8000;
                Socket socket = connectSocket(selected, address, sshPort, connectTimeout);
                if (selected != lanNetwork.get() || (forwarding && (!forwardReady || !allowed(deadline)))) {
                    socket.close();
                    throw new IOException("Временный доступ недоступен.");
                }
                return socket;
            }
            public InputStream getInputStream(Socket socket) throws IOException { return socket.getInputStream(); }
            public OutputStream getOutputStream(Socket socket) throws IOException { return socket.getOutputStream(); }
        };
    }

    private static Socket connectSocket(Network network, String host, int port, int timeout) throws IOException {
        Socket socket = network.getSocketFactory().createSocket();
        try {
            socket.connect(new InetSocketAddress(host, port), timeout);
            return socket;
        } catch (IOException e) {
            socket.close();
            throw e;
        }
    }

    private Session connectRelay(long limit) throws JSchException, IOException {
        Session session = relaySsh.getSession(relayEndpoint.user, relayEndpoint.host, relayEndpoint.port);
        pin(session, relayPin::equals);
        session.setConfig("PreferredAuthentications", "publickey");
        try {
            session.connect(timeout(limit, 10000));
            session.setServerAliveInterval(10000);
            session.setServerAliveCountMax(2);
            return session;
        } catch (JSchException | IOException e) {
            session.disconnect();
            throw e;
        }
    }

    private void openForward(Session session) throws JSchException {
        session.setPortForwardingR(relayEndpoint.bind, relayEndpoint.bindPort, host, port, forwardSockets);
    }

    private static int timeout(long limit, int maximum) throws IOException {
        long remaining = limit - SystemClock.elapsedRealtime();
        if (remaining <= 0) throw new IOException("Срок доступа истёк.");
        return (int) Math.min(maximum, remaining);
    }

    private boolean allowed(long limit) {
        return !cancelled.getAsBoolean() && SystemClock.elapsedRealtime() < limit;
    }

    private static final class RelayEndpoint {
        final String user, host, bind;
        final int port, bindPort;

        RelayEndpoint(JSONObject lease) throws Exception {
            user = match(lease, "relay_username", "[A-Za-z0-9_.-]{1,32}");
            host = match(lease, "relay_host", "[A-Za-z0-9.-]{1,253}");
            port = port(lease, "relay_port");
            bind = lease.getString("bind_host");
            if (!SupportPolicy.isLoopbackIpv4(bind)) throw new IOException("Сервер запросил небезопасный адрес туннеля.");
            bindPort = port(lease, "bind_port");
        }
    }

    private void checkCancelled() throws IOException {
        if (cancelled.getAsBoolean()) throw new IOException("Доступ отменён.");
    }

    boolean close() {
        try { return closeAccess(); }
        finally { if (router != null) router.disconnect(); }
    }

    boolean closeAccess() {
        forwardReady = false;
        boolean clean = !leaseRequestUnconfirmed;
        if (relay != null) {
            relay.disconnect();
            relay = null;
        }
        try { relaySsh.removeAllIdentity(); }
        catch (JSchException e) { clean = false; }
        relayEndpoint = null;
        if (revokeToken != null) {
            try { request("DELETE", "/support/sessions/" + leaseId, null, revokeToken); }
            catch (Exception e) { clean = false; }
            revokeToken = null;
        }
        if (cleanup != null) {
            try { run(cleanup); } catch (Exception e) { clean = false; }
            cleanup = null;
        }
        deadline = 0;
        return clean;
    }

    private void installKey(String id, long expires, String key) throws Exception {
        String dir = "/root/katovpn-support/" + id;
        String marker = "KatoVPN-Support-" + id;
        String auth = "/etc/dropbear/authorized_keys";
        String cron = "/etc/crontabs/root";
        String removeEntries = "sed -i '\\| " + marker + "$|d' " + auth + " " + cron + "\n";
        String lock = "lock=/tmp/katovpn-android-support.lock\n"
            + "tries=0\nuntil mkdir \"$lock\" 2>/dev/null; do\n"
            + "tries=$((tries + 1)); [ \"$tries\" -lt 5 ] || exit 1; sleep 1\ndone\n"
            + "trap 'rmdir \"$lock\"' EXIT\ntrap 'exit 1' HUP INT TERM\n";
        String removal = "set -e\n" + lock + removeEntries + "chmod 600 " + auth + "\n/etc/init.d/cron restart >/dev/null\n"
            + "rm -f " + dir + "/session.sh " + dir + "/cleanup.sh\nrmdir " + dir + "\n";
        cleanup = "set -e; if [ -x " + dir + "/cleanup.sh ]; then " + dir + "/cleanup.sh --force; fi";
        run("set -eu\numask 077\n" + lock + "mkdir -p /root/katovpn-support\nmkdir " + dir + "\n"
            + "touch " + auth + " " + cron + "\nchmod 600 " + auth + "\n"
            + "cat > " + dir + "/cleanup.sh <<'KATO_CLEANUP'\n#!/bin/sh\n"
            + "if [ \"${1:-}\" != --force ]; then [ \"$(date +%s)\" -ge " + expires + " ] || exit 0; fi\n"
            + removal + "KATO_CLEANUP\n"
            + "cat > " + dir + "/session.sh <<'KATO_SESSION'\n#!/bin/sh\n"
            + "set -eu\nremaining=$((" + expires + " - $(date +%s)))\n"
            + "[ \"$remaining\" -gt 0 ] && [ \"$remaining\" -le 3600 ] || exit 124\n"
            + "if [ -n \"${SSH_ORIGINAL_COMMAND:-}\" ]; then exec timeout -s KILL \"$remaining\" /bin/ash -c \"$SSH_ORIGINAL_COMMAND\"; fi\n"
            + "exec timeout -s KILL \"$remaining\" /bin/ash -l\nKATO_SESSION\n"
            + "chmod 700 " + dir + "/session.sh " + dir + "/cleanup.sh\n"
            + "printf '\\n%s\\n' '* * * * * " + dir + "/cleanup.sh # " + marker + "' >> " + cron + "\n"
            + "/etc/init.d/cron restart >/dev/null\n"
            + "printf '\\n%s\\n' 'command=\"" + dir + "/session.sh\",no-agent-forwarding,no-X11-forwarding,no-port-forwarding "
            + key + " " + marker + "' >> " + auth + "\n"
            + "[ \"$(grep -F -c ' " + marker + "' " + auth + ")\" = 1 ]\n");
    }

    private String run(String command) throws Exception {
        ChannelExec channel = (ChannelExec) router.openChannel("exec");
        try {
            channel.setCommand(command);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            try (InputStream input = channel.getInputStream()) {
                channel.connect(8000);
                long limit = SystemClock.elapsedRealtime() + 12000;
                while (!channel.isClosed() || input.available() > 0) {
                    if (SystemClock.elapsedRealtime() >= limit) throw new IOException("Роутер не ответил вовремя.");
                    if (input.available() > 0) {
                        output.write(input.read());
                        if (output.size() > 1024) throw new IOException("Неожиданный ответ роутера.");
                    } else Thread.sleep(25);
                }
                if (channel.getExitStatus() != 0) throw new IOException("Роутер не подтвердил операцию. Проверьте root, Dropbear, cron и timeout.");
                return new String(output.toByteArray(), StandardCharsets.UTF_8);
            }
        } finally { channel.disconnect(); }
    }

    private JSONObject request(String method, String path, JSONObject body, String token) throws Exception {
        HttpsURLConnection connection = (HttpsURLConnection) new URL(api + path).openConnection();
        try {
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.setRequestMethod(method);
            connection.setRequestProperty("User-Agent", "KatoVPN-Router-Control/0.4");
            if (token != null) connection.setRequestProperty("Authorization", "Bearer " + token);
            if (body != null) {
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/json");
                try (OutputStream output = connection.getOutputStream()) { output.write(body.toString().getBytes(StandardCharsets.UTF_8)); }
            }
            int status = connection.getResponseCode();
            if (body != null && (status == 400 || status == 401 || status == 403 || status == 429))
                leaseRequestUnconfirmed = false;
            if (token != null && (status == 200 || status == 202 || status == 204 || status == 404 || status == 410)) return null;
            if (body == null || status != 200 && status != 201) throw new IOException("Сервер поддержки ответил HTTP " + status + ".");
            try (InputStream input = connection.getInputStream()) {
                byte[] raw = new byte[8193];
                int count = 0, n;
                while (count < raw.length && (n = input.read(raw, count, raw.length - count)) > 0) count += n;
                if (count == raw.length) throw new IOException("Слишком большой ответ сервера.");
                return new JSONObject(new String(raw, 0, count, StandardCharsets.UTF_8));
            }
        } finally { connection.disconnect(); }
    }

    private static void pin(Session session, Consent check) {
        session.setConfig("StrictHostKeyChecking", "yes");
        session.setHostKeyRepository(new HostKeyRepository() {
            public int check(String host, byte[] key) {
                try {
                    byte[] hash = MessageDigest.getInstance("SHA-256").digest(key);
                    return check.confirm("SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(hash)) ? OK : CHANGED;
                } catch (Exception e) { return CHANGED; }
            }
            public void add(HostKey host, UserInfo info) {}
            public void remove(String host, String type) {}
            public void remove(String host, String type, byte[] key) {}
            public String getKnownHostsRepositoryID() { return "support-session"; }
            public HostKey[] getHostKey() { return new HostKey[0]; }
            public HostKey[] getHostKey(String host, String type) { return getHostKey(); }
        });
    }

    private static String supportKey(String value) throws Exception {
        if (value.length() > 4096 || value.contains("\n") || value.contains("\r")) throw new IOException("Неверный ключ поддержки.");
        String[] parts = value.trim().split("[ \\t]+", 3);
        if (parts.length < 2 || !parts[0].matches("ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256")
            || !parts[1].matches("[A-Za-z0-9+/]+={0,2}")) throw new IOException("Неверный ключ поддержки.");
        byte[] blob = Base64.getDecoder().decode(parts[1]);
        if (blob.length < 32) throw new IOException("Неверный ключ поддержки.");
        return keyLine(parts[0], blob);
    }

    private static String keyLine(String type, byte[] blob) {
        return type + " " + Base64.getEncoder().encodeToString(blob);
    }

    private static String match(JSONObject object, String name, String pattern) throws Exception {
        String value = object.getString(name);
        if (!value.matches(pattern)) throw new IOException("Неверный ответ сервера поддержки.");
        return value;
    }

    private static int port(JSONObject object, String name) throws Exception {
        int value = object.getInt(name);
        if (value < 1 || value > 65535) throw new IOException("Неверный порт сервера поддержки.");
        return value;
    }

    private static long now() { return System.currentTimeMillis() / 1000; }
}

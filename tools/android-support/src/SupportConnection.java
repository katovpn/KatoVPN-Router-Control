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
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import java.util.function.Supplier;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONObject;

final class SupportConnection {
    interface Consent { boolean confirm(String fingerprint) throws InterruptedException; }
    static final class UserError extends IOException {
        UserError(String message) { super(message); }
    }

    final String host, user;
    final int port;
    private final String api, relayPin;
    private final BooleanSupplier cancelled;
    private final ConnectivityManager networks;
    private final SocketFactory forwardSockets;
    private final SupportRouterTransport routerTransport;
    private final JSch relaySsh = new JSch();
    private final AtomicReference<Network> lanNetwork = new AtomicReference<>();
    private Session router, relay;
    private Network routerNetwork;
    private RelayEndpoint relayEndpoint;
    private SupportRouterLease routerLease;
    private String leaseId, revokeToken;
    private long nextStateCheck;
    private boolean leaseRequestUnconfirmed;
    private volatile Network forwardNetwork;
    volatile long deadline;

    SupportConnection(String host, int port, String user, JSONObject config, Network wifi,
                      ConnectivityManager networks, BooleanSupplier cancelled) throws Exception {
        if (!SupportPolicy.isLocalIpv4(host) || port < 1 || port > 65535 || !user.matches("[A-Za-z0-9_.-]{1,32}"))
            throw new UserError("Проверьте локальный IP, порт и логин роутера.");
        this.host = host;
        this.port = port;
        this.user = user;
        this.networks = networks;
        lanNetwork.set(wifi);
        this.cancelled = cancelled;
        routerTransport = new SupportRouterTransport(host, port, user);
        forwardSockets = lanSockets(() -> forwardNetwork, this::forwardAllowed, () -> deadline, 8000);
        api = config.getString("api_url");
        relayPin = config.getString("relay_host_key_sha256");
        if (!api.startsWith("https://") || !relayPin.matches("SHA256:[A-Za-z0-9+/]{43}"))
            throw new UserError("Неверная конфигурация сервера поддержки.");
        JSch.setConfig("signature.ed25519", "com.jcraft.jsch.bc.SignatureEd25519");
    }

    void login(byte[] password, Consent consent) throws Exception {
        Network selected = lanNetwork.get();
        long socketLimit = SystemClock.elapsedRealtime() + 10000;
        BooleanSupplier permitted = () -> selectedWifi(selected) && !cancelled.getAsBoolean();
        try {
            router = routerTransport.login(password, routerSockets(selected, socketLimit, permitted), permitted, 10000, consent::confirm);
            routerNetwork = selected;
        } catch (JSchException e) {
            String message = String.valueOf(e.getMessage());
            if (message.contains("HostKey") || message.contains("hostkey")) {
                throw new UserError("SSH-ключ не подтверждён или изменился. Проверьте, что телефон подключён к нужному роутеру.");
            }
            if (message.startsWith("Auth")) throw new UserError("Роутер не принял логин или пароль SSH.");
            throw new UserError("Не удалось установить SSH-соединение. Проверьте адрес и порт роутера.");
        }
    }

    String start() throws Exception {
        checkCancelled();
        Network selected = lanNetwork.get();
        BooleanSupplier permitted = () -> selectedWifi(selected) && !cancelled.getAsBoolean();
        long routerTime = Long.parseLong(run(router, "set -e; [ \"$(id -u)\" = 0 ]; [ -d /etc/dropbear ]; "
            + "[ -x /etc/init.d/cron ]; ls /etc/rc.d/S*cron >/dev/null; command -v timeout >/dev/null; date +%s",
            SystemClock.elapsedRealtime() + 12000, permitted).trim());
        if (Math.abs(routerTime - now()) > 300) throw new UserError("Часы телефона и роутера расходятся.");

        KeyPair key = KeyPair.genKeyPair(relaySsh, KeyPair.RSA, 3072);
        try {
            ByteArrayOutputStream privateKey = new ByteArrayOutputStream();
            key.writePrivateKey(privateKey);
            byte[] raw = privateKey.toByteArray();
            try { relaySsh.addIdentity("temporary-support", raw, null, null); }
            finally { Arrays.fill(raw, (byte) 0); privateKey.reset(); }
            String publicKey = keyLine("ssh-rsa", key.getPublicKeyBlob());
            checkCancelled();
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
            // Capture both clocks before the router round-trip; its latency must
            // not be added to the original relay/key expiration deadline.
            long phoneElapsed = SystemClock.elapsedRealtime();
            long phoneMillis = System.currentTimeMillis();
            long phone = phoneMillis / 1000;
            if (expiry < phone + 60 || expiry > phone + 3720) throw new UserError("Неверный срок доступа.");
            long routerNow = Long.parseLong(run(router, "date +%s", SystemClock.elapsedRealtime() + 12000, permitted).trim());
            long stopAt = Math.min(expiry, Math.min(phone, routerNow) + 3600);
            if (!SupportPolicy.validExpiry(phone, routerNow, stopAt)) throw new UserError("Не удалось согласовать таймер доступа.");
            deadline = SupportPolicy.deadlineAt(phoneElapsed, phoneMillis, stopAt);
            String supportKey = supportKey(lease.getString("support_public_key"));
            relayEndpoint = new RelayEndpoint(lease);
            String code = match(lease, "code", "[A-Z0-9-]{6,32}");
            String address = match(lease, "support_server", "[A-Za-z0-9.-]{1,253}");
            int supportPort = port(lease, "support_port");
            try { relay = connectRelay(deadline); }
            catch (JSchException e) { throw new UserError("Не удалось открыть SSH-соединение с сервером поддержки."); }
            routerLease = new SupportRouterLease(id, stopAt, supportKey);
            validateLease(selected, deadline);
            try { openForward(relay); }
            catch (JSchException e) { throw new UserError("Сервер поддержки не открыл порт туннеля."); }
            if (!currentRouter(selected) || !allowed(deadline)) throw new UserError("Временный доступ завершён или роутер недоступен.");
            forwardNetwork = selected;
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
        Network selected = lanNetwork.get();
        if (!currentRouter(selected) || !routerBanner(selected, deadline)) {
            forwardNetwork = null;
            // Keep any authenticated transport for best-effort cleanup if the user is stopping.
            if (allowed(deadline)) disconnectRouter();
            return false;
        }
        if (relay == null || !relay.isConnected()) {
            forwardNetwork = null;
            return false;
        }
        if (!forwardAllowed(selected) || SystemClock.elapsedRealtime() >= nextStateCheck) {
            forwardNetwork = null;
            try {
                // A periodic read-only check detects silent loss of router-side state.
                BooleanSupplier permitted = () -> currentRouter(selected) && allowed(deadline);
                if (!run(router, routerLease.inspectCommand(), deadline, permitted).trim().equals("present")
                    || !permitted.getAsBoolean()) return false;
                nextStateCheck = SystemClock.elapsedRealtime() + 30000;
                forwardNetwork = selected;
            } catch (Exception ignored) { return false; }
        }
        return forwardAllowed(selected);
    }

    boolean restore(long limit) {
        forwardNetwork = null;
        if (!allowed(limit)) return false;
        Network selected = lanNetwork.get();
        if (selectedWifi(selected)) return restoreOn(selected, limit);
        if (selected != null) lanNetwork.compareAndSet(selected, null);
        // Android assigns a new Network to Wi-Fi after a real link loss. Test each
        // candidate on its bound socket, but retain only a proven, pinned router route.
        for (Network candidate : networks.getAllNetworks()) {
            if (!allowed(limit)) return false;
            if (!isWifi(candidate) || !lanNetwork.compareAndSet(null, candidate)) continue;
            if (restoreOn(candidate, limit)) return true;
            if (currentRouter(candidate)) return false; // Same router, but lease/relay not ready yet.
            lanNetwork.compareAndSet(candidate, null);
        }
        return false;
    }

    private boolean restoreOn(Network selected, long limit) {
        Session replacement = null;
        try {
            BooleanSupplier permitted = () -> selectedWifi(selected) && allowed(limit);
            if (!permitted.getAsBoolean()) return false;
            if (!currentRouter(selected)) {
                disconnectRouter();
                if (!routerBanner(selected, limit)) return false;
                router = routerTransport.reconnect(routerSockets(selected, limit, permitted), permitted, timeout(limit, 5000));
                routerNetwork = selected;
            }
            validateLease(selected, limit);
            if (relay == null || !relay.isConnected()) {
                if (relay != null) relay.disconnect();
                relay = null;
                replacement = connectRelay(limit);
                if (!permitted.getAsBoolean() || !currentRouter(selected)) return false;
                openForward(replacement);
                if (!permitted.getAsBoolean() || !currentRouter(selected)) return false;
                relay = replacement;
            }
            if (!permitted.getAsBoolean() || !currentRouter(selected)) return false;
            forwardNetwork = selected;
            return forwardAllowed(selected);
        } catch (Exception ignored) {
            return false;
        } finally {
            if (replacement != null && relay != replacement) replacement.disconnect();
        }
    }

    private void validateLease(Network selected, long limit) throws Exception {
        BooleanSupplier permitted = () -> currentRouter(selected) && allowed(limit);
        Session authenticated = router;
        routerLease.ensure(command -> run(authenticated, command, limit, permitted), permitted);
        nextStateCheck = SystemClock.elapsedRealtime() + 30000;
    }

    private boolean isWifi(Network network) {
        if (network == null) return false;
        NetworkCapabilities capabilities = networks.getNetworkCapabilities(network);
        return capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
    }

    private boolean selectedWifi(Network network) {
        return network != null && network.equals(lanNetwork.get()) && isWifi(network);
    }

    private boolean currentRouter(Network selected) {
        return selectedWifi(selected) && selected.equals(routerNetwork) && router != null && router.isConnected();
    }

    private boolean routerBanner(Network selected, long limit) {
        if (!selectedWifi(selected) || !allowed(limit)) return false;
        long probeLimit = Math.min(limit, SystemClock.elapsedRealtime() + 1200);
        try (Socket socket = connectSocket(selected, host, port, timeout(probeLimit, 1000))) {
            return SupportRouterTransport.hasSshBanner(socket, () -> probeLimit - SystemClock.elapsedRealtime())
                && selectedWifi(selected) && allowed(limit);
        } catch (IOException ignored) {
            return false;
        }
    }

    private boolean forwardAllowed(Network network) {
        return network != null && network.equals(forwardNetwork) && selectedWifi(network) && allowed(deadline);
    }

    private SocketFactory routerSockets(Network selected, long limit, BooleanSupplier permitted) {
        return lanSockets(() -> selected, network -> permitted.getAsBoolean(), () -> limit, 5000);
    }

    private SocketFactory lanSockets(Supplier<Network> route, Predicate<Network> permitted, LongSupplier limit, int maxTimeout) {
        return new SocketFactory() {
            public Socket createSocket(String address, int sshPort) throws IOException {
                Network selected = route.get();
                if (!host.equals(address) || port != sshPort || !permitted.test(selected))
                    throw new UserError("Временный доступ недоступен.");
                Socket socket = connectSocket(selected, address, sshPort, timeout(limit.getAsLong(), maxTimeout));
                if (!permitted.test(selected)) {
                    socket.close();
                    throw new UserError("Временный доступ недоступен.");
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
        if (!allowed(limit)) throw new UserError("Временный доступ завершён.");
        Session session = relaySsh.getSession(relayEndpoint.user, relayEndpoint.host, relayEndpoint.port);
        SupportRouterTransport.pin(session, fingerprint -> allowed(limit) && relayPin.equals(fingerprint));
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
        if (remaining <= 0) throw new UserError("Срок доступа истёк.");
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
            if (!SupportPolicy.isLoopbackIpv4(bind)) throw new UserError("Сервер запросил небезопасный адрес туннеля.");
            bindPort = port(lease, "bind_port");
        }
    }

    private void checkCancelled() throws IOException {
        if (cancelled.getAsBoolean()) throw new UserError("Доступ отменён.");
    }

    boolean close() {
        routerTransport.close();
        try { return closeAccess(); }
        finally { disconnectRouter(); }
    }

    private void disconnectRouter() {
        if (router != null) router.disconnect();
        router = null;
        routerNetwork = null;
    }

    boolean closeAccess() {
        forwardNetwork = null;
        boolean clean = !leaseRequestUnconfirmed;
        if (relay != null) {
            relay.disconnect();
            relay = null;
        }
        try { relaySsh.removeAllIdentity(); }
        catch (JSchException e) { clean = false; }
        relayEndpoint = null;
        if (routerLease != null) {
            Network selected = routerNetwork;
            try {
                // No new password authentication after stop/expiry. An already
                // authenticated session may still remove this exact lease.
                run(router, routerLease.removeCommand(), SystemClock.elapsedRealtime() + 12000,
                    () -> currentRouter(selected));
            } catch (Exception e) { clean = false; }
            routerLease = null;
        }
        if (revokeToken != null) {
            try { request("DELETE", "/support/sessions/" + leaseId, null, revokeToken); }
            catch (Exception e) { clean = false; }
            revokeToken = null;
        }
        deadline = 0;
        return clean;
    }

    private String run(Session session, String command, long limit, BooleanSupplier permitted) throws Exception {
        long commandLimit = Math.min(limit, SystemClock.elapsedRealtime() + 12000);
        try {
            return SupportRouterTransport.run(session, command, SystemClock::elapsedRealtime, commandLimit, permitted);
        } catch (SupportRouterTransport.CommandFailure e) {
            throw new UserError(e.getMessage());
        }
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
            if (body == null || status != 200 && status != 201) throw new UserError("Сервер поддержки ответил HTTP " + status + ".");
            try (InputStream input = connection.getInputStream()) {
                byte[] raw = new byte[8193];
                int count = 0, n;
                while (count < raw.length && (n = input.read(raw, count, raw.length - count)) > 0) count += n;
                if (count == raw.length) throw new UserError("Слишком большой ответ сервера.");
                return new JSONObject(new String(raw, 0, count, StandardCharsets.UTF_8));
            }
        } finally { connection.disconnect(); }
    }

    private static String supportKey(String value) throws Exception {
        if (value.length() > 4096 || value.contains("\n") || value.contains("\r")) throw new UserError("Неверный ключ поддержки.");
        String[] parts = value.trim().split("[ \\t]+", 3);
        if (parts.length < 2 || !parts[0].matches("ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256")
            || !parts[1].matches("[A-Za-z0-9+/]+={0,2}")) throw new UserError("Неверный ключ поддержки.");
        byte[] blob = Base64.getDecoder().decode(parts[1]);
        if (blob.length < 32) throw new UserError("Неверный ключ поддержки.");
        return keyLine(parts[0], blob);
    }

    private static String keyLine(String type, byte[] blob) {
        return type + " " + Base64.getEncoder().encodeToString(blob);
    }

    private static String match(JSONObject object, String name, String pattern) throws Exception {
        String value = object.getString(name);
        if (!value.matches(pattern)) throw new UserError("Неверный ответ сервера поддержки.");
        return value;
    }

    private static int port(JSONObject object, String name) throws Exception {
        int value = object.getInt(name);
        if (value < 1 || value > 65535) throw new UserError("Неверный порт сервера поддержки.");
        return value;
    }

    private static long now() { return System.currentTimeMillis() / 1000; }
}

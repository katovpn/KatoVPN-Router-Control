package app.katovpn.support;

import com.jcraft.jsch.*;
import java.io.IOException;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;
import java.util.stream.Collectors;

final class SupportRouterTransport implements AutoCloseable {
    interface Consent { boolean confirm(String fingerprint) throws Exception; }
    static final class CommandFailure extends IOException {
        CommandFailure(String message) { super(message); }
    }

    private final JSch ssh = new JSch();
    private final String host, user;
    private final int port;
    private byte[] password;
    private String fingerprint;

    SupportRouterTransport(String host, int port, String user) {
        this.host = host;
        this.port = port;
        this.user = user;
    }

    Session login(byte[] supplied, SocketFactory sockets, BooleanSupplier allowed, int timeout, Consent consent)
        throws IOException, JSchException {
        close();
        try { password = supplied.clone(); }
        finally { Arrays.fill(supplied, (byte) 0); }
        try { return authenticate(sockets, allowed, timeout, consent); }
        catch (IOException | JSchException | RuntimeException e) {
            close();
            throw e;
        }
    }

    Session reconnect(SocketFactory sockets, BooleanSupplier allowed, int timeout) throws IOException, JSchException {
        if (fingerprint == null || password == null) throw new IOException("No live router login");
        return authenticate(sockets, allowed, timeout, fingerprint::equals);
    }

    private Session authenticate(SocketFactory sockets, BooleanSupplier allowed, int timeout, Consent consent)
        throws IOException, JSchException {
        if (!allowed.getAsBoolean()) throw new IOException("Router network no longer selected");
        Session session = ssh.getSession(user, host, port);
        session.setSocketFactory(sockets);
        session.setConfig("PreferredAuthentications", "password");
        session.setConfig("MaxAuthTries", "1");
        AtomicReference<String> matched = new AtomicReference<>();
        pin(session, value -> {
            if (!allowed.getAsBoolean()) return false;
            String accepted = matched.get();
            if (accepted != null) return accepted.equals(value);
            if (!consent.confirm(value) || !allowed.getAsBoolean()) return false;
            // JSch verifies possession of the host key before this check, then authenticates.
            // It copies these bytes and zeroes its copy in Session.connect()'s finally block.
            session.setPassword(password);
            matched.set(value);
            return true;
        });
        boolean connected = false;
        try {
            session.connect(timeout);
            if (matched.get() == null || !allowed.getAsBoolean()) throw new IOException("Router network no longer selected");
            session.setServerAliveInterval(15000);
            session.setServerAliveCountMax(2);
            fingerprint = matched.get();
            connected = true;
            return session;
        } finally {
            if (!connected) session.disconnect();
        }
    }

    static boolean hasSshBanner(Socket socket, LongSupplier remaining) {
        try {
            InputStream input = new BufferedInputStream(socket.getInputStream(), 256);
            byte[] line = new byte[255];
            int size = 0;
            for (int lines = 0; lines < 4;) {
                long millis = remaining.getAsLong();
                if (millis <= 0) return false;
                socket.setSoTimeout((int) Math.min(Integer.MAX_VALUE, millis));
                int next = input.read();
                if (next < 0) return false;
                if (next == '\n') {
                    int length = size > 0 && line[size - 1] == '\r' ? size - 1 : size;
                    String value = new String(line, 0, length, StandardCharsets.US_ASCII);
                    if (value.startsWith("SSH-")) return value.matches("SSH-(?:2\\.0|1\\.99)-[!-~]+(?: [ -~]*)?");
                    size = 0;
                    lines++;
                } else {
                    if (size == line.length) return false;
                    line[size++] = (byte) next;
                }
            }
        } catch (IOException ignored) { }
        return false;
    }

    static String run(Session session, String command, LongSupplier clock, long limit, BooleanSupplier permitted)
        throws IOException, JSchException, InterruptedException {
        requireAllowed(clock, limit, permitted);
        byte[] script = (command + "\n").getBytes(StandardCharsets.UTF_8);
        byte[] commit = "# KATO_SCRIPT_END\n".getBytes(StandardCharsets.US_ASCII);
        if (script.length + commit.length > 16384) throw new CommandFailure("Слишком большая команда роутера.");
        ChannelExec channel = (ChannelExec) session.openChannel("exec");
        try {
            // Dropbear limits exec request length. It must buffer and verify the
            // complete stdin program before executing even its first statement.
            channel.setCommand("LC_ALL=C; export LC_ALL; script=$(cat) || exit 125; "
                + "[ \"${#script}\" -eq " + (script.length + commit.length - 1) + " ] || exit 125; "
                + "case \"$script\" in *'# KATO_SCRIPT_END') eval \"$script\";; *) exit 125;; esac");
            try (InputStream input = channel.getInputStream()) {
                requireAllowed(clock, limit, permitted);
                channel.connect((int) Math.max(1, Math.min(8000, limit - clock.getAsLong())));
                try (OutputStream output = channel.getOutputStream()) {
                    requireAllowed(clock, limit, permitted);
                    output.write(script);
                    output.flush();
                    requireAllowed(clock, limit, permitted);
                    output.write(commit);
                }
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                while (!channel.isClosed() || input.available() > 0) {
                    requireAllowed(clock, limit, permitted);
                    if (input.available() > 0) {
                        output.write(input.read());
                        if (output.size() > 1024) throw new CommandFailure("Неожиданный ответ роутера.");
                    } else Thread.sleep(25);
                }
                requireAllowed(clock, limit, permitted);
                if (channel.getExitStatus() != 0) throw new CommandFailure("Роутер не подтвердил операцию. Проверьте root, Dropbear, cron и timeout.");
                return new String(output.toByteArray(), StandardCharsets.UTF_8);
            }
        } finally { channel.disconnect(); }
    }

    private static void requireAllowed(LongSupplier clock, long limit, BooleanSupplier permitted) throws IOException {
        if (clock.getAsLong() >= limit) throw new CommandFailure("Роутер не ответил вовремя.");
        if (!permitted.getAsBoolean()) throw new CommandFailure("Роутер недоступен.");
    }

    static void pin(Session session, Consent check) {
        session.setConfig("StrictHostKeyChecking", "yes");
        // This application pins raw host keys, not host certificates or certificate authorities.
        session.setConfig("server_host_key", Arrays.stream(session.getConfig("server_host_key").split(","))
            .filter(name -> !name.contains("-cert-")).collect(Collectors.joining(",")));
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

    @Override public void close() {
        if (password != null) Arrays.fill(password, (byte) 0);
        password = null;
        fingerprint = null;
    }
}

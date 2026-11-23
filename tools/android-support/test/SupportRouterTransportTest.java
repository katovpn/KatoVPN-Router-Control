package app.katovpn.support;

import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

public final class SupportRouterTransportTest {
    public static void main(String[] args) throws Exception {
        bannerHealth();
        if (args.length == 2) pinnedAuthentication(args[0], args[1]);
        System.out.println("Support router transport tests passed" + (args.length == 2 ? " (including SSH handshake)" : ""));
    }

    private static void bannerHealth() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
             Socket client = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
             Socket server = listener.accept()) {
            check(!SupportRouterTransport.hasSshBanner(client, () -> 25),
                "TCP accept without SSH banner must not mark router healthy");
        }
        check(!banner("HTTP/1.1 200 OK\r\n"), "non-SSH service is not healthy");
        check(!banner("SSH-2.0-\r\n"), "malformed SSH identification is not healthy");
        check(banner("router notice\r\nSSH-2.0-dropbear\r\n"), "valid Dropbear banner after prelude is healthy");
    }

    private static boolean banner(String identifier) throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
             Socket client = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
             Socket server = listener.accept()) {
            server.getOutputStream().write(identifier.getBytes(StandardCharsets.US_ASCII));
            server.shutdownOutput();
            long limit = System.nanoTime() / 1_000_000 + 1000;
            return SupportRouterTransport.hasSshBanner(client, () -> limit - System.nanoTime() / 1_000_000);
        }
    }

    private static void pinnedAuthentication(String python, String fixture) throws Exception {
        ProcessBuilder fixtureProcess = new ProcessBuilder(python, fixture).redirectError(ProcessBuilder.Redirect.INHERIT);
        fixtureProcess.environment().remove("KATO_ANDROID_SIGN_PASSWORD");
        Process process = fixtureProcess.start();
        try (BufferedReader events = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.US_ASCII));
             SupportRouterTransport transport = new SupportRouterTransport("192.168.1.1", 22, "root")) {
            String[] ports = events.readLine().split(" ");
            SocketFactory original = sockets(Integer.parseInt(ports[0]));
            SocketFactory changed = sockets(Integer.parseInt(ports[1]));
            AtomicInteger consents = new AtomicInteger();
            byte[] supplied = "in-memory-fixture".getBytes(StandardCharsets.US_ASCII);
            Session login = transport.login(supplied, original, () -> true, 5000, fingerprint -> {
                consents.incrementAndGet();
                return fingerprint.startsWith("SHA256:");
            });
            long limit = System.nanoTime() / 1_000_000 + 8000;
            String maxKey = "ssh-ed25519 " + "A".repeat(4084);
            SupportRouterLease maxLease = new SupportRouterLease("a".repeat(64), Instant.now().getEpochSecond() + 1200, maxKey, ".");
            check(SupportRouterTransport.run(login, maxLease.installCommand(), SupportRouterTransportTest::clock, limit, () -> true).equals("present\n"),
                "lease with the longest accepted key and ID must install over SSH");
            AtomicInteger checkpoints = new AtomicInteger();
            try {
                SupportRouterTransport.run(login, "touch authorized_keys crontab session.sh", SupportRouterTransportTest::clock, limit,
                    () -> checkpoints.incrementAndGet() <= 3);
                throw new AssertionError("cancelled command was reported as accepted");
            } catch (IOException expected) { }
            login.disconnect();
            check(Arrays.equals(supplied, new byte[supplied.length]), "login zeroes supplied bytes after cloning");
            try {
                transport.reconnect(original, () -> false, 5000);
                throw new AssertionError("unselected route was accepted");
            } catch (IOException expected) { }
            try {
                transport.reconnect(changed, () -> true, 5000);
                throw new AssertionError("changed host key was accepted");
            } catch (JSchException expected) { }
            Session recovered = transport.reconnect(original, () -> true, 5000);
            check(recovered.isConnected(), "original pin authenticates from retained bytes");
            recovered.disconnect();
            check(consents.get() == 1, "reconnect cannot ask to trust a different identity");
            check(events.readLine().equals("auth:2,0 scripts:present writes:0"),
                "changed host must receive no password and truncated stream must not execute");
            check(process.waitFor() == 0, "SSH fixture exited successfully");
            transport.close();
            try {
                transport.reconnect(original, () -> true, 5000);
                throw new AssertionError("closed credential can still reconnect");
            } catch (IOException expected) { }
        } finally {
            process.destroyForcibly();
        }
    }

    private static SocketFactory sockets(int fixturePort) {
        return new SocketFactory() {
            public Socket createSocket(String host, int port) throws IOException {
                return new Socket(InetAddress.getByName("127.0.0.1"), fixturePort);
            }
            public InputStream getInputStream(Socket socket) throws IOException { return socket.getInputStream(); }
            public OutputStream getOutputStream(Socket socket) throws IOException { return socket.getOutputStream(); }
        };
    }

    private static long clock() { return System.nanoTime() / 1_000_000; }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

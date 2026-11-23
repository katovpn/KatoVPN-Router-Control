package app.katovpn.support;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public final class SupportRouterLeaseTest {
    private static final String ID = "test-lease_123";
    private static final String KEY = "ssh-ed25519 " + Base64.getEncoder().encodeToString(new byte[48]);
    private static final String MARKER = "KatoVPN-Support-" + ID;

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("kato-android-lease-");
        try {
            commandBoundaries();
            if (args.length > 0) shellState(args[0], root);
            System.out.println("Support router lease tests passed" + (args.length > 0 ? " (including shell)" : ""));
        } finally {
            try (var paths = Files.walk(root)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toArray(Path[]::new))
                    Files.deleteIfExists(path);
            }
        }
    }

    private static void commandBoundaries() throws Exception {
        SupportRouterLease lease = new SupportRouterLease(ID, 100000, KEY);
        List<String> commands = new ArrayList<>();
        lease.ensure(command -> { commands.add(command); return "present\n"; }, () -> true);
        check(commands.size() == 1, "intact state must not dispatch a write");

        commands.clear();
        lease.ensure(command -> {
            commands.add(command);
            return commands.size() == 1 ? "missing\n" : "present\n";
        }, () -> true);
        check(commands.size() == 2, "missing state must dispatch a repair");

        commands.clear();
        boolean[] allowed = {true};
        try {
            lease.ensure(command -> {
                commands.add(command);
                allowed[0] = false;
                return "missing\n";
            }, () -> allowed[0]);
            throw new AssertionError("a lease revoked mid-inspection was accepted");
        } catch (IOException expected) {
            check(commands.size() == 1, "no repair may be sent after a cancelled or expired inspection");
        }
    }

    private static void shellState(String shell, Path root) throws Exception {
        Files.createDirectories(root.resolve("etc/dropbear"));
        Files.createDirectories(root.resolve("etc/crontabs"));
        Files.createDirectories(root.resolve("etc/init.d"));
        Files.createDirectories(root.resolve("etc/rc.d"));
        Files.createDirectories(root.resolve("tmp"));
        Files.createDirectories(root.resolve("bin"));
        Path auth = root.resolve("etc/dropbear/authorized_keys");
        Path cron = root.resolve("etc/crontabs/root");
        String otherKey = KEY + " KatoVPN-Support-test-lease_1234";
        String otherCron = "* * * * * /other/cleanup.sh # KatoVPN-Support-test-lease_1234";
        Files.writeString(auth, otherKey + "\n");
        Files.writeString(cron, otherCron + "\n");
        Files.writeString(root.resolve("etc/init.d/cron"), "#!/bin/sh\nexit 0\n");
        Files.writeString(root.resolve("etc/rc.d/S99cron"), "");
        Files.writeString(root.resolve("bin/id"), "#!/bin/sh\nprintf '0\\n'\n");
        shell(shell, root, "chmod +x etc/init.d/cron bin/id");

        long expiry = Instant.now().getEpochSecond() + 1200;
        SupportRouterLease lease = new SupportRouterLease(ID, expiry, KEY, ".");
        SupportRouterLease.Runner runner = command -> shell(shell, root, command);
        lease.ensure(runner, () -> true);
        String initialAuth = Files.readString(auth);
        String initialCron = Files.readString(cron);
        Path scripts = root.resolve("root/katovpn-support/" + ID);
        String session = Files.readString(scripts.resolve("session.sh"));
        String cleanup = Files.readString(scripts.resolve("cleanup.sh"));
        check(initialAuth.lines().filter(line -> line.endsWith(" " + MARKER)).count() == 1, "initial key is unique");
        check(initialCron.lines().filter(line -> line.endsWith(" " + MARKER)).count() == 1, "initial cron entry is unique");

        lease.ensure(runner, () -> true);
        check(Files.readString(auth).equals(initialAuth) && Files.readString(cron).equals(initialCron), "healthy state is unchanged");
        Files.writeString(auth, otherKey + "\n");
        Files.writeString(cron, otherCron + "\n");
        Files.delete(scripts.resolve("session.sh"));
        Files.writeString(scripts.resolve("cleanup.sh"), "not the lease cleanup");
        lease.ensure(runner, () -> true);
        check(Files.readString(auth).equals(initialAuth), "repair restored original key only");
        check(Files.readString(cron).equals(initialCron), "repair restored original cron only");
        check(Files.readString(scripts.resolve("session.sh")).equals(session), "repair preserved exact original session expiry");
        check(Files.readString(scripts.resolve("cleanup.sh")).equals(cleanup), "repair preserved exact original cleanup expiry");

        Files.delete(scripts.resolve("cleanup.sh"));
        runner.run(lease.removeCommand());
        check(Files.readString(auth).lines().noneMatch(line -> line.endsWith(" " + MARKER)), "cleanup removed key without trusting script");
        check(Files.readString(cron).lines().noneMatch(line -> line.endsWith(" " + MARKER)), "cleanup removed cron without trusting script");
        check(Files.readString(auth).lines().anyMatch(otherKey::equals) && Files.readString(cron).lines().anyMatch(otherCron::equals),
            "cleanup preserved unrelated key and cron entries");
        expectFailure(() -> runner.run(lease.installCommand()), "an already dispatched repair cannot reauthorize a revoked lease");
        SupportRouterLease expired = new SupportRouterLease("expired123", Instant.now().getEpochSecond() - 1, KEY, ".");
        expectFailure(() -> runner.run(expired.installCommand()), "the router rejects a delayed write after the original expiry");
        check(!Files.exists(root.resolve("root/katovpn-support/expired123")), "expired repair changes no state");
    }

    interface Attempt { void run() throws Exception; }

    private static void expectFailure(Attempt attempt, String message) throws Exception {
        try { attempt.run(); }
        catch (IOException expected) { return; }
        throw new AssertionError(message);
    }

    private static String shell(String shell, Path cwd, String command) throws Exception {
        Process process = new ProcessBuilder(shell, "-s").directory(cwd.toFile()).redirectErrorStream(true).start();
        try (var input = process.getOutputStream()) {
            input.write(("export PATH=\"$PWD/bin:$PATH\"; " + command + "\n").getBytes(StandardCharsets.UTF_8));
        }
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (process.waitFor() != 0) throw new IOException("synthetic router shell command failed: " + output);
        return output;
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

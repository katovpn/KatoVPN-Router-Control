package app.katovpn.support;

import java.io.IOException;
import java.util.function.BooleanSupplier;

final class SupportRouterLease {
    interface Runner { String run(String command) throws Exception; }

    private final String id, marker, dir, auth, cron, cronInit, enabledCron, lockDir, revokedDir;
    private final String authLine, cronLine;
    private final long expiry;

    SupportRouterLease(String id, long expiry, String key) { this(id, expiry, key, ""); }

    SupportRouterLease(String id, long expiry, String key, String prefix) {
        if (!id.matches("[A-Za-z0-9_-]{8,64}") || expiry < 1
            || !key.matches("(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/]+={0,2}")
            || !(prefix.isEmpty() || prefix.equals("."))) throw new IllegalArgumentException();
        this.id = id;
        this.expiry = expiry;
        marker = "KatoVPN-Support-" + id;
        dir = prefix + "/root/katovpn-support/" + id;
        auth = prefix + "/etc/dropbear/authorized_keys";
        cron = prefix + "/etc/crontabs/root";
        cronInit = prefix + "/etc/init.d/cron";
        enabledCron = prefix + "/etc/rc.d/S*cron";
        lockDir = prefix + "/tmp/katovpn-android-support.lock";
        revokedDir = prefix + "/tmp/katovpn-android-support-revoked";
        authLine = "command=\"" + dir + "/session.sh\",no-agent-forwarding,no-X11-forwarding,no-port-forwarding " + key + " " + marker;
        cronLine = "* * * * * " + dir + "/cleanup.sh # " + marker;
    }

    void ensure(Runner runner, BooleanSupplier allowed) throws Exception {
        checkAllowed(allowed);
        String state = runner.run(inspectCommand()).trim();
        checkAllowed(allowed);
        if (state.equals("present")) return;
        if (!state.equals("missing") || !runner.run(installCommand()).trim().equals("present"))
            throw new IOException("Роутер не подтвердил временный ключ поддержки.");
        checkAllowed(allowed);
    }

    private static void checkAllowed(BooleanSupplier allowed) throws IOException {
        if (!allowed.getAsBoolean()) throw new IOException("Временный доступ завершён.");
    }

    String inspectCommand() {
        return "set -eu\n" + timeAndCapabilities() + stateChecks()
            + "if state_ok; then echo present; else echo missing; fi\n";
    }

    String installCommand() {
        return "set -eu\numask 077\n" + lock() + timeAndCapabilities() + stateChecks() + lineEditor()
            + "[ ! -e " + revokedDir + "/" + id + " ] || exit 125\n"
            + "safe_time\n"
            + "if state_ok; then echo present; exit 0; fi\n"
            + "mkdir -p " + dir + "\nchmod 700 " + dir + "\n"
            + "if ! session_ok; then\n" + writeScript("session", sessionScript()) + "fi\n"
            + "if ! cleanup_ok; then\n" + writeScript("cleanup", cleanupScript()) + "fi\n"
            + "restart=0\nif ! cron_ok; then\n"
            + "  update_line " + cron + " '# " + marker + "' \"$expected_cron\"\n  restart=1\nfi\n"
            + "if [ \"$restart\" -eq 1 ] || ! cron_running; then " + cronInit + " restart >/dev/null 2>&1; fi\n"
            + "cron_running\nsafe_time\n"
            + "if ! auth_ok; then\n"
            + "  update_line " + auth + " ' " + marker + "' \"$expected_auth\" write_key\nfi\n"
            + "state_ok\nsafe_time\necho present\n";
    }

    String removeCommand() { return "set -eu\numask 077\n" + removal(true); }

    private String removal(boolean revoke) {
        return lock() + lineEditor()
            + (revoke ? "mkdir -p " + revokedDir + "\n: > " + revokedDir + "/" + id + "\n" : "")
            + removeLine(auth, " " + marker)
            + "restart=0\n" + removeLine(cron, "# " + marker)
            + "rm -f " + dir + "/session.sh " + dir + "/cleanup.sh\n"
            + "rmdir " + dir + " 2>/dev/null || true\n"
            + "if [ \"$restart\" -eq 1 ]; then " + cronInit + " restart >/dev/null 2>&1; fi\n";
    }

    private String removeLine(String file, String suffix) {
        return "if [ -f " + file + " ] && grep -q '" + suffix + "$' " + file + "; then\n"
            + "  update_line " + file + " '" + suffix + "' ''\n  restart=1\nfi\n";
    }

    private String lock() {
        return "lock=" + lockDir + "\ntries=0\nuntil mkdir \"$lock\" 2>/dev/null; do\n"
            + "  tries=$((tries + 1)); [ \"$tries\" -lt 5 ] || exit 1; sleep 1\ndone\n"
            + "trap 'rmdir \"$lock\"' EXIT\ntrap 'exit 1' HUP INT TERM\n";
    }

    private String lineEditor() {
        return "update_line() {\n"
            + "  target=$1; suffix=$2; entry=$3; tmp=\"$target.kato-" + id + ".$$\"\n"
            + "  if [ -f \"$target\" ]; then\n"
            + "    awk -v suffix=\"$suffix\" 'length($0) < length(suffix) || substr($0, length($0)-length(suffix)+1) != suffix' \"$target\" > \"$tmp\"\n"
            + "  else : > \"$tmp\"; fi\n"
            + "  if [ -n \"$entry\" ]; then printf '%s\\n' \"$entry\" >> \"$tmp\"; fi\n"
            + "  if [ \"${4:-}\" = write_key ] && ! safe_time; then rm -f \"$tmp\"; return 124; fi\n"
            + "  chmod 600 \"$tmp\"\n  mv -f \"$tmp\" \"$target\"\n}\n";
    }

    private String timeAndCapabilities() {
        return "safe_time() { now=$(date +%s) || return 1; remaining=$((" + expiry + " - now)); "
            + "[ \"$remaining\" -gt 0 ] && [ \"$remaining\" -le 3600 ]; }\n"
            + "[ \"$(id -u)\" = 0 ] && [ -x " + cronInit + " ] && ls " + enabledCron + " >/dev/null 2>&1 "
            + "&& command -v timeout >/dev/null && safe_time || exit 124\n";
    }

    private String stateChecks() {
        return checkScript("session", sessionScript()) + checkScript("cleanup", cleanupScript())
            + checkLine("auth", auth, " " + marker, authLine)
            + checkLine("cron", cron, "# " + marker, cronLine)
            + "cron_running() { " + cronInit + " running >/dev/null 2>&1; }\n"
            + "state_ok() { [ ! -e " + revokedDir + "/" + id + " ] && session_ok && cleanup_ok && cron_ok && cron_running && auth_ok; }\n";
    }

    private String checkLine(String name, String file, String suffix, String entry) {
        return "expected_" + name + "='" + entry + "'\n" + name + "_ok() { [ -f " + file + " ] && "
            + "lines=$(sed -n '\\|" + suffix + "$|p' " + file + ") && [ \"$lines\" = \"$expected_" + name + "\" ]; }\n";
    }

    private String checkScript(String name, String script) {
        String file = dir + "/" + name + ".sh";
        return name + "_ok() {\n  [ -x " + file + " ] || return 1\n"
            + "  cmp -s " + file + " - <<'KATO_EXPECTED'\n" + script + "KATO_EXPECTED\n}\n";
    }

    private String writeScript(String name, String script) {
        String file = dir + "/" + name + ".sh";
        return "cat > " + file + ".new <<'KATO_WRITE'\n" + script + "KATO_WRITE\n"
            + "chmod 700 " + file + ".new\nmv -f " + file + ".new " + file + "\n";
    }

    private String cleanupScript() {
        return "#!/bin/sh\nset -eu\numask 077\n"
            + "[ \"$(date +%s)\" -ge " + expiry + " ] || exit 0\n" + removal(false);
    }

    private String sessionScript() {
        return "#!/bin/sh\nset -eu\nremaining=$((" + expiry + " - $(date +%s)))\n"
            + "[ \"$remaining\" -gt 0 ] && [ \"$remaining\" -le 3600 ] || exit 124\n"
            + "if [ -n \"${SSH_ORIGINAL_COMMAND:-}\" ]; then exec timeout -s KILL \"$remaining\" /bin/ash -c \"$SSH_ORIGINAL_COMMAND\"; fi\n"
            + "exec timeout -s KILL \"$remaining\" /bin/ash -l\n";
    }
}

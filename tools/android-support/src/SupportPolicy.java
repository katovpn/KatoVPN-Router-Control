package app.katovpn.support;

import java.util.function.BooleanSupplier;
import java.util.function.LongPredicate;
import java.util.function.LongSupplier;

final class SupportPolicy {
    private static final long RECOVERY_MS = 300_000;

    interface Pause { void waitMillis(long milliseconds) throws InterruptedException; }

    static boolean recover(long expiry, LongSupplier clock, BooleanSupplier cancelled,
                           LongPredicate attempt, Pause pause) throws InterruptedException {
        long limit = Math.min(expiry, clock.getAsLong() + RECOVERY_MS);
        while (!cancelled.getAsBoolean() && clock.getAsLong() < limit) {
            boolean restored = attempt.test(limit);
            long remaining = limit - clock.getAsLong();
            if (remaining <= 0 || cancelled.getAsBoolean()) return false;
            if (restored) return true;
            pause.waitMillis(Math.min(1000, remaining));
        }
        return false;
    }

    static boolean isLocalIpv4(String value) {
        if (!validIpv4(value)) return false;
        String[] parts = value.split("\\.");
        int a = Integer.parseInt(parts[0]), b = Integer.parseInt(parts[1]);
        return a == 10 || a == 172 && b >= 16 && b <= 31 || a == 192 && b == 168;
    }

    static boolean isLoopbackIpv4(String value) {
        return value.startsWith("127.") && validIpv4(value);
    }

    private static boolean validIpv4(String value) {
        if (!value.matches("(?:0|[1-9][0-9]{0,2})(?:\\.(?:0|[1-9][0-9]{0,2})){3}")) return false;
        for (String part : value.split("\\.")) if (Integer.parseInt(part) > 255) return false;
        return true;
    }

    static boolean validExpiry(long phone, long router, long expiry) {
        return router >= phone - 300 && router <= phone + 300
            && expiry >= Math.max(phone, router) + 60
            && expiry <= Math.min(phone, router) + 3600;
    }
}

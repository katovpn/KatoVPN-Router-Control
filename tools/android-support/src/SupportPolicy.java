package app.katovpn.support;

final class SupportPolicy {
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

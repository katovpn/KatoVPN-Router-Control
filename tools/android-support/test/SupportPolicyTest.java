package app.katovpn.support;

public final class SupportPolicyTest {
    public static void main(String[] args) {
        check(SupportPolicy.isLocalIpv4("192.168.1.1"));
        check(SupportPolicy.isLocalIpv4("10.1.2.3"));
        check(SupportPolicy.isLocalIpv4("172.31.1.2"));
        check(!SupportPolicy.isLocalIpv4("172." + 32 + ".1.2"));
        check(!SupportPolicy.isLocalIpv4("127.0.0.1"));
        check(!SupportPolicy.isLocalIpv4("192.168.000.1"));
        check(!SupportPolicy.isLocalIpv4("router.example.test"));
        check(SupportPolicy.isLoopbackIpv4("127.77.0.1"));
        check(!SupportPolicy.isLoopbackIpv4("127.77.300.1"));
        check(!SupportPolicy.isLoopbackIpv4("192.168.1.1"));
        check(SupportPolicy.validExpiry(100000, 100000, 103600));
        check(!SupportPolicy.validExpiry(100000, 100000, 103601));
        check(!SupportPolicy.validExpiry(100000, 99699, 103500));
        check(!SupportPolicy.validExpiry(100000, 100000, 100059));
        check(!SupportPolicy.validExpiry(100000, 100301, 103600));
        check(!SupportPolicy.validExpiry(100000, 99990, 103600));
        check(SupportPolicy.validExpiry(100000, 99990, 103590));
        System.out.println("Support policy tests passed");
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError();
    }
}

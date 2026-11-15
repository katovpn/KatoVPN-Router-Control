package app.katovpn.support;

public final class SupportPolicyTest {
    public static void main(String[] args) throws InterruptedException {
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
        checkRecovery();
        System.out.println("Support policy tests passed");
    }

    private static void checkRecovery() throws InterruptedException {
        long[] now = {0};
        check(SupportPolicy.recover(3600000, () -> now[0], () -> false, limit -> {
            check(limit == 300000);
            return now[0] >= 299000;
        }, delay -> now[0] += delay));
        check(now[0] == 299000);

        now[0] = 0;
        check(!SupportPolicy.recover(3600000, () -> now[0], () -> false,
            limit -> false, delay -> now[0] += delay));
        check(now[0] == 300000);

        now[0] = 0;
        check(!SupportPolicy.recover(120000, () -> now[0], () -> false, limit -> {
            check(limit == 120000);
            now[0] = limit;
            return true;
        }, delay -> { throw new AssertionError(); }));

        now[0] = 0;
        boolean[] stopped = {false};
        check(!SupportPolicy.recover(3600000, () -> now[0], () -> stopped[0], limit -> {
            stopped[0] = true;
            return true;
        }, delay -> { throw new AssertionError(); }));
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError();
    }
}

package app.katovpn.support;

import android.app.*;
import android.content.Intent;
import android.os.IBinder;
import android.os.SystemClock;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

public final class SupportService extends Service {
    static final String STOP = "app.katovpn.support.STOP";
    static volatile boolean busy, stopping;
    static volatile String status = "", details = "", fingerprint;
    static volatile long deadline;
    private static volatile boolean accepted;
    private static volatile CountDownLatch consent;
    private static Request queued;

    static final class Request {
        final String host, user;
        final int port;
        final byte[] password;
        Request(String host, String user, int port, byte[] password) {
            this.host = host; this.user = user; this.port = port; this.password = password;
        }
    }

    static synchronized boolean queue(Request request) {
        if (busy) return false;
        busy = true;
        stopping = false;
        status = "Подключение…";
        queued = request;
        return true;
    }

    static synchronized void cancelQueue() {
        if (queued != null) {
            Arrays.fill(queued.password, (byte) 0);
            queued = null;
            busy = false;
        }
    }

    static synchronized void reply(boolean allow) {
        if (consent == null) return;
        accepted = allow;
        fingerprint = null;
        consent.countDown();
    }

    private boolean confirm(String value) throws InterruptedException {
        CountDownLatch answer = new CountDownLatch(1);
        synchronized (SupportService.class) {
            if (stopping) return false;
            accepted = false;
            consent = answer;
            fingerprint = value;
        }
        try { return answer.await(45, TimeUnit.SECONDS) && accepted && !stopping; }
        finally {
            synchronized (SupportService.class) { consent = null; fingerprint = null; }
        }
    }

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int id) {
        if (intent != null && STOP.equals(intent.getAction())) {
            stopping = true;
            reply(false);
            if (!busy) stopSelf(id);
            return START_NOT_STICKY;
        }
        Request request;
        synchronized (SupportService.class) { request = queued; queued = null; }
        if (request == null) {
            if (!busy) stopSelf(id);
            return START_NOT_STICKY;
        }
        try {
            getSystemService(NotificationManager.class).createNotificationChannel(
                new NotificationChannel("support", "Временный доступ", NotificationManager.IMPORTANCE_LOW));
            startForeground(1, notification("Подключение к роутеру"));
        } catch (RuntimeException e) {
            Arrays.fill(request.password, (byte) 0);
            status = "Android не разрешил запустить службу поддержки.";
            busy = false;
            stopSelf(id);
            return START_NOT_STICKY;
        }
        new Thread(() -> runSession(request), "router-support").start();
        return START_NOT_STICKY;
    }

    private void runSession(Request request) {
        SupportConnection connection = null;
        ConnectivityManager networks = getSystemService(ConnectivityManager.class);
        ConnectivityManager.NetworkCallback watcher = null;
        String result = "Доступ завершён.";
        try (InputStream config = getAssets().open("support-relay.json")) {
            Network wifi = null;
            for (Network network : networks.getAllNetworks()) {
                NetworkCapabilities capabilities = networks.getNetworkCapabilities(network);
                if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                    wifi = network;
                    break;
                }
            }
            if (wifi == null) throw new java.io.IOException("Подключитесь к Wi-Fi роутера.");
            Network selected = wifi;
            watcher = new ConnectivityManager.NetworkCallback() {
                @Override public void onLost(Network network) {
                    if (selected.equals(network)) {
                        stopping = true;
                        reply(false);
                    }
                }
            };
            networks.registerNetworkCallback(new NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI).build(), watcher);
            byte[] buffer = new byte[4096];
            int size = config.read(buffer);
            connection = new SupportConnection(request.host, request.port, request.user,
                new JSONObject(new String(buffer, 0, size, StandardCharsets.UTF_8)), selected);
            details = connection.start(request.password, this::confirm, () -> stopping);
            deadline = connection.deadline;
            status = "Временный доступ активен";
            getSystemService(NotificationManager.class).notify(1, notification(status));
            while (!stopping && connection.active() && SystemClock.elapsedRealtime() < deadline) Thread.sleep(250);
            if (!stopping && SystemClock.elapsedRealtime() < deadline) result = "Связь прервалась. Доступ закрыт.";
        } catch (Exception e) {
            result = stopping ? "Доступ отменён." : "Не удалось открыть доступ. " +
                (e.getClass() == java.io.IOException.class ? e.getMessage() : "Проверьте SSH и связь с сервером.");
        } finally {
            if (watcher != null) {
                try { networks.unregisterNetworkCallback(watcher); } catch (IllegalArgumentException ignored) {}
            }
            Arrays.fill(request.password, (byte) 0);
            details = "";
            deadline = 0;
            if (connection != null) {
                status = "Закрываем доступ…";
                if (!connection.close()) result = "Туннель закрыт. Удаление ключа или закрытие доступа на сервере не подтверждено. Сработает ограничение срока.";
            }
            status = result;
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
            busy = false;
        }
    }

    private Notification notification(String text) {
        int flags = PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT;
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), flags);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, SupportService.class).setAction(STOP), flags);
        return new Notification.Builder(this, "support")
            .setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("KatoVPN Поддержка")
            .setContentText(text).setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
            .addAction(new Notification.Action.Builder(null, "Завершить", stop).build()).build();
    }

    @Override public void onDestroy() {
        stopping = true;
        reply(false);
        super.onDestroy();
    }
}

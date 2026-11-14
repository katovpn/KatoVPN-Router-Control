package app.katovpn.support;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.*;
import android.content.pm.PackageManager;
import android.os.*;
import android.text.InputType;
import android.view.WindowManager;
import android.widget.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

public final class MainActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private EditText host, port, user, password;
    private Button start, startAccess, stop, copy, share;
    private LinearLayout credentials;
    private TextView state;
    private AlertDialog confirmation;
    private final Runnable update = new Runnable() {
        public void run() {
            boolean busy = SupportService.busy;
            credentials.setVisibility(SupportService.signedIn ? android.view.View.GONE : android.view.View.VISIBLE);
            start.setEnabled(!busy);
            startAccess.setVisibility(SupportService.signedIn && !SupportService.opening ? android.view.View.VISIBLE : android.view.View.GONE);
            stop.setEnabled(busy && !SupportService.stopping);
            stop.setVisibility(busy ? android.view.View.VISIBLE : android.view.View.GONE);
            stop.setText(SupportService.opening ? "Завершить доступ" : "Отменить подключение");
            String details = SupportService.details;
            copy.setEnabled(!details.isEmpty());
            copy.setVisibility(details.isEmpty() ? android.view.View.GONE : android.view.View.VISIBLE);
            share.setVisibility(copy.getVisibility());
            String message = SupportService.status;
            long deadline = SupportService.deadline;
            if (!details.isEmpty() && deadline > 0) {
                long seconds = Math.max(0, (deadline - SystemClock.elapsedRealtime() + 999) / 1000);
                message += "\nОсталось " + String.format(Locale.ROOT, "%02d:%02d", seconds / 60, seconds % 60) + "\n\n" + details;
            }
            if (!state.getText().toString().equals(message)) state.setText(message);
            String fingerprint = SupportService.fingerprint;
            if (fingerprint == null && confirmation != null) {
                confirmation.dismiss();
                confirmation = null;
            } else if (fingerprint != null && confirmation == null) {
                confirmation = new AlertDialog.Builder(MainActivity.this).setTitle("Первый вход на роутер")
                    .setMessage("Сверьте SSH-отпечаток роутера. После успешного входа приложение его запомнит.\n\n" + fingerprint)
                    .setNegativeButton("Отмена", (d, w) -> SupportService.reply(false))
                    .setPositiveButton("Продолжить вход", (d, w) -> SupportService.reply(true))
                    .setOnCancelListener(d -> SupportService.reply(false)).show();
            }
            handler.postDelayed(this, 250);
        }
    };

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        LinearLayout form = new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        int padding = (int) (24 * getResources().getDisplayMetrics().density);
        form.setPadding(padding, padding * 2, padding, padding);
        ScrollView scroll = new ScrollView(this);
        scroll.setFitsSystemWindows(true);
        scroll.addView(form);
        setContentView(scroll);
        TextView title = new TextView(this);
        title.setText("Временная поддержка");
        title.setTextSize(26);
        form.addView(title);
        TextView intro = new TextView(this);
        intro.setText("Подключитесь к Wi-Fi роутера. Поддержка получит доступ к SSH на срок до одного часа.");
        intro.setPadding(0, padding / 2, 0, padding / 2);
        form.addView(intro);
        state = new TextView(this);
        state.setTextSize(16);
        state.setTextIsSelectable(true);
        state.setPadding(0, padding / 2, 0, padding / 2);
        form.addView(state);
        credentials = new LinearLayout(this);
        credentials.setOrientation(LinearLayout.VERTICAL);
        form.addView(credentials);
        host = field(credentials, "IP роутера", "", InputType.TYPE_CLASS_PHONE);
        port = field(credentials, "SSH-порт", "22", InputType.TYPE_CLASS_NUMBER);
        user = field(credentials, "Логин", "root", InputType.TYPE_CLASS_TEXT);
        password = field(credentials, "Пароль SSH", "", InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setImportantForAutofill(android.view.View.IMPORTANT_FOR_AUTOFILL_NO);
        start = button(credentials, "Войти на роутер", () -> {
            if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 1);
            else begin();
        });
        startAccess = button(form, "Разрешить доступ на час", SupportService::openAccess);
        stop = button(form, "Завершить доступ", () -> startService(new Intent(this, SupportService.class).setAction(SupportService.STOP)));
        copy = button(form, "Скопировать данные для поддержки", () -> {
            String detail = SupportService.details;
            if (detail.isEmpty()) return;
            ClipData clip = ClipData.newPlainText("Временный доступ KatoVPN", detail);
            if (Build.VERSION.SDK_INT >= 24) {
                PersistableBundle sensitive = new PersistableBundle();
                sensitive.putBoolean("android.content.extra.IS_SENSITIVE", true);
                clip.getDescription().setExtras(sensitive);
            }
            getSystemService(ClipboardManager.class).setPrimaryClip(clip);
            Toast.makeText(this, "Данные скопированы", Toast.LENGTH_SHORT).show();
        });
        share = button(form, "Поделиться", () -> {
            String detail = SupportService.details;
            if (detail.isEmpty()) return;
            Intent send = new Intent(Intent.ACTION_SEND).setType("text/plain")
                .putExtra(Intent.EXTRA_TEXT, "Временный доступ KatoVPN\n" + detail);
            startActivity(Intent.createChooser(send, "Передать данные поддержки"));
        });
    }

    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(request, permissions, results);
        if (request == 1 && results.length == 1 && results[0] == PackageManager.PERMISSION_GRANTED) begin();
        else if (request == 1) Toast.makeText(this, "Разрешите уведомления, чтобы видеть и завершать активный доступ.", Toast.LENGTH_LONG).show();
    }

    private void begin() {
        int sshPort;
        String ip = host.getText().toString().trim();
        String login = user.getText().toString().trim();
        try { sshPort = Integer.parseInt(port.getText().toString()); }
        catch (NumberFormatException e) { sshPort = 0; }
        if (!SupportPolicy.isLocalIpv4(ip) || sshPort < 1 || sshPort > 65535 || !login.matches("[A-Za-z0-9_.-]{1,32}") || password.length() == 0) {
            Toast.makeText(this, "Укажите локальный IPv4, порт, логин и пароль.", Toast.LENGTH_LONG).show();
            return;
        }
        byte[] secret = password.getText().toString().getBytes(StandardCharsets.UTF_8);
        password.getText().clear();
        getSystemService(android.view.inputmethod.InputMethodManager.class)
            .hideSoftInputFromWindow(password.getWindowToken(), 0);
        if (!SupportService.queue(new SupportService.Request(ip, login, sshPort, secret))) {
            Arrays.fill(secret, (byte) 0);
            return;
        }
        try { startForegroundService(new Intent(this, SupportService.class)); }
        catch (RuntimeException e) {
            SupportService.cancelQueue();
            SupportService.status = "Android не разрешил запустить службу поддержки.";
        }
    }

    @Override protected void onResume() { super.onResume(); handler.post(update); }
    @Override protected void onPause() {
        handler.removeCallbacks(update);
        if (confirmation != null) { confirmation.dismiss(); confirmation = null; }
        super.onPause();
    }
    private EditText field(LinearLayout form, String hint, String initial, int type) {
        EditText field = new EditText(this);
        field.setSingleLine(true);
        field.setInputType(type);
        field.setHint(hint);
        field.setText(initial);
        field.setSaveEnabled(false);
        form.addView(field);
        return field;
    }
    private Button button(LinearLayout form, String label, Runnable action) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setOnClickListener(v -> action.run());
        form.addView(button);
        return button;
    }
}

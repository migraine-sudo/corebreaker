package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Bundle;

public class ContentProviderScanProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path == null) path = "/all";

        if (path.contains("settings") || path.contains("all")) {
            testSettingsProviders(cursor);
        }
        if (path.contains("telephony") || path.contains("all")) {
            testTelephonyProvider(cursor);
        }
        if (path.contains("contacts") || path.contains("all")) {
            testContactsProvider(cursor);
        }
        if (path.contains("media") || path.contains("all")) {
            testMediaProvider(cursor);
        }
        if (path.contains("sms") || path.contains("all")) {
            testSmsProvider(cursor);
        }
        if (path.contains("calendar") || path.contains("all")) {
            testCalendarProvider(cursor);
        }
        if (path.contains("downloads") || path.contains("all")) {
            testDownloadsProvider(cursor);
        }
        if (path.contains("slice") || path.contains("all")) {
            testSliceProvider(cursor);
        }
        if (path.contains("usage") || path.contains("all")) {
            testUsageStatsProvider(cursor);
        }

        return cursor;
    }

    private void testSettingsProviders(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();

        // Settings.Global: mostly readable by any app
        // Settings.Secure: some might leak user data
        // Settings.System: some might leak preferences

        // Try reading sensitive secure settings
        String[] sensitiveKeys = {
            "bluetooth_name",
            "android_id",
            "default_input_method",
            "enabled_accessibility_services",
            "enabled_notification_listeners",
            "enabled_vr_listeners",
            "device_provisioned",
            "user_setup_complete",
            "last_setup_shown",
            "location_providers_allowed",
            "mock_location",
            "selected_input_method_subtype",
            "voice_interaction_service",
            "assistant",
            "autofill_service",
            "credential_service",
            "search_provider"
        };

        for (String key : sensitiveKeys) {
            try {
                Cursor c = cr.query(
                    Uri.parse("content://settings/secure/" + key),
                    null, null, null, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(c.getColumnIndex("value"));
                    cursor.addRow(new Object[]{"secure_" + key, val != null ? val : "null"});
                    c.close();
                } else {
                    cursor.addRow(new Object[]{"secure_" + key, "NO_DATA"});
                    if (c != null) c.close();
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"secure_" + key, "SEC:" + e.getMessage()});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"secure_" + key, "ERR:" + e.getClass().getSimpleName()});
            }
        }

        // Try cross-user settings access
        try {
            Cursor c = cr.query(
                Uri.parse("content://11@settings/secure/android_id"),
                null, null, null, null);
            if (c != null && c.moveToFirst()) {
                String val = c.getString(c.getColumnIndex("value"));
                cursor.addRow(new Object[]{"crossuser_android_id_u11", val != null ? val : "null"});
                c.close();
            } else {
                cursor.addRow(new Object[]{"crossuser_android_id_u11", "NO_DATA"});
                if (c != null) c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"crossuser_android_id_u11", "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"crossuser_android_id_u11", "ERR:" + e.getClass().getSimpleName() + ":" + trunc(e.getMessage())});
        }

        // Try Global settings that might reveal device info
        String[] globalKeys = {
            "device_name",
            "wifi_networks_available_notification_on",
            "bluetooth_on",
            "adb_enabled",
            "development_settings_enabled",
            "mobile_data",
            "data_roaming",
            "auto_time",
            "auto_time_zone"
        };
        for (String key : globalKeys) {
            try {
                Cursor c = cr.query(
                    Uri.parse("content://settings/global/" + key),
                    null, null, null, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(c.getColumnIndex("value"));
                    cursor.addRow(new Object[]{"global_" + key, val != null ? val : "null"});
                    c.close();
                } else {
                    if (c != null) c.close();
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"global_" + key, "ERR:" + e.getClass().getSimpleName()});
            }
        }
    }

    private void testTelephonyProvider(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();
        // Try to read APN settings, call log, voicemails
        String[] uris = {
            "content://telephony/carriers",
            "content://telephony/siminfo",
            "content://call_log/calls",
            "content://voicemail/voicemail",
        };
        for (String uriStr : uris) {
            try {
                Cursor c = cr.query(Uri.parse(uriStr), null, null, null, null);
                if (c != null) {
                    cursor.addRow(new Object[]{"tel_" + Uri.parse(uriStr).getLastPathSegment(), "READABLE count=" + c.getCount()});
                    c.close();
                } else {
                    cursor.addRow(new Object[]{"tel_" + Uri.parse(uriStr).getLastPathSegment(), "null_cursor"});
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"tel_" + Uri.parse(uriStr).getLastPathSegment(), "SEC:" + trunc(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"tel_" + Uri.parse(uriStr).getLastPathSegment(), "ERR:" + e.getClass().getSimpleName()});
            }
        }
    }

    private void testContactsProvider(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();
        try {
            Cursor c = cr.query(Uri.parse("content://com.android.contacts/contacts"), null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"contacts", "READABLE count=" + c.getCount()});
                c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"contacts", "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"contacts", "ERR:" + e.getClass().getSimpleName()});
        }

        // Try profile contact (sometimes different permission)
        try {
            Cursor c = cr.query(Uri.parse("content://com.android.contacts/profile"), null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"profile", "READABLE count=" + c.getCount()});
                c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"profile", "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"profile", "ERR:" + e.getClass().getSimpleName()});
        }
    }

    private void testMediaProvider(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();
        // Can we enumerate other apps' media files?
        String[] mediaUris = {
            "content://media/external/images/media",
            "content://media/external/video/media",
            "content://media/external/audio/media",
            "content://media/external/downloads",
            "content://media/external/file",
        };
        for (String uriStr : mediaUris) {
            try {
                Cursor c = cr.query(Uri.parse(uriStr),
                    new String[]{"_id", "_display_name", "owner_package_name"},
                    null, null, "_id DESC");
                if (c != null) {
                    int count = c.getCount();
                    String sample = "";
                    if (c.moveToFirst()) {
                        String name = c.getString(1);
                        String owner = c.getString(2);
                        sample = " first=" + (name != null ? name : "?") + " owner=" + (owner != null ? owner : "?");
                    }
                    cursor.addRow(new Object[]{"media_" + Uri.parse(uriStr).getLastPathSegment(),
                        "count=" + count + sample});
                    c.close();
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"media_" + Uri.parse(uriStr).getLastPathSegment(), "SEC:" + trunc(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"media_" + Uri.parse(uriStr).getLastPathSegment(), "ERR:" + e.getClass().getSimpleName()});
            }
        }
    }

    private void testSmsProvider(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();
        try {
            Cursor c = cr.query(Uri.parse("content://sms"), null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"sms", "READABLE count=" + c.getCount()});
                c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"sms", "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"sms", "ERR:" + e.getClass().getSimpleName()});
        }
    }

    private void testCalendarProvider(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();
        try {
            Cursor c = cr.query(Uri.parse("content://com.android.calendar/events"), null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"calendar", "READABLE count=" + c.getCount()});
                c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"calendar", "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"calendar", "ERR:" + e.getClass().getSimpleName()});
        }
    }

    private void testDownloadsProvider(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();
        // Downloads provider might expose other apps' downloaded files
        try {
            Cursor c = cr.query(Uri.parse("content://downloads/all_downloads"), null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"downloads_all", "READABLE count=" + c.getCount()});
                c.close();
            } else {
                cursor.addRow(new Object[]{"downloads_all", "null"});
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"downloads_all", "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"downloads_all", "ERR:" + e.getClass().getSimpleName()});
        }

        try {
            Cursor c = cr.query(Uri.parse("content://downloads/my_downloads"), null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"downloads_my", "READABLE count=" + c.getCount()});
                c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"downloads_my", "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"downloads_my", "ERR:" + e.getClass().getSimpleName()});
        }
    }

    private void testSliceProvider(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();
        // Slice URIs can expose UI state of other apps
        String[] sliceUris = {
            "content://android.settings.slices/action/wifi",
            "content://android.settings.slices/action/bluetooth",
            "content://android.settings.slices/action/airplane",
            "content://android.settings.slices/action/dnd",
            "content://android.settings.slices/action/flashlight",
            "content://android.settings.slices/action/location",
            "content://android.settings.slices/action/battery_saver",
            "content://com.android.settings.slices/action/enhanced_4g_lte",
        };
        for (String uriStr : sliceUris) {
            try {
                // Use call() to bind slice - more reliable
                Bundle result = cr.call(Uri.parse(uriStr), "bind_slice", null, null);
                if (result != null) {
                    cursor.addRow(new Object[]{"slice_" + Uri.parse(uriStr).getLastPathSegment(), "BOUND keys=" + result.keySet()});
                } else {
                    // Try query
                    Cursor c = cr.query(Uri.parse(uriStr), null, null, null, null);
                    if (c != null) {
                        cursor.addRow(new Object[]{"slice_" + Uri.parse(uriStr).getLastPathSegment(), "QUERY count=" + c.getCount()});
                        c.close();
                    } else {
                        cursor.addRow(new Object[]{"slice_" + Uri.parse(uriStr).getLastPathSegment(), "null"});
                    }
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"slice_" + Uri.parse(uriStr).getLastPathSegment(), "SEC:" + trunc(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"slice_" + Uri.parse(uriStr).getLastPathSegment(), "ERR:" + e.getClass().getSimpleName() + ":" + trunc(e.getMessage())});
            }
        }
    }

    private void testUsageStatsProvider(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();
        // Try to access usage stats provider directly
        try {
            Cursor c = cr.query(Uri.parse("content://com.android.providers.usagestats"), null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"usagestats", "READABLE count=" + c.getCount()});
                c.close();
            } else {
                cursor.addRow(new Object[]{"usagestats", "null"});
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"usagestats", "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"usagestats", "ERR:" + e.getClass().getSimpleName()});
        }
    }

    private String trunc(String s) {
        if (s == null) return "null";
        return s.length() > 100 ? s.substring(0, 100) : s;
    }

    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String sel, String[] selArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String sel, String[] selArgs) { return 0; }
}

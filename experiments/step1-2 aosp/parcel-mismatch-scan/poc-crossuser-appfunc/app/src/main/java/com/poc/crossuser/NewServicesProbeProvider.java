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

public class NewServicesProbeProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        probeAppPrediction(cursor);
        probeOnDeviceIntelligence(cursor);
        probeAmbientContext(cursor);
        probeWearableSensing(cursor);
        probeContentSuggestions(cursor);
        probeSafetyCenter(cursor);
        probeGameManager(cursor);
        probeDomainVerification(cursor);

        return cursor;
    }

    private void probeAppPrediction(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("app_prediction");
        if (binder == null) { cursor.addRow(new Object[]{"app_prediction", "no_binder"}); return; }
        
        String desc = "android.app.prediction.IPredictionManager";
        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0); // userId
                data.writeString(getContext().getPackageName());
                data.writeStrongBinder(new Binder());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"pred_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"pred_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"pred_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {
                if (tx <= 3) cursor.addRow(new Object[]{"pred_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeOnDeviceIntelligence(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("on_device_intelligence");
        if (binder == null) { cursor.addRow(new Object[]{"odi", "no_binder"}); return; }
        
        String desc = "android.app.ondeviceintelligence.IOnDeviceIntelligenceManager";
        for (int tx = 1; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                data.writeStrongBinder(new Binder());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"odi_tx" + tx, "OK avail=" + avail});
                        } else {
                            cursor.addRow(new Object[]{"odi_tx" + tx, "OK_empty"});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"odi_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"odi_tx" + tx, "EX:" + truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {
                if (tx <= 3) cursor.addRow(new Object[]{"odi_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeAmbientContext(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("ambient_context");
        if (binder == null) { cursor.addRow(new Object[]{"ambient", "no_binder"}); return; }
        
        String desc = "android.app.ambientcontext.IAmbientContextManager";
        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(0); // userId
                data.writeString(getContext().getPackageName());
                data.writeStrongBinder(new Binder());
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        cursor.addRow(new Object[]{"amb_tx" + tx, "OK avail=" + avail});
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"amb_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"amb_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {
                if (tx <= 3) cursor.addRow(new Object[]{"amb_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeWearableSensing(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("wearable_sensing");
        if (binder == null) { cursor.addRow(new Object[]{"wearable", "no_binder"}); return; }
        
        String desc = "android.app.wearable.IWearableSensingManager";
        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
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
                        cursor.addRow(new Object[]{"wear_tx" + tx, "OK avail=" + avail});
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"wear_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"wear_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {
                if (tx <= 3) cursor.addRow(new Object[]{"wear_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeContentSuggestions(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("content_suggestions");
        if (binder == null) { cursor.addRow(new Object[]{"suggestions", "no_binder"}); return; }
        
        String desc = "android.app.contentsuggestions.IContentSuggestionsManager";
        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
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
                        cursor.addRow(new Object[]{"sug_tx" + tx, "OK avail=" + avail});
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"sug_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"sug_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {
                if (tx <= 3) cursor.addRow(new Object[]{"sug_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeSafetyCenter(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("safety_center");
        if (binder == null) { cursor.addRow(new Object[]{"safety_center", "no_binder"}); return; }
        
        String desc = "android.safetycenter.ISafetyCenterManager";
        // SafetyCenter — contains security scan results, may leak security state
        for (int tx = 1; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0); // userId
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 0) {
                            cursor.addRow(new Object[]{"sc_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        if (tx <= 3) cursor.addRow(new Object[]{"sc_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"sc_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {
                if (tx <= 2) cursor.addRow(new Object[]{"sc_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeGameManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("game");
        if (binder == null) { cursor.addRow(new Object[]{"game", "no_binder"}); return; }
        
        String desc = "android.app.IGameManagerService";
        // GameManager — might expose info about installed games / game modes
        for (int tx = 1; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0); // userId
                boolean result = binder.transact(tx, data, reply, 0);
                if (result) {
                    try {
                        reply.readException();
                        int avail = reply.dataAvail();
                        if (avail > 4) {
                            cursor.addRow(new Object[]{"game_tx" + tx, "OK avail=" + avail});
                        }
                    } catch (SecurityException e) {
                        if (tx <= 2) cursor.addRow(new Object[]{"game_tx" + tx, "SEC"});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5 && !msg.contains("Unknown")) {
                            cursor.addRow(new Object[]{"game_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {}
            data.recycle();
            reply.recycle();
        }
    }

    private void probeDomainVerification(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("domain_verification");
        if (binder == null) { cursor.addRow(new Object[]{"domain_verify", "no_binder"}); return; }
        
        String desc = "android.content.pm.verify.domain.IDomainVerificationManager";
        // DomainVerification — might expose domain-app associations
        // TX=4: getDomainVerificationUserState(String pkg, int userId)
        // TX=9: getOwnersForDomain(String domain, int userId) — reveals which apps handle domains!

        for (int tx = 1; tx <= 12; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
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
                            cursor.addRow(new Object[]{"dv_tx" + tx, "OK avail=" + avail});
                        } else if (avail == 4 && tx <= 5) {
                            cursor.addRow(new Object[]{"dv_tx" + tx, "OK avail=4"});
                        }
                    } catch (SecurityException e) {
                        cursor.addRow(new Object[]{"dv_tx" + tx, "SEC:" + truncate(e.getMessage())});
                    } catch (Exception e) {
                        String msg = e.getMessage();
                        if (msg != null && !msg.contains("consumed") && msg.length() > 5) {
                            cursor.addRow(new Object[]{"dv_tx" + tx, truncate(msg)});
                        }
                    }
                }
            } catch (Exception e) {
                if (tx <= 2) cursor.addRow(new Object[]{"dv_tx" + tx, "ERR:" + e.getClass().getSimpleName()});
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

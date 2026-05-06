#!/usr/bin/env python3
"""
Parcel Mismatch Scanner v3 — Stream-based, memory-efficient.
Processes dexdump -d output line-by-line in streaming mode.
"""

import subprocess
import re
import os
import sys

DEXDUMP = os.path.expanduser("~/Library/Android/sdk/build-tools/35.0.1/dexdump")
DEX_DIR = "/tmp/fw_dex"
OUT_DIR = "/Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step1-2 aosp/parcel-mismatch-scan"

# Target classes (priority scan list)
TARGETS = [
    "android.credentials.selection.UserSelectionDialogResult",
    "android.credentials.selection.ProviderPendingIntentResponse",
    "android.credentials.selection.RequestInfo",
    "android.credentials.selection.CreateCredentialProviderData",
    "android.credentials.selection.GetCredentialProviderData",
    "android.credentials.selection.Entry",
    "android.credentials.selection.AuthenticationEntry",
    "android.credentials.selection.BaseDialogResult",
    "android.credentials.selection.FailureDialogResult",
    "android.credentials.selection.CancelSelectionRequest",
    "android.credentials.selection.DisabledProviderData",
    "android.credentials.CreateCredentialRequest",
    "android.credentials.CreateCredentialResponse",
    "android.credentials.GetCredentialRequest",
    "android.credentials.GetCredentialResponse",
    "android.credentials.Credential",
    "android.credentials.CredentialOption",
    "android.credentials.CredentialDescription",
    "android.credentials.ClearCredentialStateRequest",
    "android.credentials.PrepareGetCredentialResponseInternal",
    "android.credentials.SetEnabledProvidersRequest",
    "android.credentials.RegisterCredentialDescriptionRequest",
    "android.credentials.UnregisterCredentialDescriptionRequest",
    "android.credentials.ListEnabledProvidersResponse",
    "android.credentials.GetCandidateCredentialsRequest",
    "android.credentials.GetCandidateCredentialsResponse",
    "android.credentials.CredentialProviderInfo",
    "android.app.appfunctions.ExecuteAppFunctionAidlRequest",
    "android.app.appfunctions.ExecuteAppFunctionRequest",
    "android.app.appfunctions.ExecuteAppFunctionResponse",
    "android.app.appfunctions.AppFunctionMetadata",
    "android.app.appfunctions.AppFunctionPackageMetadata",
    "android.app.appfunctions.AppFunctionSchemaMetadata",
    "android.app.appfunctions.AppFunctionSearchSpec",
    "android.app.appfunctions.AppFunctionAidlSearchSpec",
    "android.app.appfunctions.AppFunctionName",
    "android.app.appfunctions.AppFunctionUriGrant",
    "android.app.appfunctions.AppFunctionException",
    "android.app.appfunctions.GenericDocumentWrapper",
    "android.telephony.satellite.SatelliteCapabilities",
    "android.telephony.satellite.SatelliteDatagram",
    "android.telephony.satellite.SatelliteInfo",
    "android.telephony.satellite.SatelliteModemEnableRequestAttributes",
    "android.telephony.satellite.SatellitePosition",
    "android.telephony.satellite.SatelliteSessionStats",
    "android.telephony.satellite.SatelliteSubscriberInfo",
    "android.telephony.satellite.SatelliteSubscriberProvisionStatus",
    "android.telephony.satellite.SatelliteSubscriptionInfo",
    "android.telephony.satellite.SatelliteAccessConfiguration",
    "android.telephony.satellite.PlmnSatelliteConfig",
    "android.telephony.satellite.NtnSignalStrength",
    "android.telephony.satellite.PointingInfo",
    "android.telephony.satellite.AntennaDirection",
    "android.telephony.satellite.AntennaPosition",
    "android.telephony.satellite.EarfcnRange",
    "android.telephony.satellite.SystemSelectionSpecifier",
    "android.companion.virtual.VirtualDevice",
    "android.companion.virtual.ActivityPolicyExemption",
    "android.companion.virtual.ViewConfigurationParams",
    "android.companion.virtual.camera.VirtualCameraConfig",
    "android.companion.virtual.camera.VirtualCameraSessionConfig",
    "android.companion.virtual.camera.VirtualCameraStreamConfig",
    "android.companion.virtual.computercontrol.ComputerControlSessionParams",
    "android.companion.virtual.sensor.VirtualSensor",
    "android.companion.virtual.sensor.VirtualSensorEvent",
    "android.companion.virtual.sensor.VirtualSensorAdditionalInfo",
    "android.hardware.biometrics.IdentityCheckInfo",
    "android.hardware.biometrics.IdentityCheckStatus",
    "android.service.autofill.ConvertCredentialRequest",
    "android.service.autofill.ConvertCredentialResponse",
    "android.security.talisman.TalismanIdentitySet",
    "android.service.security.talisman.TalismanIdentitySetNeed",
    "android.proximity.RangingParams",
]


def stream_scan_dex(dex_path, target_classes):
    """Stream dexdump output and extract write/read sequences for target classes."""
    # Method headers in dexdump use dot-notation: android.foo.Bar.writeToParcel
    dex_targets = {}
    for cls in target_classes:
        dex_targets[cls] = cls  # dot notation directly

    # Inner classes for createFromParcel
    inner_targets = {}
    for cls in target_classes:
        inner_targets[f"{cls}$1"] = cls
        inner_targets[f"{cls}$Creator"] = cls
        inner_targets[f"{cls}$CREATOR"] = cls

    results = {}  # class_name -> {'writes': [], 'reads': []}

    # State machine
    current_method = None  # (class_name, 'write'|'read')
    method_calls = []

    proc = subprocess.Popen(
        [DEXDUMP, '-d', dex_path],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )

    for raw_line in proc.stdout:
        line = raw_line.decode('utf-8', errors='replace')

        # Detect method entry
        # Format: "190c74: |[190c74] android.foo.Bar.writeToParcel:(Landroid/os/Parcel;I)V"
        if '|[' in line and '.writeToParcel:(Landroid/os/Parcel;I)V' in line:
            m = re.search(r'\|\[\w+\]\s+(\S+)\.writeToParcel:', line)
            if m:
                method_class = m.group(1)
                if method_class in dex_targets:
                    if current_method:
                        cls_prev, kind_prev = current_method
                        if kind_prev == 'write':
                            if method_calls or not results.get(cls_prev, {}).get('writes'):
                                results[cls_prev]['writes'] = method_calls[:]
                        else:
                            if method_calls or not results.get(cls_prev, {}).get('reads'):
                                results[cls_prev]['reads'] = method_calls[:]
                    cls = dex_targets[method_class]
                    if cls not in results:
                        results[cls] = {'writes': [], 'reads': []}
                    current_method = (cls, 'write')
                    method_calls = []
                    continue

        # Detect readFromParcel:(Landroid/os/Parcel;)V — delegate pattern
        if '|[' in line and '.readFromParcel:(Landroid/os/Parcel;)V' in line:
            m = re.search(r'\|\[\w+\]\s+(\S+)\.readFromParcel:', line)
            if m:
                method_class = m.group(1)
                if method_class in dex_targets:
                    if current_method:
                        cls_prev, kind_prev = current_method
                        if kind_prev == 'write':
                            if method_calls or not results.get(cls_prev, {}).get('writes'):
                                results[cls_prev]['writes'] = method_calls[:]
                        else:
                            if method_calls or not results.get(cls_prev, {}).get('reads'):
                                results[cls_prev]['reads'] = method_calls[:]
                    cls = dex_targets[method_class]
                    if cls not in results:
                        results[cls] = {'writes': [], 'reads': []}
                    current_method = (cls, 'read')
                    method_calls = []
                    continue

        # Detect createFromParcel or constructor(Parcel)
        if '|[' in line:
            # Match only single-param <init>:(Landroid/os/Parcel;)V — not synthetic delegates
            if '.<init>:(Landroid/os/Parcel;)V' in line:
                m = re.search(r'\|\[\w+\]\s+(\S+)\.<init>:\(Landroid/os/Parcel;\)V', line)
                if m:
                    method_class = m.group(1)
                    base_class = method_class.split('-')[0] if '-' in method_class else method_class
                    if base_class in dex_targets:
                        method_class = base_class
                        if current_method:
                            cls_prev, kind_prev = current_method
                            if kind_prev == 'write':
                                results[cls_prev]['writes'] = method_calls[:]
                            else:
                                if method_calls:
                                    results[cls_prev]['reads'] = method_calls[:]
                        cls = dex_targets[method_class]
                        if cls not in results:
                            results[cls] = {'writes': [], 'reads': []}
                        current_method = (cls, 'read')
                        method_calls = []
                        continue

            # Match createFromParcel that returns the specific type (not Object bridge)
            if '.createFromParcel:(Landroid/os/Parcel;)' in line and \
               'Ljava/lang/Object;' not in line:
                m = re.search(r'\|\[\w+\]\s+(\S+)\.createFromParcel:', line)
                if m:
                    method_class = m.group(1)
                    if method_class in inner_targets:
                        if current_method:
                            cls_prev, kind_prev = current_method
                            if kind_prev == 'write':
                                results[cls_prev]['writes'] = method_calls[:]
                            else:
                                if method_calls:
                                    results[cls_prev]['reads'] = method_calls[:]
                        cls = inner_targets[method_class]
                        if cls not in results:
                            results[cls] = {'writes': [], 'reads': []}
                        current_method = (cls, 'read')
                        method_calls = []
                        continue

        # If we're in a tracked method, collect Parcel calls
        if current_method:
            # Method end: a new method header that we didn't already match above
            if '|[' in line:
                # New method starting — save current and reset
                cls, kind = current_method
                if kind == 'write':
                    if method_calls or not results[cls]['writes']:
                        results[cls]['writes'] = method_calls[:]
                else:
                    if method_calls or not results[cls]['reads']:
                        results[cls]['reads'] = method_calls[:]
                current_method = None
                method_calls = []
                continue

            # Detect Parcel method calls
            if 'invoke-virtual' in line and 'Landroid/os/Parcel;.' in line:
                m = re.search(r'Landroid/os/Parcel;\.(\w+):', line)
                if m:
                    method_name = m.group(1)
                    if method_name.startswith('write') or \
                       method_name.startswith('read') or \
                       method_name.startswith('create'):
                        method_calls.append(method_name)

    # Save last method if any
    if current_method:
        cls, kind = current_method
        if kind == 'write':
            if method_calls or not results[cls]['writes']:
                results[cls]['writes'] = method_calls[:]
        else:
            if method_calls or not results[cls]['reads']:
                results[cls]['reads'] = method_calls[:]

    proc.wait()
    return results


def normalize(method):
    """Normalize to comparable type token"""
    method = method.replace('write', '').replace('read', '').replace('create', '')
    # Normalize array variants
    method = method.replace('ArrayList', 'List').replace('ArraySet', 'Set')
    return method


def analyze_results(results):
    """Analyze and report findings"""
    findings = []

    for cls, data in sorted(results.items()):
        writes = data['writes']
        reads = data['reads']

        if not writes and not reads:
            continue

        w_count = len(writes)
        r_count = len(reads)

        if w_count == 0 or r_count == 0:
            findings.append({
                'class': cls,
                'severity': 'INFO',
                'issue': f"Incomplete: writes={w_count} reads={r_count}",
                'writes': writes,
                'reads': reads,
            })
            continue

        # Count mismatch = HIGH
        if w_count != r_count:
            findings.append({
                'class': cls,
                'severity': 'HIGH',
                'issue': f"LENGTH MISMATCH: writes={w_count} reads={r_count} (diff={w_count-r_count})",
                'writes': writes,
                'reads': reads,
            })
            continue

        # Type mismatch check
        mismatches = []
        for i in range(min(w_count, r_count)):
            w_norm = normalize(writes[i])
            r_norm = normalize(reads[i])
            if w_norm != r_norm:
                mismatches.append(f"@{i}: {writes[i]} vs {reads[i]}")

        if mismatches:
            findings.append({
                'class': cls,
                'severity': 'MEDIUM',
                'issue': f"TYPE MISMATCH at {len(mismatches)} positions: {'; '.join(mismatches[:5])}",
                'writes': writes,
                'reads': reads,
            })
        else:
            findings.append({
                'class': cls,
                'severity': 'OK',
                'issue': f"Matched ({w_count} fields)",
                'writes': writes,
                'reads': reads,
            })

    return findings


def main():
    from pathlib import Path
    import time

    dex_files = sorted(Path(DEX_DIR).glob("classes*.dex"))

    print(f"=== Parcel Mismatch Scanner v3 ===")
    print(f"Targets: {len(TARGETS)} classes")
    print(f"DEX files: {len(dex_files)}")
    print()

    all_results = {}

    for dex_path in dex_files:
        print(f"[*] Scanning {dex_path.name}...", end=" ", flush=True)
        t0 = time.time()
        results = stream_scan_dex(str(dex_path), TARGETS)
        elapsed = time.time() - t0
        found = sum(1 for v in results.values() if v['writes'] or v['reads'])
        print(f"{found} classes found ({elapsed:.1f}s)")
        all_results.update(results)

    print(f"\nTotal classes with data: {len(all_results)}")

    # Analyze
    findings = analyze_results(all_results)

    # Print summary
    high = [f for f in findings if f['severity'] == 'HIGH']
    medium = [f for f in findings if f['severity'] == 'MEDIUM']
    ok = [f for f in findings if f['severity'] == 'OK']
    info = [f for f in findings if f['severity'] == 'INFO']

    print(f"\n{'='*60}")
    print(f"RESULTS: HIGH={len(high)} MEDIUM={len(medium)} OK={len(ok)} INFO={len(info)}")
    print(f"{'='*60}")

    if high:
        print(f"\n>>> HIGH SEVERITY (count mismatch) <<<")
        for f in high:
            print(f"\n  {f['class']}")
            print(f"    {f['issue']}")
            print(f"    Writes: {f['writes']}")
            print(f"    Reads:  {f['reads']}")

    if medium:
        print(f"\n>>> MEDIUM SEVERITY (type mismatch) <<<")
        for f in medium:
            print(f"\n  {f['class']}")
            print(f"    {f['issue']}")

    # Write report
    report_path = os.path.join(OUT_DIR, "scan_results.md")
    with open(report_path, 'w') as fp:
        fp.write("# Parcel Mismatch Scan Results\n\n")
        fp.write(f"**Target**: Pixel 10 framework.jar (Android 16, CP1A.260405.005)\n")
        fp.write(f"**Date**: 2026-04-30\n")
        fp.write(f"**Classes scanned**: {len(TARGETS)}\n")
        fp.write(f"**Classes with data**: {len(all_results)}\n")
        fp.write(f"**Findings**: HIGH={len(high)} MEDIUM={len(medium)} OK={len(ok)} INFO={len(info)}\n\n")
        fp.write("---\n\n")

        for f in high + medium:
            fp.write(f"## [{f['severity']}] `{f['class']}`\n\n")
            fp.write(f"**{f['issue']}**\n\n")
            fp.write(f"writeToParcel ({len(f['writes'])} calls):\n```\n")
            for w in f['writes']:
                fp.write(f"  {w}\n")
            fp.write("```\n\n")
            fp.write(f"createFromParcel ({len(f['reads'])} calls):\n```\n")
            for r in f['reads']:
                fp.write(f"  {r}\n")
            fp.write("```\n\n---\n\n")

        fp.write("## OK (matched)\n\n")
        for f in ok:
            fp.write(f"- `{f['class']}`: {f['issue']}\n")

        fp.write("\n## INFO (incomplete extraction)\n\n")
        for f in info:
            fp.write(f"- `{f['class']}`: {f['issue']}\n")

    print(f"\nReport written to: {report_path}")


if __name__ == '__main__':
    main()

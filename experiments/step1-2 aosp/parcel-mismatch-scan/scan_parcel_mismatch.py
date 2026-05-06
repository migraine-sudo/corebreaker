#!/usr/bin/env python3
"""
Parcel Mismatch Scanner — Detect writeToParcel/createFromParcel asymmetry in Android framework.

Approach:
  1. dexdump each DEX file to extract method bytecode
  2. For each class with CREATOR field (= Parcelable implementation):
     - Extract writeToParcel bytecode → count write* calls and their types
     - Extract createFromParcel bytecode (via CREATOR or constructor) → count read* calls
  3. Flag classes where write sequence != read sequence (potential mismatch)

A mismatch means one side writes more/fewer bytes than the other reads,
which is the root cause of Bundle key collision attacks (CVE-2017-13288 family).

Target: Pixel 10 framework.jar (Android 16, SDK 36, CP1A.260405.005)
"""

import subprocess
import sys
import os
import re
from collections import defaultdict
from pathlib import Path

DEXDUMP = os.path.expanduser("~/Library/Android/sdk/build-tools/35.0.1/dexdump")

# Parcel write/read method patterns
WRITE_METHODS = [
    'writeInt', 'writeLong', 'writeFloat', 'writeDouble', 'writeByte',
    'writeString', 'writeString8', 'writeString16',
    'writeParcelable', 'writeTypedObject', 'writeBundle', 'writeMap',
    'writeByteArray', 'writeIntArray', 'writeLongArray', 'writeFloatArray',
    'writeDoubleArray', 'writeStringArray', 'writeStringList',
    'writeTypedList', 'writeTypedArray', 'writeList', 'writeParcelableArray',
    'writeBoolean', 'writeSerializable', 'writeStrongBinder',
    'writeStrongInterface', 'writeSparseArray', 'writeSparseBooleanArray',
    'writeCharSequence', 'writeValue', 'writePersistableBundle',
    'writeArraySet', 'writeBlob', 'writeFileDescriptor',
    'writeRawFileDescriptor', 'writeParcelableList',
]

READ_METHODS = [
    'readInt', 'readLong', 'readFloat', 'readDouble', 'readByte',
    'readString', 'readString8', 'readString16',
    'readParcelable', 'readTypedObject', 'readBundle', 'readHashMap',
    'readByteArray', 'readIntArray', 'readLongArray', 'readFloatArray',
    'readDoubleArray', 'readStringArray', 'readStringList',
    'readTypedList', 'readTypedArray', 'readArrayList', 'readParcelableArray',
    'readBoolean', 'readSerializable', 'readStrongBinder',
    'readStrongInterface', 'readSparseArray', 'readSparseBooleanArray',
    'readCharSequence', 'readValue', 'readPersistableBundle',
    'readArraySet', 'readBlob', 'readFileDescriptor',
    'readRawFileDescriptor', 'readParcelableList',
    'createByteArray', 'createIntArray', 'createLongArray',
    'createFloatArray', 'createDoubleArray', 'createStringArray',
    'createStringArrayList', 'createTypedArray', 'createTypedArrayList',
]

# Normalize write→read pairs for comparison
WRITE_TO_READ_MAP = {
    'writeInt': 'readInt',
    'writeLong': 'readLong',
    'writeFloat': 'readFloat',
    'writeDouble': 'readDouble',
    'writeByte': 'readByte',
    'writeString': 'readString',
    'writeString8': 'readString8',
    'writeString16': 'readString16',
    'writeBoolean': 'readBoolean',
    'writeByteArray': 'readByteArray/createByteArray',
    'writeIntArray': 'readIntArray/createIntArray',
    'writeLongArray': 'readLongArray/createLongArray',
    'writeBundle': 'readBundle',
    'writeStrongBinder': 'readStrongBinder',
    'writeParcelable': 'readParcelable/readTypedObject',
    'writeTypedObject': 'readTypedObject/readParcelable',
    'writeTypedList': 'readTypedList/createTypedArrayList',
    'writeTypedArray': 'readTypedArray/createTypedArray',
    'writeStringList': 'readStringList/createStringArrayList',
    'writeCharSequence': 'readCharSequence',
    'writeValue': 'readValue',
    'writeSerializable': 'readSerializable',
}


def run_dexdump(dex_path):
    """Run dexdump -d and return output"""
    result = subprocess.run(
        [DEXDUMP, '-d', dex_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300
    )
    return result.stdout.decode('utf-8', errors='replace')


def extract_parcelable_classes(dexdump_output):
    """Extract class names that have a CREATOR field (= Parcelable)"""
    classes = []
    current_class = None

    for line in dexdump_output.split('\n'):
        if '  Class descriptor' in line:
            m = re.search(r"'L([^;]+);'", line)
            if m:
                current_class = m.group(1).replace('/', '.')
        if "name          : 'CREATOR'" in line and current_class:
            classes.append(current_class)

    return list(set(classes))


def extract_method_calls(dexdump_output, class_name, method_name):
    """Extract invoke-virtual calls to Parcel methods within a specific method"""
    # Convert class name to dex format
    dex_class = class_name.replace('.', '/')

    # Find the method section
    method_pattern = f"{dex_class}.{method_name}:"

    calls = []
    in_method = False
    brace_depth = 0

    lines = dexdump_output.split('\n')
    for i, line in enumerate(lines):
        if method_pattern in line:
            in_method = True
            continue

        if in_method:
            # End of method: next method header or class header
            if ('      name          :' in line and 'name          : ' in lines[i-1] if i > 0 else False):
                break
            if '    #' in line and ': (in L' in line:
                break
            if 'Class #' in line:
                break

            # Look for Parcel method invocations
            if 'invoke-virtual' in line and 'Landroid/os/Parcel;.' in line:
                m = re.search(r'Landroid/os/Parcel;\.(\w+):', line)
                if m:
                    calls.append(m.group(1))

    return calls


def extract_write_read_sequences(dexdump_output, class_name):
    """Extract the write sequence from writeToParcel and read sequence from createFromParcel"""
    dex_class = class_name.replace('.', '/')

    writes = []
    reads = []

    # State machine to find methods
    lines = dexdump_output.split('\n')
    i = 0

    while i < len(lines):
        line = lines[i]

        # Find writeToParcel
        if f'{dex_class}.writeToParcel:(Landroid/os/Parcel;I)V' in line:
            # Scan until next method
            i += 1
            while i < len(lines):
                l = lines[i]
                if '      name          :' in l or '    #' in l and ': (in L' in l:
                    break
                if 'invoke-virtual' in l and 'Landroid/os/Parcel;.' in l:
                    m = re.search(r'Landroid/os/Parcel;\.(\w+):', l)
                    if m:
                        method = m.group(1)
                        if any(method.startswith(w) for w in ['write']):
                            writes.append(method)
                i += 1
            continue

        # Find createFromParcel (in CREATOR anonymous class or $1 class)
        # Also check constructor that takes Parcel: <init>:(Landroid/os/Parcel;)V
        if f'{dex_class}.<init>:(Landroid/os/Parcel;' in line or \
           f'{dex_class}$1.createFromParcel' in line or \
           f'{dex_class}$Creator.createFromParcel' in line or \
           (f'createFromParcel' in line and dex_class in line):
            i += 1
            while i < len(lines):
                l = lines[i]
                if '      name          :' in l or ('    #' in l and ': (in L' in l):
                    break
                if 'invoke-virtual' in l and 'Landroid/os/Parcel;.' in l:
                    m = re.search(r'Landroid/os/Parcel;\.(\w+):', l)
                    if m:
                        method = m.group(1)
                        if any(method.startswith(r) for r in ['read', 'create']):
                            reads.append(method)
                i += 1
            continue

        i += 1

    return writes, reads


def normalize_method(method):
    """Normalize method name to a comparable type token"""
    # Map similar methods to same token
    if method in ('readString', 'readString8', 'readString16', 'writeString', 'writeString8', 'writeString16'):
        return 'STRING'
    if method in ('readInt', 'writeInt'):
        return 'INT'
    if method in ('readLong', 'writeLong'):
        return 'LONG'
    if method in ('readFloat', 'writeFloat'):
        return 'FLOAT'
    if method in ('readDouble', 'writeDouble'):
        return 'DOUBLE'
    if method in ('readByte', 'writeByte'):
        return 'BYTE'
    if method in ('readBoolean', 'writeBoolean'):
        return 'BOOLEAN'
    if method in ('readByteArray', 'writeByteArray', 'createByteArray'):
        return 'BYTE_ARRAY'
    if method in ('readIntArray', 'writeIntArray', 'createIntArray'):
        return 'INT_ARRAY'
    if method in ('readLongArray', 'writeLongArray', 'createLongArray'):
        return 'LONG_ARRAY'
    if method in ('readBundle', 'writeBundle'):
        return 'BUNDLE'
    if method in ('readStrongBinder', 'writeStrongBinder'):
        return 'BINDER'
    if method in ('readParcelable', 'writeParcelable', 'readTypedObject', 'writeTypedObject'):
        return 'PARCELABLE'
    if method in ('readTypedList', 'writeTypedList', 'createTypedArrayList'):
        return 'TYPED_LIST'
    if method in ('readTypedArray', 'writeTypedArray', 'createTypedArray'):
        return 'TYPED_ARRAY'
    if method in ('readStringList', 'writeStringList', 'createStringArrayList'):
        return 'STRING_LIST'
    if method in ('readCharSequence', 'writeCharSequence'):
        return 'CHARSEQUENCE'
    if method in ('readValue', 'writeValue'):
        return 'VALUE'
    if method in ('readSerializable', 'writeSerializable'):
        return 'SERIALIZABLE'
    if method in ('readPersistableBundle', 'writePersistableBundle'):
        return 'PERSISTABLE_BUNDLE'
    if method in ('readStringArray', 'writeStringArray', 'createStringArray'):
        return 'STRING_ARRAY'
    if method in ('readFloatArray', 'writeFloatArray', 'createFloatArray'):
        return 'FLOAT_ARRAY'
    if method in ('readDoubleArray', 'writeDoubleArray', 'createDoubleArray'):
        return 'DOUBLE_ARRAY'
    # Fallback: strip read/write/create prefix
    for prefix in ('write', 'read', 'create'):
        if method.startswith(prefix):
            return method[len(prefix):].upper()
    return method.upper()


def compare_sequences(writes, reads):
    """Compare normalized write/read sequences. Return mismatch details."""
    norm_writes = [normalize_method(w) for w in writes]
    norm_reads = [normalize_method(r) for r in reads]

    issues = []

    # Length mismatch
    if len(norm_writes) != len(norm_reads):
        issues.append(f"LENGTH_MISMATCH: writes={len(norm_writes)} reads={len(norm_reads)}")

    # Type mismatch at each position
    min_len = min(len(norm_writes), len(norm_reads))
    for idx in range(min_len):
        if norm_writes[idx] != norm_reads[idx]:
            issues.append(f"TYPE_MISMATCH@{idx}: write={norm_writes[idx]} read={norm_reads[idx]}")

    # Extra fields
    if len(norm_writes) > len(norm_reads):
        extras = norm_writes[len(norm_reads):]
        issues.append(f"EXTRA_WRITES: {extras}")
    elif len(norm_reads) > len(norm_writes):
        extras = norm_reads[len(norm_writes):]
        issues.append(f"EXTRA_READS: {extras}")

    return issues, norm_writes, norm_reads


def scan_dex(dex_path, priority_classes=None):
    """Scan a DEX file for Parcel mismatches"""
    print(f"[*] Scanning {dex_path}...")

    output = run_dexdump(dex_path)
    print(f"    dexdump output: {len(output)} bytes")

    # Get all Parcelable classes
    all_parcelables = extract_parcelable_classes(output)
    print(f"    Found {len(all_parcelables)} Parcelable classes")

    # If priority filter specified, scan those first
    if priority_classes:
        targets = [c for c in all_parcelables if any(p in c for p in priority_classes)]
        others = [c for c in all_parcelables if c not in targets]
        scan_order = targets + others
    else:
        scan_order = sorted(all_parcelables)

    results = []

    for cls in scan_order:
        writes, reads = extract_write_read_sequences(output, cls)

        # Skip if we couldn't extract both
        if not writes and not reads:
            continue

        if not writes or not reads:
            # One side empty — might be delegating to parent or using different pattern
            results.append({
                'class': cls,
                'severity': 'INFO',
                'writes': writes,
                'reads': reads,
                'issues': [f"INCOMPLETE: writes={len(writes)} reads={len(reads)}"],
            })
            continue

        issues, norm_w, norm_r = compare_sequences(writes, reads)

        if issues:
            # Determine severity
            severity = 'LOW'
            if any('LENGTH_MISMATCH' in i for i in issues):
                severity = 'HIGH'
            elif any('TYPE_MISMATCH' in i for i in issues):
                severity = 'MEDIUM'

            results.append({
                'class': cls,
                'severity': severity,
                'writes': writes,
                'reads': reads,
                'norm_writes': norm_w,
                'norm_reads': norm_r,
                'issues': issues,
            })

    return results


def main():
    dex_dir = "/tmp/fw_dex"
    output_dir = "/Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step1-2 aosp/parcel-mismatch-scan"

    # Priority: Android 15/16 new classes
    priority = [
        'credentials.selection',
        'credentials.C',  # Create/Clear/Credential
        'appfunctions',
        'satellite',
        'companion.virtual',
        'talisman',
        'IdentityCheck',
        'ConvertCredential',
        'proximity.Ranging',
        'ondeviceintelligence',
        'computercontrol',
    ]

    all_results = []

    dex_files = sorted(Path(dex_dir).glob("classes*.dex"))
    for dex_path in dex_files:
        results = scan_dex(str(dex_path), priority)
        all_results.extend(results)

    # Sort by severity
    severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
    all_results.sort(key=lambda r: severity_order.get(r['severity'], 99))

    # Output report
    report_path = os.path.join(output_dir, "scan_results.md")
    with open(report_path, 'w') as f:
        f.write("# Parcel Mismatch Scan Results\n\n")
        f.write(f"**Target**: Pixel 10 framework.jar (Android 16, CP1A.260405.005)\n")
        f.write(f"**Date**: 2026-04-30\n")
        f.write(f"**Total Parcelables scanned**: {sum(1 for r in all_results)}\n")
        f.write(f"**Findings**: HIGH={sum(1 for r in all_results if r['severity']=='HIGH')} ")
        f.write(f"MEDIUM={sum(1 for r in all_results if r['severity']=='MEDIUM')} ")
        f.write(f"LOW={sum(1 for r in all_results if r['severity']=='LOW')} ")
        f.write(f"INFO={sum(1 for r in all_results if r['severity']=='INFO')}\n\n")
        f.write("---\n\n")

        for r in all_results:
            if r['severity'] in ('HIGH', 'MEDIUM'):
                f.write(f"## [{r['severity']}] {r['class']}\n\n")
                f.write(f"**Issues**: {'; '.join(r['issues'])}\n\n")
                f.write(f"**Write sequence** ({len(r['writes'])} calls):\n")
                f.write(f"```\n{r['writes']}\n```\n\n")
                f.write(f"**Read sequence** ({len(r['reads'])} calls):\n")
                f.write(f"```\n{r['reads']}\n```\n\n")
                if 'norm_writes' in r:
                    f.write(f"**Normalized comparison**:\n")
                    f.write(f"```\nW: {r.get('norm_writes', [])}\nR: {r.get('norm_reads', [])}\n```\n\n")
                f.write("---\n\n")

        # Summary of INFO/LOW
        f.write("## Low/Info findings (incomplete extraction)\n\n")
        for r in all_results:
            if r['severity'] in ('LOW', 'INFO'):
                f.write(f"- **[{r['severity']}]** `{r['class']}`: {r['issues'][0] if r['issues'] else 'unknown'}\n")

    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Total analyzed: {len(all_results)}")
    print(f"HIGH:   {sum(1 for r in all_results if r['severity']=='HIGH')}")
    print(f"MEDIUM: {sum(1 for r in all_results if r['severity']=='MEDIUM')}")
    print(f"LOW:    {sum(1 for r in all_results if r['severity']=='LOW')}")
    print(f"INFO:   {sum(1 for r in all_results if r['severity']=='INFO')}")
    print(f"\nReport: {report_path}")

    # Print HIGH findings immediately
    high_findings = [r for r in all_results if r['severity'] == 'HIGH']
    if high_findings:
        print(f"\n{'='*60}")
        print("HIGH SEVERITY FINDINGS:")
        print(f"{'='*60}")
        for r in high_findings:
            print(f"\n  {r['class']}")
            print(f"    Issues: {r['issues']}")
            print(f"    Writes ({len(r['writes'])}): {r['writes']}")
            print(f"    Reads  ({len(r['reads'])}): {r['reads']}")


if __name__ == '__main__':
    main()

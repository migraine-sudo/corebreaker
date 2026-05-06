#!/usr/bin/env python3
"""
Intent Redirection Scanner v1
Finds system service methods that call startActivity/startActivityAsUser
and traces whether the Intent comes from an untrusted source (Bundle, Parcel, callback).

Usage:
  python3 scan_intent_redirect.py <dex_path> [<dex_path2> ...]

Example:
  python3 scan_intent_redirect.py /tmp/services_dex/classes.dex /tmp/services_dex/classes2.dex
"""

import subprocess
import re
import sys
import os
import time

DEXDUMP = os.path.expanduser("~/Library/Android/sdk/build-tools/35.0.1/dexdump")

# Methods that launch activities (potential sinks)
LAUNCH_SINKS = [
    'startActivity', 'startActivityAsUser', 'startActivityForResult',
    'startActivities', 'startActivityAsCaller',
    'sendBroadcast', 'sendBroadcastAsUser', 'sendOrderedBroadcast',
    'startService', 'startServiceAsUser', 'startForegroundService',
    'bindService', 'bindServiceAsUser',
    'send',  # PendingIntent.send()
]

# Methods that extract Intents from untrusted sources
INTENT_SOURCES = [
    'getParcelable',       # Bundle.getParcelable() → Intent
    'getParcelableExtra',  # Intent.getParcelableExtra() → nested Intent
    'readParcelable',      # Parcel.readParcelable() → Intent
    'readTypedObject',     # Parcel.readTypedObject() → Intent
    'getIntent',           # various getIntent() calls
    'getAction',           # retrieved from external
    'createFromParcel',    # CREATOR.createFromParcel()
]

# Mitigations that reduce exploitability
MITIGATIONS = [
    'setComponent', 'setPackage', 'setClass', 'setClassName',
    'filterEquals', 'sanitizeIntent',
    'isLaunchable', 'resolveActivity',
    'FLAG_IMMUTABLE',
    'checkCallingPermission', 'enforceCallingPermission',
    'checkCallingOrSelfPermission', 'enforceCallingOrSelfPermission',
    'getCallingUid', 'getCallingPid',
]


def scan_dex_for_intent_redirects(dex_path):
    """
    Stream dexdump and find methods that both:
    1. Extract an Intent from some source (Bundle, Parcel, callback)
    2. Pass it to startActivity or similar sink

    Returns list of findings: {class, method, sinks, sources, mitigations}
    """
    proc = subprocess.Popen(
        [DEXDUMP, '-d', dex_path],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )

    current_method = None  # (class_name, method_name, method_sig)
    method_sinks = []
    method_sources = []
    method_mitigations = []
    findings = []

    for raw_line in proc.stdout:
        line = raw_line.decode('utf-8', errors='replace')

        # Method header
        if '|[' in line:
            # Save previous method if it had both source and sink
            if current_method and method_sinks and method_sources:
                findings.append({
                    'class': current_method[0],
                    'method': current_method[1],
                    'signature': current_method[2],
                    'sinks': method_sinks[:],
                    'sources': method_sources[:],
                    'mitigations': method_mitigations[:],
                })

            current_method = None
            method_sinks = []
            method_sources = []
            method_mitigations = []

            # Parse method header
            m = re.search(r'\|\[\w+\]\s+(\S+)\.(\w+):(\S+)', line)
            if m:
                cls = m.group(1)
                method_name = m.group(2)
                sig = m.group(3)
                # Only track service implementation classes
                if ('com.android.server' in cls or
                    'Service' in cls or
                    'Manager' in cls) and \
                   method_name not in ('toString', 'hashCode', 'equals'):
                    current_method = (cls, method_name, sig)
            continue

        if not current_method:
            continue

        # Check for launch sinks
        if 'invoke-' in line:
            for sink in LAUNCH_SINKS:
                if f'.{sink}:' in line or f'.{sink}(' in line:
                    method_sinks.append(sink)
                    break

            # Check for Intent sources from untrusted data
            for source in INTENT_SOURCES:
                if f'.{source}:' in line or f'.{source}(' in line:
                    # Extra check: is this reading an Intent specifically?
                    if 'Intent' in line or 'Parcel' in line or 'Bundle' in line:
                        method_sources.append(source)
                    break

            # Check for mitigations
            for mit in MITIGATIONS:
                if mit in line:
                    method_mitigations.append(mit)
                    break

    # Save last method
    if current_method and method_sinks and method_sources:
        findings.append({
            'class': current_method[0],
            'method': current_method[1],
            'signature': current_method[2],
            'sinks': method_sinks[:],
            'sources': method_sources[:],
            'mitigations': method_mitigations[:],
        })

    proc.wait()
    return findings


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    dex_paths = sys.argv[1:]

    print(f"\n{'='*60}")
    print(f"Intent Redirection Scanner v1")
    print(f"  DEX files: {len(dex_paths)}")
    print(f"{'='*60}\n")

    all_findings = []

    for dex_path in dex_paths:
        print(f"[*] Scanning {os.path.basename(dex_path)}...", end=" ", flush=True)
        t0 = time.time()
        findings = scan_dex_for_intent_redirects(dex_path)
        print(f"{len(findings)} potential redirects ({time.time()-t0:.1f}s)")
        all_findings.extend(findings)

    # Categorize
    unmitigated = [f for f in all_findings if not f['mitigations']]
    mitigated = [f for f in all_findings if f['mitigations']]

    print(f"\n{'='*60}")
    print(f"RESULTS: {len(all_findings)} total, {len(unmitigated)} UNMITIGATED, {len(mitigated)} mitigated")
    print(f"{'='*60}\n")

    if unmitigated:
        print(">>> UNMITIGATED (no setComponent/setPackage/sanitize) <<<\n")
        for f in sorted(unmitigated, key=lambda x: x['class']):
            print(f"  [!!!] {f['class']}.{f['method']}")
            print(f"        Sinks: {f['sinks']}")
            print(f"        Sources: {f['sources']}")
            print()

    if mitigated:
        print("\n>>> MITIGATED (has protections) <<<\n")
        for f in sorted(mitigated, key=lambda x: x['class']):
            print(f"  [OK]  {f['class']}.{f['method']}")
            print(f"        Sinks: {f['sinks']}")
            print(f"        Sources: {f['sources']}")
            print(f"        Mitigations: {f['mitigations']}")
            print()

    # Write report
    out_dir = os.path.dirname(os.path.abspath(__file__))
    report_path = os.path.join(out_dir, "intent_redirect_results.md")
    with open(report_path, 'w') as fp:
        fp.write("# Intent Redirection Scan Results\n\n")
        fp.write(f"**Date**: {time.strftime('%Y-%m-%d')}\n")
        fp.write(f"**Target**: services.jar DEX files\n")
        fp.write(f"**Total findings**: {len(all_findings)}\n")
        fp.write(f"**Unmitigated**: {len(unmitigated)}\n")
        fp.write(f"**Mitigated**: {len(mitigated)}\n\n---\n\n")

        fp.write("## Unmitigated Findings (Priority Review)\n\n")
        for f in sorted(unmitigated, key=lambda x: x['class']):
            fp.write(f"### `{f['class']}.{f['method']}`\n\n")
            fp.write(f"- **Signature**: `{f['signature']}`\n")
            fp.write(f"- **Sinks**: {', '.join(f['sinks'])}\n")
            fp.write(f"- **Sources**: {', '.join(f['sources'])}\n")
            fp.write(f"- **Mitigations**: NONE\n\n")

        fp.write("---\n\n## Mitigated Findings\n\n")
        for f in sorted(mitigated, key=lambda x: x['class']):
            fp.write(f"- `{f['class']}.{f['method']}` — {', '.join(f['mitigations'])}\n")

    print(f"\nReport written to: {report_path}")


if __name__ == '__main__':
    main()

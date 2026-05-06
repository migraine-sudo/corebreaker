#!/usr/bin/env python3
"""
Binder Permission Check Scanner v2
Extracts transaction codes from AIDL $Stub.onTransact() and checks
whether the corresponding service implementation methods enforce permissions.

Usage:
  python3 scan_binder_perms.py <stub_dex> <impl_dex> <interface_class>

Example:
  python3 scan_binder_perms.py /tmp/fw_dex/classes.dex /tmp/services_dex/classes.dex \
    android.credentials.ICredentialManager
"""

import subprocess
import re
import sys
import os
import time

DEXDUMP = os.path.expanduser("~/Library/Android/sdk/build-tools/35.0.1/dexdump")

PERM_CHECK_PATTERNS = [
    'enforceCallingPermission', 'enforceCallingOrSelfPermission',
    'checkCallingPermission', 'checkCallingOrSelfPermission',
    'enforcePermission', 'checkPermission',
    'getCallingUid', 'getCallingPid',
    'enforceCrossUserPermission', 'enforceAccessPermission',
    'enforceChangePermission', 'hasPermission',
    'checkAuthorization', 'isCallerSystem',
    'checkPackage', 'enforceBluetoothPrivilegedPermission',
    'requirePermission',
    # Service-specific caller validation helpers
    'validateCallingPackage', 'CallerValidator',
    'verifyTargetUserHandle', 'assertCallerIsOwner',
    'checkCallerIsSystemOrSameApp', 'enforceCallerIsOwner',
    'checkCallerPermission', 'assertPermission',
    'verifyCaller', 'validateCaller',
    'enforceOwnership', 'checkUidPermission',
    'isCallerAllowed', 'verifyCallingPackage',
    'enforceSystemCaller', 'ensureCallerPermission',
    # AIDL @EnforcePermission generated methods
    '_enforcePermission',
    # Role-based access control
    'checkCallerIsRecentsOrHomeRoleHolder',
    'isCallerSystemOrShell', 'checkCallerIsSystem',
    # Service-specific enforcers (inter-procedural)
    'enforceManageHealthPermissions', 'DataPermissionEnforcer',
    'enforceAnyOfPermissions', 'enforceAllOfPermissions',
    'throwIllegalStateExceptionIfDataSyncInProgress',
    # WiFi module-specific patterns
    'WifiPermissionsUtil', 'enforceCanAccessScanResults',
    'enforceTetherAccessPermission', 'enforceNetworkSettingsPermission',
    'enforceNetworkStackPermission', 'enforceConnectivityInternalPermission',
    'enforceNearbyDevicesPermission', 'enforceCoarseLocationPermission',
    'enforceFineLocationPermission', 'enforceLocationPermission',
    'enforceMulticastLock', 'enforceNetworkStackOrSettingsPermission',
    # UWB module-specific patterns
    'enforceUwbPrivilegedPermission', 'checkUwbRangingPermissionForStartDataDelivery',
    'enforceUwbRangingPermissionForPreflight', 'hasUwbPrivilegedPermission',
    # USD (Wi-Fi Aware NAN Service Discovery) patterns
    'enforceNearbyDevicesPermission', 'enforceLocationPermission',
]


def extract_stub_methods(dex_path, iface_class):
    """
    Stream dexdump to extract methods called from onTransact.
    Returns list of method names in transaction order.
    """
    stub_header = f"{iface_class}$Stub.onTransact:(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z"
    # In bytecode refs, dots become slashes
    stub_bytecode_pattern = f"L{iface_class.replace('.', '/')}$Stub;."

    proc = subprocess.Popen(
        [DEXDUMP, '-d', dex_path],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )

    in_method = False
    methods = []

    for raw_line in proc.stdout:
        line = raw_line.decode('utf-8', errors='replace')

        if not in_method:
            if '|[' in line and stub_header in line:
                in_method = True
            continue

        # End of onTransact
        if '|[' in line:
            break

        # Look for invoke-virtual on the Stub class
        if 'invoke-virtual' in line and stub_bytecode_pattern in line:
            m = re.search(rf'{re.escape(stub_bytecode_pattern)}(\w+):', line)
            if m:
                method_name = m.group(1)
                if method_name != 'onTransact':
                    methods.append(method_name)

    proc.kill()
    proc.wait()
    return methods


def check_permissions_batch(dex_paths, iface_class, methods):
    """
    Stream dexdump of impl DEX files once and check all target methods
    for permission enforcement.

    The implementation could be in:
    1. The Stub class itself (inline in framework)
    2. A server-side class like CredentialManagerService$CredentialManagerServiceStub

    We search for ANY class that has a method with the same name and check its body.
    """
    # Build search targets — we look for any method with matching names
    # that belongs to a class related to our interface
    target_methods = set(methods)
    iface_short = iface_class.split('.')[-1]  # e.g. "ICredentialManager"
    # Service impl class patterns to look for
    service_patterns = [
        iface_class + "$Stub",  # Framework stub
        iface_short.lstrip('I'),  # e.g. "CredentialManager"
    ]

    results = {}  # method_name -> (has_perm_check, [checks_found])

    for dex_path in (dex_paths if isinstance(dex_paths, list) else [dex_paths]):
        proc = subprocess.Popen(
            [DEXDUMP, '-d', dex_path],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )

        current_method = None  # (class_name, method_name)
        method_body = []
        perm_checks = []

        for raw_line in proc.stdout:
            line = raw_line.decode('utf-8', errors='replace')

            if '|[' in line:
                # Save previous method if it was one we're tracking
                if current_method and current_method[1] in target_methods:
                    if current_method[1] not in results or perm_checks:
                        results[current_method[1]] = (len(perm_checks) > 0, perm_checks[:])

                current_method = None
                perm_checks = []

                # Check if this is a method we care about
                for method_name in target_methods:
                    if f".{method_name}:" in line:
                        # Extract class name
                        m = re.search(r'\|\[\w+\]\s+(\S+)\.' + re.escape(method_name) + ':', line)
                        if m:
                            cls = m.group(1)
                            # Only track if it's a plausible implementation class
                            relevant = False
                            for pat in service_patterns:
                                if pat in cls:
                                    relevant = True
                                    break
                            # Also accept any class with the method if we haven't found it yet
                            if relevant or method_name not in results:
                                current_method = (cls, method_name)
                        break
                continue

            # Collect permission check evidence
            if current_method:
                for pattern in PERM_CHECK_PATTERNS:
                    if pattern in line:
                        perm_checks.append(pattern)
                        break

        # Save last method
        if current_method and current_method[1] in target_methods:
            if current_method[1] not in results or perm_checks:
                results[current_method[1]] = (len(perm_checks) > 0, perm_checks[:])

        proc.wait()

    return results


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    stub_dex = sys.argv[1]
    impl_dex = sys.argv[2]
    iface_class = sys.argv[3]

    print(f"\n{'='*60}")
    print(f"Binder Permission Scanner")
    print(f"  Interface: {iface_class}")
    print(f"  Stub DEX:  {stub_dex}")
    print(f"  Impl DEX:  {impl_dex}")
    print(f"{'='*60}\n")

    # Step 1: Extract transaction methods from onTransact
    print("[1] Extracting transaction methods from Stub.onTransact...", flush=True)
    t0 = time.time()
    methods = extract_stub_methods(stub_dex, iface_class)
    print(f"    Found {len(methods)} methods ({time.time()-t0:.1f}s)")

    if not methods:
        print("    ERROR: No methods found in onTransact")
        sys.exit(1)

    for i, m in enumerate(methods, 1):
        print(f"    TX={i}: {m}")
    print()

    # Step 2: Check permission enforcement in implementation
    print("[2] Checking permission enforcement in implementation...", flush=True)
    t0 = time.time()

    # Search both stub DEX and impl DEX
    all_dex = [stub_dex]
    if impl_dex != stub_dex:
        # If impl_dex contains multiple files (comma-separated)
        all_dex.extend(impl_dex.split(','))

    results = check_permissions_batch(all_dex, iface_class, methods)
    print(f"    Done ({time.time()-t0:.1f}s)\n")

    # Step 3: Report
    findings = []
    print(f"{'='*60}")
    print(f"RESULTS")
    print(f"{'='*60}\n")

    for i, method in enumerate(methods, 1):
        if method in results:
            has_check, checks = results[method]
            if has_check:
                print(f"  [OK]  TX={i:3d}  {method}  — {checks[:3]}")
            else:
                print(f"  [!!!] TX={i:3d}  {method}  — NO PERMISSION CHECK")
                findings.append({'tx': i, 'method': method})
        else:
            print(f"  [?]   TX={i:3d}  {method}  — implementation not found")

    print(f"\n{'='*60}")
    print(f"FINDINGS: {len(findings)} methods without permission checks")
    print(f"{'='*60}")
    for f in findings:
        print(f"  TX={f['tx']}: {iface_class}$Stub.{f['method']}")


if __name__ == '__main__':
    main()

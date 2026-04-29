# Finding 040: Opaque Origins Without Precursor Bypass All Process Lock Checks

## Summary

In `ChildProcessSecurityPolicyImpl::CanAccessOrigin()`, opaque origins without a valid precursor tuple unconditionally pass the access check — as long as a `SecurityState` exists for the child process (which it always does for any running renderer). This effectively bypasses the entire Jail/Citadel/committed-origin enforcement framework for any opaque origin that lacks precursor information.

## Affected Files

- `content/browser/child_process_security_policy_impl.cc:2213-2226` — Universal access for precursor-less opaque origins
- `content/browser/child_process_security_policy_impl.cc:2249-2264` — Sandboxed process kCanCommitNewOrigin always true

## Details

### Precursor-less opaque origin bypass

```cpp
// child_process_security_policy_impl.cc:2213-2226
if (origin.opaque()) {
  auto precursor_tuple = origin.GetTupleOrPrecursorTupleIfOpaque();
  if (!precursor_tuple.IsValid()) {
    // Allow opaque origins w/o precursors (if the security state exists).
    // TODO(acolwell): Investigate all cases that trigger this path (e.g.,
    // browser-initiated navigations to data: URLs) and fix them so we have
    // precursor information.
    base::AutoLock lock(lock_);
    const SecurityState* security_state = ...;
    return !!security_state;  // ALWAYS TRUE for any running renderer
  }
}
```

`SecurityState` is created for every child process in `Add()` and only removed in `Remove()` when the process terminates. This means `!!security_state` is `true` for any living renderer process. The access check passes regardless of what site the process is locked to.

### Sandboxed process universal commit

```cpp
// child_process_security_policy_impl.cc:2254-2264
case AccessType::kCanCommitNewOrigin:
  // TODO(crbug.com/325410297): For now, don't restrict URLs from committing
  // in sandboxed processes here...
  return true;
```

A sandboxed process can commit **any** URL. The TODO acknowledges this should be strengthened.

### Additional bypasses in the same file

- **data: URLs** (line 1774-1778): `CanCommitURL` unconditionally allows data: URLs in any process
- **blob:null/ lock** (lines 2444-2448): Opaque-origin precursor checks bypassed for blob:null locked processes
- **Unused process** (line 2512): `process->IsUnused()` passes citadel checks for any origin
- **file:// origin matching** (lines 631-645): `file:///etc/passwd` matches `file:///home/secret`

## Attack Scenario

### Via compromised renderer

1. Compromised renderer constructs an opaque origin with no precursor
2. Sends IPC to browser process claiming this opaque origin
3. `CanAccessOrigin()` is called with this origin
4. Since precursor_tuple is invalid, check falls through to `return !!security_state`
5. Security state exists → access granted regardless of process lock
6. Renderer gains access to data for any origin

### Data URL trigger

1. Browser-initiated navigation to `data:text/html,...` creates an opaque origin with no precursor
2. The navigation commits in whatever process is assigned
3. That process now has an opaque origin that passes `CanAccessOrigin()` for any access type
4. If the process also hosts other sites (e.g., in Android WebView where process sharing is common), the opaque-origin document may access data outside its intended scope

## Impact

- **Process lock bypass**: The core enforcement mechanism of site isolation is circumvented
- **Requires compromised renderer** (for direct exploitation): Need to forge opaque origin IPCs
- **Acknowledged placeholder**: The TODO confirms this is known and unfixed
- **Combined with Finding 036**: The DCHECK-only CanAccessOrigin in navigation_request.cc means this bypass can't even be caught by the navigation stack

## VRP Value

**Medium** — Requires compromised renderer to directly exploit, but represents a fundamental gap in the site isolation enforcement layer. The attack amplifies any renderer compromise by granting cross-origin data access. Combined with Findings 034-036 (disabled origin validation), this creates a chain where no production check prevents cross-origin access after a renderer compromise.

# Finding 035: kEnforceSameDocumentOriginInvariants Disabled — Origin Spoofing via Same-Document Navigation

## Summary

The `kEnforceSameDocumentOriginInvariants` feature flag is **DISABLED_BY_DEFAULT** and doubly gated (also requires `kTreatMhtmlInitialDocumentLoadsAsCrossDocument`). When disabled:

1. The browser calls `SetLastCommittedOrigin()` with renderer-provided origin for **all** navigations including same-document
2. Insecure request policy modification checks for same-document navigations are skipped entirely
3. A cross-origin same-document navigation check exists but compares against `GetLastCommittedOrigin()` which itself can be spoofed

A compromised renderer can change the browser-side committed origin via a same-document navigation IPC.

## Affected Files

- `content/common/features.cc:245-246` — Feature flag, DISABLED_BY_DEFAULT
- `content/browser/renderer_host/render_frame_host_impl.cc:5280-5296` — SetLastCommittedOrigin from renderer params
- `content/browser/renderer_host/render_frame_host_impl.cc:16024-16043` — Skipped insecure_request_policy check
- `content/browser/renderer_host/render_frame_host_impl.cc:12061-12066` — Bypassable fallback check

## Details

### Feature flag

```cpp
// features.cc:245-246
// This feature acts as a kill switch for https://crbug.com/40580002.
BASE_FEATURE(kEnforceSameDocumentOriginInvariants,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

### Origin blindly accepted from renderer

```cpp
// render_frame_host_impl.cc:5290-5296 (DidNavigate)
if (!was_within_same_document ||
    !features::IsEnforceSameDocumentOriginInvariantsEnabled()) {
  SetLastCommittedOrigin(params.origin,
                         params.has_potentially_trustworthy_unique_origin);
}
```

Since the flag is disabled, `SetLastCommittedOrigin` is called for every same-document navigation with the renderer-supplied origin. Same-document navigations (pushState, fragment changes) should **never** change the origin.

### Insecure request policy check skipped

```cpp
// render_frame_host_impl.cc:16024-16043
if (is_same_document_navigation &&
    features::IsEnforceSameDocumentOriginInvariantsEnabled()) {
  // bad_message::RFH_SAME_DOC_INSECURE_REQUEST_POLICY_CHANGE
  // bad_message::RFH_SAME_DOC_INSECURE_NAV_SET_CHANGE
  // ... ENTIRELY SKIPPED when flag disabled
}
```

### Bypassable fallback check (circular dependency)

```cpp
// render_frame_host_impl.cc:12061-12066
if (!features::IsEnforceSameDocumentOriginInvariantsEnabled()) {
  if (is_same_document_navigation && origin != GetLastCommittedOrigin()) {
    return CanCommitStatus::CANNOT_COMMIT_ORIGIN;
  }
}
```

This check compares against `GetLastCommittedOrigin()` — but that value was already overwritten by the renderer in `DidNavigate()` (above). An attacker can first spoof the origin, then all subsequent comparisons pass.

## Attack Scenario

1. Compromised renderer sends `DidCommitSameDocumentNavigation` IPC with `params.origin = evil.com`
2. Browser calls `SetLastCommittedOrigin(evil.com)` (flag disabled, no check)
3. Subsequent `CanCommitOriginAndUrl` checks compare against `GetLastCommittedOrigin()` which now returns `evil.com`
4. The renderer is now "committed" to `evil.com` from the browser's perspective
5. Subsequent navigations to `evil.com` may be allowed in the same process, breaking site isolation

### Without renderer compromise (theoretical)

If MHTML loading or `document.open()` timing can trigger a confused renderer state where a same-document navigation IPC is sent with a different origin, this could be exploitable without explicit renderer compromise. The flag comment references crbug.com/40580002 (MHTML-related).

## Impact

- **Compromised renderer**: Can change browser-side committed origin via same-document navigation IPC
- **Site isolation bypass**: Browser process trusts the spoofed origin for future isolation decisions
- **Insecure request policy downgrade**: Upgrade-Insecure-Requests can be silently removed
- **Circular defense**: The fallback check depends on the same state the attack modifies

## VRP Value

**Medium** — Requires a compromised renderer (or confused renderer state) to exploit. The severity comes from the fact that this flag was specifically designed to prevent origin confusion via same-document navigations, and it's disabled in production. Combined with Finding 034, this creates a layered defense failure in origin validation.

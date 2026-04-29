# Finding 054: Navigation Commit Origin Access Check is DCHECK-Only (crbug.com/497761255)

## Summary

At navigation commit time, the critical check that verifies whether a renderer process is allowed to access the committed origin (`CanAccessOrigin` with `kCanCommitNewOrigin`) is only enforced via DCHECK — stripped in release builds. This is the same crbug.com/497761255 seen in SW controller matching (Finding 051).

## Affected Files

- `content/browser/renderer_host/navigation_request.cc:9369-9373` — DCHECK-only origin access check at commit

## Details

```cpp
// navigation_request.cc:9369-9373
// TODO(https://crbug.com/497761255): CHECK-exclusion: Convert to CHECK once
// we are sure this isn't hit.
DCHECK(policy->CanAccessOrigin(
    process_id, origin,
    ChildProcessSecurityPolicyImpl::AccessType::kCanCommitNewOrigin));
```

This check should verify that the renderer process hosting the navigation is actually allowed to commit content with the given origin. In release builds, this check is completely absent.

## Attack Scenario

### Cross-origin commit via navigation logic bug

1. A logic bug elsewhere in navigation (e.g., redirect handling, about:blank inheritance, or SiteInstance selection) causes a navigation to be assigned to the wrong process
2. The process commits a page with an origin it should not have access to
3. In release builds, the DCHECK is stripped — the commit succeeds without any enforcement
4. The renderer now has access to data (cookies, storage) for the wrong origin
5. This is a complete site-isolation bypass

## Impact

- **Requires compromised renderer or navigation logic bug**: Not directly exploitable from web content
- **Site isolation bypass**: If triggered, a process gains access to a cross-origin's data
- **Defense-in-depth gap**: This should be the last line of defense against process misassignment
- **Same crbug as Finding 051**: Part of a pattern of DCHECK-only security checks

## VRP Value

**Medium** — Requires compromised renderer for direct exploitation. However, this is a critical defense-in-depth check that should catch bugs in navigation logic. The same crbug.com/497761255 appearing in multiple critical code paths (navigation commit, SW controller assignment, SW security utils) suggests systematic under-enforcement.

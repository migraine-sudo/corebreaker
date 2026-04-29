# Finding 036: CanAccessOrigin Process-to-Origin Check is DCHECK-Only — Absent in Release Builds

## Summary

In `GetOriginForURLLoaderFactoryAfterResponse()`, the verification that a renderer process is authorized to commit a given origin (`ChildProcessSecurityPolicy::CanAccessOrigin` with `kCanCommitNewOrigin`) is implemented as a `DCHECK`, not a `CHECK`. DCHECKs are stripped from release/official builds. This means the last line of defense for site isolation — verifying the computed origin is valid for the assigned process — **does not exist in production Chrome**.

## Affected Files

- `content/browser/renderer_host/navigation_request.cc:9364-9374` — DCHECK-only CanAccessOrigin check

## Details

```cpp
// navigation_request.cc:9364-9374
if (HasRenderFrameHost() &&
    !GetRenderFrameHost()->ShouldBypassSecurityChecksForErrorPage(this) &&
    !IsForMhtmlSubframe()) {
  int process_id = GetRenderFrameHost()->GetProcess()->GetDeprecatedID();
  auto* policy = ChildProcessSecurityPolicyImpl::GetInstance();
  // TODO(https://crbug.com/497761255): CHECK-exclusion: Convert to CHECK once
  // we are sure this isn't hit.
  DCHECK(policy->CanAccessOrigin(
      process_id, origin,
      ChildProcessSecurityPolicyImpl::AccessType::kCanCommitNewOrigin));
}
```

The TODO explicitly acknowledges this should be a CHECK but says "convert... once we are sure this isn't hit" — confirming it fires in some cases and is intentionally not enforced.

### What CanAccessOrigin verifies

`CanAccessOrigin` with `kCanCommitNewOrigin` verifies that the renderer process identified by `process_id` is allowed to commit the given origin. This is the site isolation enforcement point — if a cross-origin redirect causes the browser to compute an origin that doesn't match the process lock, this check should catch it.

In release builds, this entire block is compiled out. The origin is used unconditionally.

## Attack Scenario

1. A navigation involves cross-origin redirects that confuse the process assignment logic
2. The browser computes an origin (e.g., `bank.com`) for a renderer process that is locked to a different site (e.g., `evil.com`)
3. In debug/canary builds, the DCHECK would fire and catch this
4. In production release builds, the DCHECK is absent — the navigation proceeds
5. The `evil.com`-locked process now has a document committed at `bank.com` origin
6. Site isolation is bypassed: the process can read cross-site data

### Combined with Finding 034

Finding 034 shows that `kValidateCommitOriginAtCommit` (which validates origin against FrameNavigationEntry) is also disabled. Finding 036 shows that `CanAccessOrigin` (which validates origin against process lock) is DCHECK-only. Together, these mean **neither** origin validation check is active in production Chrome.

## Impact

- **Site isolation last-resort check absent**: The process-to-origin authorization is not enforced in production
- **Amplifies other origin confusion bugs**: Any bug that produces the wrong origin in `GetOriginForURLLoaderFactoryAfterResponse()` would have been caught by this DCHECK in debug builds but passes silently in release
- **Acknowledged but unresolved**: The TODO crbug.com/497761255 confirms this needs to be a CHECK but hasn't been converted

## VRP Value

**Medium** — On its own, this requires triggering the edge case where origin computation produces the wrong result. But as a defense-in-depth failure, it means all other origin-related bugs in the navigation stack have no safety net in production. The specific concern is the layered failure: Finding 034 (commit origin validation disabled) + Finding 036 (process-origin check DCHECK-only) = zero origin validation in production navigation.

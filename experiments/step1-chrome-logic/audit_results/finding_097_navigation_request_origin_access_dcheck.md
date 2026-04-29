# Finding 097: Navigation Commit Origin Access Check is DCHECK-Only

## Summary

In `NavigationRequest::GetOriginForURLLoaderFactoryAfterResponse()`, the check that the renderer process can commit the new origin uses DCHECK instead of CHECK. In release builds, this check is stripped, allowing a navigation to commit an origin that the process shouldn't have access to.

## Affected Files

- `content/browser/renderer_host/navigation_request.cc:9369-9373` — DCHECK-only origin access check

## Details

```cpp
// navigation_request.cc:9369-9373
// TODO(https://crbug.com/497761255): CHECK-exclusion: Convert to CHECK once
// we are sure this isn't hit.
DCHECK(policy->CanAccessOrigin(
    process_id, origin,
    ChildProcessSecurityPolicyImpl::AccessType::kCanCommitNewOrigin));
```

In release builds, this DCHECK is stripped. A compromised renderer (or an edge case) could navigate to and commit an origin that the ChildProcessSecurityPolicy should prevent.

## Attack Scenario

1. Compromised renderer navigates to a URL that resolves to a different origin
2. The DCHECK-only check means release Chrome doesn't verify origin access at commit
3. Navigation commits in a process that shouldn't have access to that origin
4. Process can now access data associated with the committed origin

## Impact

- **Requires compromised renderer or edge case**: The DCHECK suggests this may be hittable in normal scenarios
- **Origin isolation violation**: Process commits to unauthorized origin
- **Known TODO**: crbug.com/497761255 — explicitly says "convert to CHECK once we are sure"

## VRP Value

**Medium** — The DCHECK-only check indicates uncertainty about whether this is hit in production. If it can be hit without a compromised renderer, it's a site isolation bypass.

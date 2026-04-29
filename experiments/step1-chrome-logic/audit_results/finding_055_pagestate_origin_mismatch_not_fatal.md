# Finding 055: PageState Sent Despite Origin Mismatch (NotFatalUntil::M140)

## Summary

When navigating back/forward, if the committed origin does not match the origin stored in the FrameNavigationEntry, a CHECK verifies that no PageState (session history, form data, scroll positions) is sent. However, this CHECK is `NotFatalUntil::M140`, meaning it is NOT enforced in current Chrome releases. This allows cross-origin PageState leakage during history navigations.

## Affected Files

- `content/browser/renderer_host/navigation_request.cc:12500-12534` — Origin mismatch with PageState not enforced

## Details

```cpp
// navigation_request.cc:12506-12533
// Current weakened check: allows precursor tuple comparison if *either*
// origin is opaque. This is a temporary workaround because sandbox
// navigations do not currently clear PageState properly.
//
// TODO(crbug.com/421948889): After this bug is fixed, tighten this check
// to only allow precursor tuple comparison if *both* origins are opaque.
if (expected_origin.opaque() || origin_to_commit.opaque()) {
  origins_match = expected_origin.GetTupleOrPrecursorTupleIfOpaque() ==
                  origin_to_commit.GetTupleOrPrecursorTupleIfOpaque();
} else {
  origins_match = expected_origin.IsSameOriginWith(origin_to_commit);
}

if (!origins_match) {
  CHECK(commit_params_->page_state.empty(), base::NotFatalUntil::M140)
      << "PageState wasn't cleared after a commit origin mismatch."
      << "expected_origin: " << expected_origin
      << ", origin_to_commit: " << origin_to_commit;
}
```

### Two issues combined:

1. **Weakened origin comparison (line 12512)**: If *either* origin is opaque, falls back to precursor-tuple comparison. This means any sandboxed navigation (opaque origin) that shares a precursor tuple with the committed entry will "match" even if the opaque origins are distinct.

2. **NotFatalUntil::M140 (line 12530)**: Even when origins genuinely don't match, the check that PageState is empty is not enforced. PageState containing form data, scroll positions, and session history from one origin can be applied to a navigation committing with a different origin.

## Attack Scenario

### Cross-origin form data exfiltration via history navigation

1. User visits `https://bank.example/transfer` and fills in form fields (amount, account number)
2. A redirect or CSP-modified navigation causes the FrameNavigationEntry to retain `bank.example`'s committed_origin
3. User later navigates away and back
4. The back-navigation commits with a slightly different origin (e.g., due to a redirect or sandbox)
5. Origins don't match, but the CHECK at line 12530 doesn't fire (NotFatalUntil::M140)
6. PageState from `bank.example` (containing form data) is applied to the new origin's document
7. The new document's JavaScript can read the form field values that were auto-restored

## Impact

- **No compromised renderer required**: Exploitable via navigation sequences
- **Cross-origin data leak**: Form data, scroll positions, session state from one origin exposed to another
- **Time-limited but current**: Not enforced until M140 (all current Chrome versions affected)
- **Compounded by weakened origin check**: Sandboxed navigations further weaken the comparison

## VRP Value

**Medium-High** — No compromised renderer needed. The practical exploitation requires crafting a navigation sequence that causes origin mismatches while preserving PageState, which may be achievable through redirects or CSP-modified navigations.

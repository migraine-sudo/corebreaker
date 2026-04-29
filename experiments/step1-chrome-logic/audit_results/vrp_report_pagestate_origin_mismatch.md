# Chrome VRP Report: Cross-Origin PageState Leak via NotFatalUntil::M140 in ValidateCommitOrigin

## Summary

Chrome's `NavigationRequest::ValidateCommitOrigin` has a non-fatal CHECK (`NotFatalUntil::M140`) that allows PageState data to be sent to a frame committing with a mismatched origin. PageState can contain form data (including passwords), scroll positions, and document state. Combined with a weakened origin comparison (allowing opaque/non-opaque conflation), this creates a cross-origin data leak.

## Vulnerability Details

**Component:** `content/browser/renderer_host/navigation_request.cc`

### Issue 1: Non-fatal CHECK on PageState leak

```cpp
// navigation_request.cc:12530-12533
CHECK(commit_params_->page_state.empty(), base::NotFatalUntil::M140)
    << "PageState wasn't cleared after a commit origin mismatch."
    << "expected_origin: " << expected_origin
    << ", origin_to_commit: " << origin_to_commit;
```

The CHECK is `NotFatalUntil::M140`, meaning in current Chrome releases (before M140), when an origin mismatch occurs during navigation commit AND PageState is non-empty, the browser continues instead of crashing. The PageState — which can contain sensitive form data from a previous navigation to a different origin — is passed through to the new (potentially wrong) origin.

### Issue 2: Weakened origin comparison

```cpp
// navigation_request.cc:12506-12515
// Current weakened check: allows precursor tuple comparison if *either*
// origin is opaque. This is a temporary workaround...
if (expected_origin.opaque() || origin_to_commit.opaque()) {
    origins_match = expected_origin.GetTupleOrPrecursorTupleIfOpaque() ==
                    origin_to_commit.GetTupleOrPrecursorTupleIfOpaque();
}
```

If *either* origin is opaque, the comparison falls back to precursor tuple matching.

## Steps to Reproduce

### Scenario: PageState leak via redirect-induced origin mismatch

1. Navigate to `https://bank.com/transfer`, fill in form fields (amount, recipient)
2. Navigate away, then use browser Back to return to the bank page
3. If a redirect or CSP block during the history navigation changes the committing origin (crbug.com/420965165)
4. The CHECK at line 12530 logs but doesn't crash (NotFatalUntil::M140)
5. PageState from the bank page (containing form data) is delivered to the redirected page

### Expected Behavior

PageState should be cleared when origins don't match.

### Actual Behavior

PageState is NOT cleared; the CHECK is non-fatal; execution continues with leaked data.

## Impact

1. **Cross-Origin Data Leak**: PageState containing form data (potentially passwords) crosses origin boundaries
2. **No Compromised Renderer Required**: Triggered by navigation history patterns
3. **Known bugs**: crbug.com/420965165 (stale origin), crbug.com/421948889 (weakened comparison)

## Severity Assessment

**Medium-High** — Cross-origin PageState leak without compromised renderer.

## Suggested Fix

Clear PageState when origins don't match:
```cpp
if (!origins_match && !commit_params_->page_state.empty()) {
    commit_params_->page_state = blink::PageState();
}
```

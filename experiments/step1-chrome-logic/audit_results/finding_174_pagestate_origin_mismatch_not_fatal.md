# Finding 174: PageState Sent Despite Origin Mismatch (NotFatalUntil::M140)

## Summary

When a navigation commits with an origin that doesn't match the expected origin stored in FrameNavigationEntry, Chrome should prevent PageState from being sent. However, the CHECK that enforces this is marked `NotFatalUntil::M140`, meaning it doesn't crash in current release builds. Additionally, the origin comparison is weakened: if either origin is opaque, it falls back to precursor tuple comparison, which is explicitly described as a "temporary workaround."

## Affected Files

- `content/browser/renderer_host/navigation_request.cc:12490-12534` — ValidateCommitOrigin with weakened checks
- `content/browser/renderer_host/navigation_request.cc:12530` — NotFatalUntil::M140 CHECK

## Details

### 1. Weakened origin comparison

```cpp
// navigation_request.cc:12506-12515
// Current weakened check: allows precursor tuple comparison if *either*
// origin is opaque. This is a temporary workaround because sandbox
// navigations do not currently clear PageState properly.
if (expected_origin.opaque() || origin_to_commit.opaque()) {
    origins_match = expected_origin.GetTupleOrPrecursorTupleIfOpaque() ==
                    origin_to_commit.GetTupleOrPrecursorTupleIfOpaque();
} else {
    origins_match = expected_origin.IsSameOriginWith(origin_to_commit);
}
```

This means a sandboxed iframe (opaque origin) derived from `https://example.com` would match a non-sandboxed `https://example.com` origin, or any other opaque origin derived from the same precursor.

### 2. Non-fatal CHECK on PageState leak

```cpp
// navigation_request.cc:12530
CHECK(commit_params_->page_state.empty(), base::NotFatalUntil::M140)
    << "PageState wasn't cleared after a commit origin mismatch.";
```

When origin mismatch IS detected (even with the weakened comparison), the CHECK that PageState should be empty doesn't crash until M140. PageState contains:
- Form data (including passwords from `<input type="password">`)
- Scroll positions
- Document state
- Referenced file paths

## Attack Scenario

1. User navigates to `https://bank.com/transfer` and fills in a form (PageState captured)
2. The user navigates back/forward through session history
3. A redirect or CSP block changes the origin during the history navigation
4. Due to the stale FrameNavigationEntry (crbug.com/420965165), the expected origin doesn't match
5. The CHECK doesn't crash (NotFatalUntil::M140), so PageState containing the bank form data is sent to the new origin
6. The new page (potentially attacker-controlled) receives form data intended for `bank.com`

### Sandbox origin confusion variant

1. Page `https://attacker.com` embeds `<iframe sandbox="allow-scripts" src="https://victim.com">`
2. The sandboxed frame has an opaque origin with precursor `https://victim.com`
3. During history navigation, the weakened comparison treats this as matching `https://victim.com`
4. PageState from a prior `https://victim.com` navigation may be sent to the sandboxed attacker frame

## Impact

- **No compromised renderer required**: Triggered by navigation history manipulation
- **PageState data leak**: Form data, scroll positions, document state cross origin boundaries
- **Weakened origin comparison**: Opaque/non-opaque origins conflated via precursor tuples
- **Known issues**: crbug.com/420965165 (stale origin), crbug.com/421948889 (weakened comparison)

## VRP Value

**Medium-High** — Cross-origin PageState leak without compromised renderer. PageState can contain form data including credentials. The NotFatalUntil::M140 means this is actively exploitable in current Chrome versions. The weakened origin comparison adds a second vector through sandbox origin confusion.

# Finding 056: Cross-Origin about:srcdoc Navigation Not Blocked

## Summary

Cross-origin navigations to `about:srcdoc` are not blocked by the browser. The code has a TODO (crbug.com/40165505) acknowledging this should be unreachable, but currently only clears the `initiator_base_url` as a workaround instead of blocking the navigation.

## Affected Files

- `content/browser/renderer_host/navigation_request.cc:6701-6709` — Cross-origin about:srcdoc allowed

## Details

```cpp
// navigation_request.cc:6701-6709
if (GetURL().IsAboutSrcdoc() &&
    (!common_params().initiator_origin ||
     origin_to_commit.GetTupleOrPrecursorTupleIfOpaque() !=
         common_params()
             .initiator_origin->GetTupleOrPrecursorTupleIfOpaque())) {
  // TODO(crbug.com/40165505): Make this unreachable by blocking
  // cross-origin about:srcdoc navigations. Then enforce that the chosen
  // origin for srcdoc cases agrees with the parent frame's origin.
  common_params_->initiator_base_url = std::nullopt;
}
```

An `about:srcdoc` document inherits its content from the parent frame's `srcdoc` attribute. If a cross-origin page navigates a frame to `about:srcdoc`, the srcdoc content comes from the parent but the initiator origin is from a different origin. The code only clears the base URL but does NOT block the navigation.

## Attack Scenario

### Cross-origin content injection into srcdoc frames

1. Page A at `https://parent.example` has an iframe with `srcdoc="<sensitive content>"`
2. Page B at `https://attacker.example` has a reference to the iframe (e.g., via `window.open` + named targeting)
3. Page B navigates the iframe to `about:srcdoc` with its own initiator origin
4. The navigation is NOT blocked — only the base URL is cleared
5. The resulting document may have an inconsistent state: content from parent, initiator from attacker
6. This could affect origin-dependent behaviors like relative URL resolution, referrer policy, or security decisions

## Impact

- **No compromised renderer required**: Standard cross-origin navigation via frame targeting
- **Content/origin mismatch**: The srcdoc document may have inconsistent origin metadata
- **Known unfixed issue**: The TODO explicitly acknowledges this should be blocked

## VRP Value

**Medium** — The practical exploitation depends on what security decisions are affected by the origin/content mismatch. The clearing of `initiator_base_url` mitigates some attacks but doesn't address the fundamental issue.

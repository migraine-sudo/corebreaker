# Finding 101: Fenced Frame Top-Level Navigation Trusts Renderer-Supplied User Gesture

## Summary

When a fenced frame navigates the top-level window, the user activation check relies on a renderer-supplied `user_gesture` boolean instead of the browser's own source of truth. The browser's `HasTransientUserActivation()` has already been consumed by the time this check runs. A compromised renderer in a fenced frame can forge this value to navigate the top-level page without user interaction.

## Affected Files

- `content/browser/renderer_host/render_frame_host_impl.cc:1037-1053` — User gesture trusted from renderer

## Details

```cpp
// render_frame_host_impl.cc:1037-1053
// User activation is required, because fenced frames use the sandbox
// flag `allow-top-navigation-by-user-activation`.
// It would be better to instead check
// `render_frame_host->HasTransientUserActivation()`,
// but it has already been consumed at this point.
// TODO(crbug.com/40091540): use the browser's source of truth for user
// activation here (and elsewhere in this file) rather than trust the
// renderer.
if (!user_gesture) {
  // ... block navigation ...
  return false;
}
```

The `user_gesture` parameter comes from the renderer's IPC message, not from the browser's user activation tracking. A compromised renderer can always set this to `true`.

## Attack Scenario

1. Attacker runs an ad in a fenced frame (the standard use case for fenced frames)
2. The fenced frame's renderer is compromised (e.g., via memory corruption)
3. Compromised renderer sends top-level navigation IPC with `user_gesture=true`
4. Browser trusts the value because `HasTransientUserActivation()` was already consumed
5. Fenced frame navigates the top-level page to `https://phishing.com` without user interaction

### No-Compromise Variant (if any code path sets user_gesture incorrectly)

If any Blink-side code path sets the `user_gesture` flag incorrectly (e.g., from a timer or event handler that shouldn't count as user activation), this becomes exploitable without a compromised renderer.

## Impact

- **Requires compromised renderer (currently)**: The renderer must forge the `user_gesture` boolean
- **Top-level navigation hijack**: Fenced frame can navigate the top-level page
- **Phishing vector**: Navigate user to phishing page from an ad
- **Known issue**: crbug.com/40091540

## VRP Value

**Medium** — Requires compromised renderer, but the TODO explicitly acknowledges the trust-the-renderer problem. The fenced frame → top-level navigation is a high-value attack surface for ad-based attacks.

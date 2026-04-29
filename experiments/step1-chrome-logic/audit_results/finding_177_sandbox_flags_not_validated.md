# Finding 177: Renderer-Supplied Sandbox Flags Not Validated as Subset of Effective Flags

## Summary

When a renderer sends updated sandbox flags via `UpdateFramePolicyHeaders`, the browser does not verify that the new flags are a subset of the currently effective sandbox flags. This means a compromised renderer could potentially relax its own sandbox restrictions by sending weaker flags. The issue is tracked as crbug.com/740556.

## Affected Files

- `content/browser/renderer_host/browsing_context_state.cc:182-189` — Missing sandbox flags subset validation

## Details

```cpp
// browsing_context_state.cc:182-189
// TODO(iclelland): Kill the renderer if sandbox flags is not a subset of the
// currently effective sandbox flags from the frame. https://crbug.com/740556
network::mojom::WebSandboxFlags updated_flags =
    sandbox_flags | replication_state_->frame_policy.sandbox_flags;
if (replication_state_->active_sandbox_flags != updated_flags) {
    replication_state_->active_sandbox_flags = updated_flags;
    changed = true;
}
```

The code ORs the renderer-supplied `sandbox_flags` with the frame policy's sandbox flags. While ORing ensures flags can only be added (made more restrictive), the issue is that `sandbox_flags` comes from the renderer's `Content-Security-Policy: sandbox` header parsing. A compromised renderer could:

1. Claim the CSP sandbox directive is empty (no additional sandbox flags)
2. This would leave only `frame_policy.sandbox_flags` active
3. If the frame's CSP had additional sandbox restrictions beyond the iframe's `sandbox` attribute, those would be lost

The TODO indicates the renderer should be killed if it sends flags that aren't a superset of what the browser expects.

## Attack Scenario

1. Page embeds `<iframe sandbox="allow-scripts" src="https://attacker.com">`
2. `attacker.com` responds with `Content-Security-Policy: sandbox allow-scripts allow-popups allow-forms`
3. A compromised renderer ignores the CSP and sends empty sandbox flags
4. The browser ORs empty with `allow-scripts` from the iframe attribute
5. CSP-based sandbox restrictions (`allow-popups`, `allow-forms` being the ONLY allowed) are not enforced browser-side
6. The attacker's frame operates with fewer restrictions than intended

## Impact

- **Requires compromised renderer**: The renderer must lie about CSP sandbox flags
- **Sandbox relaxation**: CSP-specified sandbox restrictions can be bypassed
- **Long-standing issue**: crbug.com/740556 is an old bug
- **Defense-in-depth failure**: Browser should enforce sandbox flags independently of renderer

## VRP Value

**Low-Medium** — Requires compromised renderer. The ORing with frame policy flags limits the bypass to CSP-originated sandbox restrictions, not iframe attribute restrictions. Still a defense-in-depth gap.

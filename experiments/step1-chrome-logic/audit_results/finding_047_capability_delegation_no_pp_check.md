# Finding 047: Missing Permissions Policy Check in Capability Delegation via postMessage

## Summary

When delegating capabilities (payment, fullscreen, display-capture) via `postMessage`, there is no Permissions Policy check to verify the sender is allowed to use the capability being delegated. An iframe denied a capability by Permissions Policy can still delegate that capability to another window.

## Affected Files

- `third_party/blink/renderer/core/frame/dom_window.cc:1079` — Missing PP check TODO
- `third_party/blink/renderer/core/frame/dom_window.cc:1089` — Only user activation checked

## Details

### The TODO acknowledging the gap

```cpp
// dom_window.cc:1079
// TODO(mustaq): Add checks for allowed-to-use policy as proposed here:
// https://wicg.github.io/capability-delegation/spec.html#monkey-patch-to-html-initiating-delegation
```

When delegating capabilities, the only check is on user activation (line 1089), not on whether the sender frame is allowed to use the feature via Permissions Policy.

## Attack Scenario

### Payment capability escalation

1. Main page at `shop.example` embeds `<iframe src="tracker.example" allow="">`
   - The iframe has no granted permissions (empty allow attribute)
2. User clicks inside the `tracker.example` iframe (granting user activation)
3. `tracker.example` sends `postMessage({}, '*', {delegate: 'payment'})` to parent
4. Parent receives a payment capability delegation from an iframe that has no payment permission
5. Parent uses the delegated capability to trigger `PaymentRequest` 
6. The Permissions Policy restriction on the iframe is effectively bypassed

### Fullscreen delegation from restricted iframe

1. `<iframe src="untrusted.example" sandbox="allow-scripts">`
   - Sandboxed iframe without fullscreen permission
2. User interacts with the sandboxed iframe
3. Iframe delegates fullscreen capability to parent via postMessage
4. Parent enters fullscreen using the delegated capability
5. Sandbox restriction bypassed through delegation

## Impact

- **No compromised renderer required**: Standard JavaScript APIs
- **Permissions Policy bypass**: Capability delegation circumvents iframe restrictions
- **Spec violation**: The capability delegation spec requires permissions policy checks
- **Elevation of privilege**: Restricted iframes can grant capabilities they don't possess

## VRP Value

**Medium** — Standard web API exploitation. The capability delegation spec explicitly requires this check. Practical impact depends on whether the receiving window validates the delegation source.

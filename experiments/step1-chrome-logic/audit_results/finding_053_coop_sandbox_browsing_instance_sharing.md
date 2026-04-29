# Finding 053: COOP Does Not Account for Sandbox Flags — BrowsingInstance Sharing with Cross-Origin-Isolated Pages

## Summary

The Cross-Origin-Opener-Policy (COOP) status computation does not account for iframe sandbox flags. Two same-origin pages — one sandboxed (with an opaque origin) and one not — can end up in the same BrowsingInstance. A sandboxed page can inherit the cross-origin isolation status of its non-sandboxed counterpart, potentially gaining access to `SharedArrayBuffer` and high-resolution timers.

## Affected Files

- `content/browser/renderer_host/navigation_request.cc:11482-11496` — COOP ignores sandbox flags
- The crbug.com/415943168 acknowledges the issue

## Details

### The gap

```cpp
// navigation_request.cc:11482-11496
// TODO(crbug.com/415943168): Currently neither the
// CrossOriginOpenerPolicyStatus nor this function take sandbox flags into
// account, so it does not mandate a BrowsingInstance switch when navigating
// between two same-origin pages where one has sandbox flags that make its
// origin opaque.
```

### What this means

1. Page A at `https://example.com` sets COOP headers for cross-origin isolation
2. Page A is in a BrowsingInstance with `CrossOriginIsolated = true`
3. A sandboxed iframe navigates to `https://example.com` (same origin)
4. COOP does not require a BrowsingInstance switch (no sandbox flag check)
5. The sandboxed page ends up in the same BrowsingInstance
6. Sandboxed page inherits `CrossOriginIsolated` status

## Attack Scenario

### SharedArrayBuffer access from sandboxed context

1. Attacker controls `https://example.com/page.html` with `COOP: same-origin` + `COEP: require-corp`
2. This page gains cross-origin isolation → `SharedArrayBuffer` available
3. Attacker creates a sandboxed iframe to `https://example.com/sandbox.html`
4. The sandboxed frame should have an opaque origin and NOT be cross-origin isolated
5. Due to BrowsingInstance sharing, the sandboxed frame inherits COI status
6. Sandboxed frame can use `SharedArrayBuffer` for Spectre-type timing attacks
7. Since the sandboxed frame has weaker security properties, this creates an unexpected attack surface

## Impact

- **No compromised renderer required**: Exploitable via standard HTML
- **Cross-origin isolation bypass**: Sandboxed contexts gain COI capabilities
- **Spectre amplification**: `SharedArrayBuffer` available in unexpected contexts
- **High-resolution timers**: `performance.now()` granularity increased in sandboxed frames

## VRP Value

**Low-Medium** — Requires specific COOP/COEP configuration. Impact is that sandboxed frames gain capabilities they shouldn't have. The practical exploitation depends on whether the sandboxed context can perform meaningful Spectre attacks with the gained SharedArrayBuffer access.

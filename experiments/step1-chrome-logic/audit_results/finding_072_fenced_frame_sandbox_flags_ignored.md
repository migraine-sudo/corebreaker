# Finding 072: Fenced Frame Browser-Side Ignores Sandbox Flags From Embedder

## Summary

When a `<fencedframe>` element has sandbox attributes, the browser process silently ignores these flags. The `FencedFrame::DidChangeFramePolicy()` method explicitly overrides any sandbox flags sent by the renderer with the fixed `kFencedFrameForcedSandboxFlags` set. This means embedder-specified sandbox restrictions are never enforced at the browser level.

## Affected Files

- `content/browser/fenced_frame/fenced_frame.cc:379-392` — Sandbox flags overridden
- Known issue: `crbug.com/40233168`

## Details

```cpp
// fenced_frame.cc:379-392
void FencedFrame::DidChangeFramePolicy(const blink::FramePolicy& frame_policy) {
  // The sandbox flags sent from the renderer are currently ignored.
  blink::FramePolicy current_frame_policy = inner_delegate_frame_tree_node_
      ->pending_frame_policy();
  // Override with fixed sandbox flags
  current_frame_policy.sandbox_flags = 
      kFencedFrameForcedSandboxFlags;  // Fixed set, ignores embedder
}
```

The embedder might specify `<fencedframe sandbox="allow-scripts">` expecting no popups, no forms, no top navigation. But the browser applies only the hardcoded `kFencedFrameForcedSandboxFlags`, ignoring the embedder's restrictions.

## Attack Scenario

1. An embedder page adds `<fencedframe sandbox="">` (most restrictive sandbox)
2. The embedder expects the fenced frame content to be heavily restricted
3. The fenced frame content actually runs with `kFencedFrameForcedSandboxFlags` (which allows scripts, forms, popups)
4. The fenced frame content can perform actions the embedder tried to prevent

## Impact

- **No compromised renderer required**: Browser-side logic gap
- **Sandbox bypass**: Embedder's security expectations not enforced
- **Known issue**: crbug.com/40233168

## VRP Value

**Low-Medium** — Known issue, but embedder sandbox expectations are completely ignored.

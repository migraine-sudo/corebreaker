# Finding 106: Renderer-Supplied allow_popup Flag Can Bypass Popup Blocking

## Summary

The `CreateNewWindow` handler in RenderFrameHostImpl receives an `allow_popup` flag from the renderer via Mojo IPC. When set to true, it enables a code path that can treat the popup request as if it had transient user activation, potentially bypassing popup blocking. Impact depends on embedder's `IsPopupBypassAllowed` implementation.

## Affected Files

- `content/browser/renderer_host/render_frame_host_impl.cc:10248-10258` — allow_popup handling

## Details

```cpp
// render_frame_host_impl.cc:10248-10258
if (!effective_transient_activation_state && params->allow_popup) {
    bool bypass_allowed =
        GetContentClient()->browser()->IsPopupBypassAllowed(this);
    // ...
    if (bypass_allowed) {
      effective_transient_activation_state = true;
    }
}
```

The `allow_popup` flag comes directly from the renderer via `CreateNewWindowParams`. While Chrome's default `IsPopupBypassAllowed` implementation returns false (limited to extensions), other Chromium embedders (WebView, WebLayer, Electron) may return true, making this exploitable.

## Attack Scenario

1. Compromised renderer in a Chromium-based browser (WebView, Electron app, etc.)
2. Sets `allow_popup=true` in CreateNewWindowParams
3. Embedder's `IsPopupBypassAllowed` returns true
4. Browser treats the popup as user-initiated, bypassing popup blocker
5. Popup opens without user interaction

## Impact

- **Requires compromised renderer**: Yes
- **Embedder-dependent**: Chrome itself has a restrictive gate, but WebView/Electron may not
- **Popup blocking bypass**: Open popups without user interaction

## VRP Value

**Medium** — Embedder-dependent impact. Most dangerous in WebView and Electron contexts where `IsPopupBypassAllowed` may be more permissive.

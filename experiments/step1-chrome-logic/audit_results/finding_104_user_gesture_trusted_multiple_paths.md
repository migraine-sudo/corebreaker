# Finding 104: Renderer-Supplied user_gesture Trusted in Multiple Security-Gating Decisions

## Summary

Multiple security-critical code paths in `render_frame_host_impl.cc` trust a renderer-supplied `has_user_gesture` or `user_gesture` boolean without browser-side verification. This enables a compromised renderer to bypass popup blocking, override ongoing navigations, and register protocol handlers without user interaction.

## Affected Files

- `content/browser/renderer_host/render_frame_host_impl.cc:8801-8826` — GoToEntryAtOffset
- `content/browser/renderer_host/render_frame_host_impl.cc:8587-8596` — RegisterProtocolHandler
- `content/browser/renderer_host/navigation_request.cc:4834` — was_activated propagation

## Details

### GoToEntryAtOffset
```cpp
void RenderFrameHostImpl::GoToEntryAtOffset(int32_t offset, bool has_user_gesture, ...) {
  if (Navigator::ShouldIgnoreIncomingRendererRequest(
        frame_tree_->root()->navigation_request(), has_user_gesture)) {
    return;  // Only ignored if has_user_gesture is false
  }
  // ... proceeds to navigate history
}
```

### RegisterProtocolHandler
```cpp
void RenderFrameHostImpl::RegisterProtocolHandler(const std::string& scheme,
                                                  const GURL& url,
                                                  bool user_gesture) {
  delegate_->RegisterProtocolHandler(this, scheme, url, user_gesture);
}
```

### Same-Document Navigation Activation
```cpp
bool started_with_transient_activation =
    (is_same_document_navigation &&
     same_document_params->started_with_transient_activation);
```

## Attack Scenario

1. Compromised renderer sets `has_user_gesture=true` in GoToEntryAtOffset IPC
2. Browser allows history navigation that would otherwise be blocked (overriding ongoing browser-initiated navigation)
3. OR: Renderer sets `user_gesture=true` in RegisterProtocolHandler to register `mailto:`, `tel:`, etc. handlers
4. OR: Renderer sets `started_with_transient_activation=true` for same-document navigations to appear user-initiated

## Impact

- **Requires compromised renderer**: Yes
- **Navigation override**: Can override browser-initiated navigations
- **Protocol handler hijack**: Register handlers for mailto:, tel:, web+* schemes
- **History manipulation**: Manipulate history navigation with forged activation state

## VRP Value

**Medium-High** — Multiple attack vectors from a single trust-the-renderer pattern. Protocol handler registration is particularly concerning for phishing.

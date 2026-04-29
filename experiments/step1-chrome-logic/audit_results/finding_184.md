# Finding 184: WebView-to-Extension Messaging Restricts Only Receiver but Not Content of Messages

## Summary
The extension messaging system restricts WebView-to-extension messaging to only component extensions (checking `Manifest::IsComponentLocation`). However, this check only controls whether the WebView can initiate a connection -- once the connection is established, there are no restrictions on message content or frequency. Additionally, the WebView guest process information is passed through to component extensions, which could be used to fingerprint or identify the guest process. The TODO at line 1004 acknowledges that `<webview>` service worker messaging is not investigated.

## Affected Files
- `extensions/browser/api/messaging/message_service.cc` (lines 615-625, 1000-1012)

## Details

WebView-to-extension connection check:
```cpp
#if BUILDFLAG(ENABLE_GUEST_VIEW)
    // Check to see if it was a WebView making the request.
    // Sending messages from WebViews to extensions breaks webview isolation,
    // so only allow component extensions to receive messages from WebViews.
    bool is_web_view =
        !!WebViewGuest::FromRenderFrameHost(source_render_frame_host);
    if (is_web_view &&
        Manifest::IsComponentLocation(target_extension->location())) {
      include_guest_process_info = true;
    }
#endif
```

Guest process info forwarded:
```cpp
#if BUILDFLAG(ENABLE_GUEST_VIEW)
  if (params->include_guest_process_info &&
      // TODO(lazyboy): Investigate <webview> SW messaging.
      source.is_for_render_frame()) {
    guest_process_id = params->source.render_process_id();
    DCHECK(port_context.frame);
    guest_render_frame_routing_id = port_context.frame->routing_id;

    DCHECK(WebViewGuest::FromRenderFrameHost(source.GetRenderFrameHost()));
  }
#endif
```

Issues:
1. The check is only `if (is_web_view && IsComponentLocation(...))` with `include_guest_process_info = true`. If the target extension is NOT a component extension and the source is a WebView, the code simply doesn't set `include_guest_process_info`. But the connection still proceeds because the general `externally_connectable` check may allow it. The WebView isolation is only about whether `include_guest_process_info` is set, not about blocking the connection itself.

2. The `<webview>` service worker messaging path is explicitly uninvestigated (TODO at line 1004). A WebView guest that has a service worker could potentially bypass the frame-based WebView check entirely.

3. The `guest_process_id` and `guest_render_frame_routing_id` are forwarded as process-level identifiers, which could be used by a component extension (or a compromised one) to identify and target specific WebView guest processes.

## Attack Scenario
1. An extension uses `<webview>` to embed a web page.
2. The embedded web page within the WebView has its own extension messaging capability (via `externally_connectable` on the hosting extension).
3. The WebView guest, if it has a service worker, could send messages that bypass the `is_web_view` check because the TODO indicates service worker messaging for WebViews is not investigated.
4. For component extensions: the guest process ID and routing ID are forwarded, allowing the component extension to identify which WebView instance sent the message. If a compromised component extension exists, it could use these IDs to target specific renderer processes.

## Impact
Low-Medium. The primary concern is the uninvestigated SW messaging path for WebViews and the forwarding of process-level identifiers to component extensions. The WebView isolation restriction is a partial defense that can be bypassed through the service worker path.

## VRP Value
Low

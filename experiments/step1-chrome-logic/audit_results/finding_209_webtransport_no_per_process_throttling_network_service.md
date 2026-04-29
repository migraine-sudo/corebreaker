# Finding 209: WebTransport Lacks Per-Process Throttling at Network Service Layer (Asymmetry with WebSocket)

## Summary

WebSocket connections are throttled per-renderer-process in the network service via `WebSocketThrottler`, which limits pending connections to 255 per process and adds exponential backoff delays for failing connections. WebTransport has NO per-process throttling at the network service layer. The only throttling is per-page (64 pending sessions) in the browser process, and for SharedWorker/ServiceWorker contexts, it falls back to per-PROFILE throttling.

A malicious website using ServiceWorkers could potentially open large numbers of WebTransport sessions that all share a single per-profile throttle context, creating a more effective network-level DoS compared to WebSocket.

## Affected Files

- `services/network/network_context.cc` lines 2094-2119:
  - `CreateWebTransport` has no throttling or per-process limits
  - Contrast with `CreateWebSocket` which goes through `WebSocketFactory` with `WebSocketThrottler`
- `content/browser/webtransport/web_transport_connector_impl.cc` lines 45-62:
  - SharedWorker/ServiceWorker uses per-profile throttle, not per-process
  ```cpp
  } else {
    // This is either a SharedWorker or a ServiceWorker. Use per-profile
    // throttling.
    auto* browser_context = process->GetBrowserContext();
    return GetThrottleContextFromUserData(browser_context);
  }
  ```
- `content/browser/webtransport/web_transport_throttle_context.h` line 68:
  - `kMaxPendingSessions = 64` (per-page for frames, per-profile for workers)
- `services/network/websocket_throttler.h` line 107:
  - WebSocket: `kMaxPendingWebSocketConnections = 255` (per-process)

## Code Snippet

```cpp
// content/browser/webtransport/web_transport_connector_impl.cc:45-62
base::WeakPtr<WebTransportThrottleContext> GetThrottleContext(
    int process_id,
    base::WeakPtr<RenderFrameHostImpl> frame) {
  if (frame) {
    // Per-page throttling for frames
    auto& page = frame->GetPage();
    return GetThrottleContextFromUserData(&page);
  } else {
    // Per-PROFILE throttling for SharedWorker/ServiceWorker
    // This is much weaker - ALL workers in the profile share one bucket
    auto* browser_context = process->GetBrowserContext();
    return GetThrottleContextFromUserData(browser_context);
  }
}
```

## Attack Scenario

1. Attacker registers a ServiceWorker on their origin
2. The ServiceWorker creates WebTransport connections -- these are throttled per-profile with a limit of 64 pending
3. Attacker opens multiple tabs/windows to the same origin, each creating a ServiceWorker
4. All ServiceWorkers share the same per-profile throttle context, so the aggregate limit is 64
5. However, unlike WebSocket (which has process-level throttling in the network service), once a WebTransport session is established, it is not counted against any limit in the network service
6. Each established session can create an unlimited number of bidirectional/unidirectional streams
7. This allows resource exhaustion at the network layer with significantly less throttling than equivalent WebSocket connections

Additionally, browser-process throttling for WebTransport bypasses the `--webtransport-developer-mode` command-line flag:
```cpp
bool ShouldQueueHandshakeFailurePenalty() {
  return !command_line->HasSwitch(switches::kWebTransportDeveloperMode);
}
```

## Impact

- **Severity**: Medium (resource exhaustion / DoS asymmetry)
- **Requires compromised renderer**: No -- standard web API usage
- **Security principle violated**: Protocol-level throttling inconsistency
- ServiceWorker-based attack is especially concerning as ServiceWorkers persist
- No per-process limit at the network service layer means established connections are unbounded

## VRP Value Rating

Medium - The per-process throttling gap between WebSocket and WebTransport is a design inconsistency that could enable more effective DoS attacks. Chrome VRP values DoS findings that demonstrate meaningful resource exhaustion from standard web content.

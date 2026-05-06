# Round 3: WebTransport & WebSocket Origin/URL Validation Audit

## Audit Scope
- WebTransport URL validation (renderer + browser + network service)
- WebSocket handshake origin handling
- Mixed content checks for WS/WT
- Private Network Access (PNA/LNA) enforcement
- Extension interaction with Origin header
- Worker origin propagation

---

## 1. WebTransport URL Validation

### Analysis

**Renderer side** (`third_party/blink/renderer/modules/webtransport/web_transport.cc`, `Init()` at line 1385):
- Validates URL is valid (line 1397)
- Enforces `https` scheme only (line 1406): `if (!url_.ProtocolIs("https"))` -- rejects anything else
- Rejects fragment identifiers (line 1414)
- Checks CSP `connect-src` via `AllowConnectToSource` (line 1427)
- Checks SubresourceFilter (line 1516)

**Browser side** (`content/browser/webtransport/web_transport_connector_impl.cc`):
- `WebTransportConnectorImpl` is created with `last_committed_origin_` from the RenderFrameHost (line 14899)
- Origin is stored as `origin_` and passed to `NetworkContext::CreateWebTransport` (line 308)
- `ClientSecurityState` is passed through for PNA checks

**Network service** (`services/network/network_context.cc`, line 2094):
- `CreateWebTransport` creates a `WebTransport` object, passing `origin` directly
- Origin is stored in `origin_` (line 448) and used for PNA checks (line 626)

### Finding: NO explicit localhost/127.0.0.1 blocking for WebTransport

The WebTransport constructor only checks `url_.ProtocolIs("https")`. There is **no explicit check** that prevents `https://localhost` or `https://127.0.0.1` connections. This means:

- A web page at `https://attacker.com` CAN attempt `new WebTransport("https://localhost:4433")`.
- The connection will proceed to the network service.
- **PNA (Local Network Access) is the defense**, but it is behind a feature flag: `kLocalNetworkAccessChecksWebTransport` (enabled by default at `services/network/public/cpp/features.cc:281`).

The PNA check happens in `WebTransport::OnLocalNetworkAccessCheck()` (line 610 of `services/network/web_transport.cc`). If the feature flag is disabled, the check is **entirely skipped** (line 614-617):
```cpp
if (!base::FeatureList::IsEnabled(
        features::kLocalNetworkAccessChecksWebTransport)) {
  std::move(callback).Run(net::OK);
  return;
}
```

**Severity**: Low-Medium. When PNA is enabled (default), connections to local addresses require user permission. But if PNA is disabled via enterprise policy or feature flag, WebTransport provides a direct SSRF vector to localhost over QUIC/HTTP3 (port 443/custom). This is by design but worth noting that WebTransport's HTTPS-only requirement means localhost needs a valid TLS cert to respond, limiting practical exploitation.

---

## 2. WebSocket Handshake Origin Header

### Analysis

**Origin setting** (`net/websockets/websocket_stream.cc`, line 130):
```cpp
headers.SetHeader(HttpRequestHeaders::kOrigin, origin.Serialize());
```
The Origin header is set from the `origin` parameter passed through the entire chain:
1. `RenderFrameHostImpl::CreateWebSocketConnector` passes `last_committed_origin_` (line 14889)
2. `WebSocketConnectorImpl` stores it as `origin_` (line 71)
3. Passed to `CreateWebSocket` on the network context (line 127)
4. Stored in `WebSocket::origin_` (line 535)
5. Passed to `WebSocketChannel::SendAddChannelRequest` (line 751)
6. Eventually set as the `Origin` header

The origin flows from the browser process's `last_committed_origin_`, which is controlled by the browser, not the renderer. A compromised renderer cannot spoof it.

### Finding: Extension WebRequest API CAN modify the Origin header on WebSocket handshakes

**File**: `extensions/browser/api/web_request/web_request_api_helpers.cc`, line 1817-1826

The `ShouldHideRequestHeader` function hides the "origin" header from extensions **unless** the extension specifies `extraHeaders`:
```cpp
bool ShouldHideRequestHeader(...) {
  static constexpr auto kRequestHeaders =
      base::MakeFixedFlatSet<std::string_view>({"accept-encoding",
                                                "accept-language", "cookie",
                                                "origin", "referer"});
  return !(extra_info_spec & ExtraInfoSpec::EXTRA_HEADERS) &&
         kRequestHeaders.contains(base::ToLowerASCII(name));
}
```

When an extension uses `extraHeaders`, it can:
1. See the Origin header
2. Modify it via `onBeforeSendHeaders`
3. The modified headers flow through the `TrustedHeaderClient` path in `WebSocket::OnBeforeSendHeadersComplete` (line 1020), which passes them directly to the network stack without re-validation

The `additional_headers` path (non-TrustedHeaderClient) is filtered by `IsSafeHeader` which blocks "origin" (line 341 of `net/http/http_util.cc`). BUT the `TrustedHeaderClient` path bypasses this filter entirely.

**This is by design** -- extensions with `webRequest` + `extraHeaders` are considered trusted. However, a malicious extension or an extension with a XSS vulnerability could spoof the Origin header on WebSocket connections to any server.

**Severity**: Medium (by design, but worth documenting). A content script in an extension's isolated world cannot directly do this -- it requires background page/service worker with `webRequest` + `extraHeaders` permissions.

### Finding: Additional headers filtering gap in WebSocket

**File**: `services/network/websocket.cc`, lines 738-750

The `AddChannel` method filters `additional_headers` using `IsSafeHeader`, which blocks "origin". However, it explicitly **allows**:
- `User-Agent`
- `Cookie`
- `cookie2`

These are in the forbidden headers list but whitelisted for WebSocket. The `Cookie` allowance is expected (WebSocket sends cookies), but `User-Agent` being allowed through `additional_headers` means any Mojo caller (including a compromised renderer) can spoof the User-Agent on WebSocket connections. This is low severity since User-Agent is not security-sensitive in the same way Origin is.

---

## 3. WebTransport CORS Model / Origin Handling

### Analysis

WebTransport does NOT use CORS. Instead:
- The browser sends the `:origin` pseudo-header in the CONNECT request
- The server decides whether to accept based on this origin

**Origin propagation**:
- For frames: `last_committed_origin_` from RenderFrameHostImpl (line 14899)
- For DedicatedWorkers: `GetWorkerStorageKey().origin()` (line 816 of `dedicated_worker_host.cc`)
- For SharedWorkers: `GetWorkerStorageKey().origin()` (line 676 of `shared_worker_host.cc`)
- For ServiceWorkers: `version_->key().origin()` (line 94 of `service_worker_host.cc`)

All origins come from browser-process state, not from the renderer.

### Finding: WebTransport extension proxy does NOT expose Origin header

**File**: `extensions/browser/api/web_request/web_request_proxying_webtransport.cc`, lines 32-45

The `GetRequestHeaders()` function explicitly does NOT include the "origin" header:
```cpp
// We don't attach the "origin" header, to be aligned with the usual
// loading case. Extension authors can use the "initiator" property to
// observe it.
```

This means extensions **cannot** modify the `:origin` pseudo-header on WebTransport connections. This is more secure than the WebSocket path.

### Finding: No scenario found where browser sends wrong or missing origin for WebTransport

The origin is always set from browser-side state. The renderer has no influence on it via Mojo. The `WebTransportConnectorImpl` stores the origin at construction time and uses it immutably. No race conditions or TOCTOU issues found.

---

## 4. Mixed Content for WebSocket/WebTransport

### WebSocket Mixed Content

**File**: `third_party/blink/renderer/modules/websockets/websocket_common.cc`, lines 54-67

WebSocket has upgrade-insecure-requests support:
```cpp
if (upgrade_insecure_requests_set && url_.Protocol() == "ws" &&
    !network::IsUrlPotentiallyTrustworthy(GURL(url_))) {
  url_.SetProtocol("wss");
  if (url_.Port() == 80)
    url_.SetPort(443);
}
```

Mixed content is checked in `websocket_channel_impl.cc`:
1. `ShouldBlockWebSocketByMixedContentCheck(url)` (line 287) -- blocks if mixed content
2. `MixedContentChecker::IsMixedContent(origin, url)` (line 309) -- logs a warning for deprecation

**Finding: WebSocket mixed content correctly blocks ws:// from https:// pages** when `upgrade-insecure-requests` is not set. When it IS set, ws:// is automatically upgraded to wss://. This is correct behavior.

However, there is a **known deprecation warning** at line 311-312:
```
"Connecting to a non-secure WebSocket server from a secure origin is deprecated."
```
This message fires even when the connection is later blocked, which is cosmetic but not a vulnerability.

### WebTransport Mixed Content

WebTransport enforces `https`-only at the renderer level (line 1406):
```cpp
if (!url_.ProtocolIs("https")) { /* reject */ }
```

WebTransport runs over QUIC (HTTP/3), which is inherently TLS. There is no `wt://` or insecure variant. **No mixed content bypass is possible for WebTransport.**

---

## 5. Dedicated Worker + WebTransport Origin

### Analysis

**File**: `content/browser/worker_host/dedicated_worker_host.cc`, lines 802-819

When a DedicatedWorker creates a WebTransport:
```cpp
mojo::MakeSelfOwnedReceiver(std::make_unique<WebTransportConnectorImpl>(
    worker_process_host_->GetDeprecatedID(),
    ancestor_render_frame_host->GetWeakPtr(),
    GetWorkerStorageKey().origin(),   // <-- origin from worker's storage key
    isolation_info_.network_anonymization_key(),
    worker_client_security_state_->Clone()),
```

The origin sent is `GetWorkerStorageKey().origin()`, which is the **worker's own origin** (derived from the script URL, NOT the creator page's origin).

For a same-origin worker, this is the same as the creator's origin.

### Finding: Cross-origin iframe + DedicatedWorker origin is correct

If a cross-origin iframe at `https://b.com` creates a DedicatedWorker, the worker's storage key origin will be `https://b.com`. The WebTransport connection from that worker will send `:origin: https://b.com`, which is correct.

The `ancestor_render_frame_host` is used for throttling (page-level) and DevTools, but does NOT influence the origin. The security state also comes from the worker, not the ancestor frame.

**No vulnerability found here.**

---

## 6. Content Script WebSocket Origin

### Analysis

**File**: `third_party/blink/renderer/modules/websockets/websocket_channel_impl.cc`, lines 379-397

When a content script (isolated world) creates a WebSocket:
```cpp
scoped_refptr<const SecurityOrigin> isolated_security_origin;
const DOMWrapperWorld* world = execution_context_->GetCurrentWorld();
if (world && world->IsIsolatedWorld()) {
  isolated_security_origin = world->IsolatedWorldSecurityOrigin(
      execution_context_->GetAgentClusterID());
}
```

The `isolated_security_origin` is passed to the `handshake_throttle_->ThrottleHandshake()` for the SafeBrowsing/throttle check. However, the **actual origin used for the WebSocket connection** comes from the browser side:

In `RenderFrameHostImpl::CreateWebSocketConnector` (line 14884-14892):
```cpp
mojo::MakeSelfOwnedReceiver(
    std::make_unique<WebSocketConnectorImpl>(
        GlobalRenderFrameHostId(GetProcess()->GetID(), routing_id_),
        last_committed_origin_,   // <-- page's origin, not extension's
        isolation_info_, BuildClientSecurityState(),
        GetNetworkRestrictionsID()),
```

### Finding: Content script WebSocket sends the PAGE's origin, not the extension's

When a Chrome extension content script creates a WebSocket via `new WebSocket("wss://server.example")`, the `Origin` header in the WebSocket handshake will be the **page's origin** (e.g., `https://victim.com`), NOT the extension's origin (`chrome-extension://...`).

This is by design -- content scripts execute in the page's context (albeit an isolated world), and their network requests carry the page's origin. However, this creates an **origin laundering** scenario:

1. Extension content script on `https://bank.com` creates `new WebSocket("wss://extension-server.com")`
2. The WebSocket handshake sends `Origin: https://bank.com`
3. `extension-server.com` receives a request appearing to come from `bank.com`
4. If `extension-server.com` trusts requests from `bank.com` (e.g., allowlists the origin), the extension can abuse this

**Severity**: Low. This is known/by-design behavior. Server-side origin validation for WebSocket should not be the sole authentication mechanism. Extensions that need WebSocket connections should use the background page/service worker, which sends the extension's own origin.

However, note that for the **TrustedHeaderClient path** (when extensions use `webRequest` + `extraHeaders`), an extension's background page CAN modify the Origin header to arbitrary values as discussed in Finding 2 above.

---

## 7. CSP connect-src Enforcement

### WebSocket CSP

**File**: `third_party/blink/renderer/modules/websockets/websocket_common.cc`, lines 97-98
```cpp
if (!execution_context->GetContentSecurityPolicyForCurrentWorld()
         ->AllowConnectToSource(url_, url_, RedirectStatus::kNoRedirect)) {
```

WebSocket correctly checks CSP `connect-src` before initiating the connection. Uses `GetContentSecurityPolicyForCurrentWorld()`, which respects isolated world CSP (relevant for content scripts).

### WebTransport CSP

**File**: `third_party/blink/renderer/modules/webtransport/web_transport.cc`, lines 1427-1443
```cpp
if (!execution_context->GetContentSecurityPolicyForCurrentWorld()
         ->AllowConnectToSource(url_, url_, RedirectStatus::kNoRedirect)) {
```

WebTransport also correctly checks CSP `connect-src`.

**Both WebSocket and WebTransport correctly enforce CSP connect-src. No bypass found.**

---

## 8. PNA/LNA Feature Flag Analysis

### Current State

Both feature flags are **ENABLED BY DEFAULT**:

```cpp
// services/network/public/cpp/features.cc:273
BASE_FEATURE(kLocalNetworkAccessChecksWebSockets,
             base::FEATURE_ENABLED_BY_DEFAULT);

// services/network/public/cpp/features.cc:281
BASE_FEATURE(kLocalNetworkAccessChecksWebTransport,
             base::FEATURE_ENABLED_BY_DEFAULT);
```

### WebSocket PNA Check

**File**: `services/network/websocket.cc`, lines 222-296

The `OnURLRequestConnected` handler checks PNA. If the feature is disabled:
```cpp
if (!base::FeatureList::IsEnabled(
        features::kLocalNetworkAccessChecksWebSockets)) {
  return net::OK;  // Skip all checks
}
```

### WebTransport PNA Check

**File**: `services/network/web_transport.cc`, lines 610-683

The `OnLocalNetworkAccessCheck` handler. Same pattern -- if disabled, all checks are skipped.

### Finding: PNA checks can be disabled via enterprise policy or command-line flags

Since these are `BASE_FEATURE` flags, they can be disabled via:
- `--disable-features=LocalNetworkAccessChecksWebSockets,LocalNetworkAccessChecksWebTransport`
- Enterprise policy `DisableFeatures`

When disabled, both WebSocket and WebTransport can freely connect to local network addresses without any PNA prompt.

**Severity**: Low (enterprise configuration issue, not a vulnerability in the code itself).

---

## Summary of Findings

| # | Finding | Severity | Type |
|---|---------|----------|------|
| 1 | WebTransport allows `https://localhost` connections (PNA is the only defense, feature-flag gated) | Low-Medium | Design observation |
| 2 | Extension WebRequest API with `extraHeaders` can modify WebSocket Origin header via TrustedHeaderClient path | Medium | By design |
| 3 | WebTransport extension proxy correctly does NOT expose Origin header | N/A | Positive finding |
| 4 | No mixed content bypass for WebTransport (https-only enforced) | N/A | Positive finding |
| 5 | DedicatedWorker WebTransport correctly sends worker's own origin | N/A | Positive finding |
| 6 | Content script WebSocket sends page's origin, enabling origin laundering | Low | By design |
| 7 | CSP connect-src correctly enforced for both WebSocket and WebTransport | N/A | Positive finding |
| 8 | PNA checks can be completely disabled via feature flags | Low | Configuration |

### No exploitable bugs found

The WebTransport and WebSocket implementations in Chromium are well-designed with defense-in-depth:
- Origins are always set from browser-process state (not renderer-controllable)
- CSP connect-src is enforced for both protocols
- Mixed content is blocked/upgraded for WebSocket, and WebTransport is inherently HTTPS-only
- PNA/LNA checks are enabled by default for both protocols
- Extension header modification through TrustedHeaderClient is intentional and requires explicit `extraHeaders` permission

The most interesting observation is Finding #2 (extension Origin spoofing on WebSocket via TrustedHeaderClient), but this is intentional design given that extensions with `webRequest` + `extraHeaders` are fully trusted.

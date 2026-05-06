# Finding: Port Message Injection via Predictable Channel Identifiers

## Summary

Safari's WebKit Web Extension port messaging system (`PortPostMessage`) validates port connections using only the channel identifier and world types, without verifying that the sender actually owns the port. Combined with predictable sequential `ObjectIdentifier` channel IDs, a content script in one tab can inject messages into another tab's port channel to the background page.

## Severity

**Medium** (requires XSS into content script of the same extension, no renderer compromise needed)

## Affected Code

- **Port message handler**: `UIProcess/Extensions/Cocoa/API/WebExtensionContextAPIPortCocoa.mm`
  - `portPostMessage()` (line 44-67)
  - `isPortConnected()` (line 174-190)
- **IPC definition**: `UIProcess/Extensions/WebExtensionContext.messages.in` (line 119)
- **Channel ID type**: `Shared/Extensions/WebExtensionPortChannelIdentifier.h`

## Root Cause

### 1. No Port Ownership Verification

`portPostMessage` validates the port connection exists but NOT that the caller owns it:

```cpp
void WebExtensionContext::portPostMessage(WebExtensionContentWorldType sourceContentWorldType,
    WebExtensionContentWorldType targetContentWorldType,
    std::optional<WebPageProxyIdentifier> sendingPageProxyIdentifier,
    WebExtensionPortChannelIdentifier channelIdentifier,
    const String& messageJSON, bool userGesture)
{
    if (!isPortConnected(sourceContentWorldType, targetContentWorldType, channelIdentifier)) {
        // Queue message
        return;
    }
    firePortMessageEventsIfNeeded(targetContentWorldType, sendingPageProxyIdentifier, channelIdentifier, messageJSON, resolvedUserGesture);
}
```

`isPortConnected` only checks that the port counts exist in `m_ports`:
```cpp
bool WebExtensionContext::isPortConnected(WebExtensionContentWorldType sourceContentWorldType,
    WebExtensionContentWorldType targetContentWorldType,
    WebExtensionPortChannelIdentifier channelIdentifier)
{
    const auto sourceWorldCount = openPortCount(sourceContentWorldType, channelIdentifier);
    const auto targetWorldCount = openPortCount(targetContentWorldType, channelIdentifier);
    return sourceWorldCount && targetWorldCount;
}
```

`openPortCount` checks `m_ports.count({worldType, channelID})` — a global counter, not per-sender.

### 2. Predictable Channel Identifiers

```cpp
// WebExtensionPortChannelIdentifier.h
struct WebExtensionPortChannelIdentifierType;
using WebExtensionPortChannelIdentifier = ObjectIdentifier<WebExtensionPortChannelIdentifierType>;
```

`ObjectIdentifier` is a sequential 64-bit integer. Channel IDs are N, N+1, N+2... fully predictable.

### 3. No IPC Sender Binding

The IPC message definition allows any content script to specify any channel ID:
```
[Validator=isLoaded] PortPostMessage(sourceContentWorldType, targetContentWorldType, sendingPageProxyIdentifier, channelIdentifier, messageJSON, userGesture)
```

## Attack Scenario

1. Victim extension uses `runtime.connect()` for content script ↔ background communication
2. Tab A (content script) connects to background → gets channelID = 42
3. Attacker achieves XSS on a page where the extension's content script runs (Tab B)
4. Attacker calls `runtime.connect()` from Tab B → gets channelID = 43
5. Attacker now knows Tab A's channel is likely 42 (or enumerates nearby values)
6. Attacker sends IPC: `PortPostMessage(ContentScript, Main, tabB_pageProxyID, 42, malicious_json, false)`
7. UIProcess checks `isPortConnected(ContentScript, Main, 42)`:
   - `openPortCount(ContentScript, 42)` = 1 (Tab A's port) ✓
   - `openPortCount(Main, 42)` = 1 (background's port) ✓
   - Returns true!
8. Message delivered to background page's `port.onMessage` handler
9. Background page processes the injected message as if it came from Tab A

## Impact

- **Cross-tab message injection**: A compromised content script in one tab can inject messages into port connections established by other tabs
- **Background page confusion**: The background page cannot distinguish injected messages from legitimate ones
- **Privilege escalation potential**: If the background page performs privileged operations based on port messages (script injection, API calls, data access), the attacker inherits those capabilities
- **No renderer compromise required**: Only requires XSS into any page where the target extension's content script runs

## Constraints

- Attacker must be in the same extension's content script context (via XSS on a matching page)
- Target extension must use `runtime.connect()` (not just `runtime.sendMessage()`)
- Attacker needs to enumerate/predict the target channelID (feasible due to sequential allocation)
- Messages go through the extension's own context only (no cross-extension injection)

## Recommended Fix

Add port ownership verification in `portPostMessage`:

```cpp
void WebExtensionContext::portPostMessage(...) {
    // Verify the sender actually owns a port on this channel
    auto& pagePorts = m_pagePortMap.get(sendingPageProxyIdentifier.value_or(WebPageProxyIdentifier()));
    if (!pagePorts.contains({sourceContentWorldType, targetContentWorldType, channelIdentifier})) {
        // Sender doesn't own this port - reject
        return;
    }
    
    if (!isPortConnected(sourceContentWorldType, targetContentWorldType, channelIdentifier))
        // ... queue as before
    
    firePortMessageEventsIfNeeded(...);
}
```

Alternatively, use cryptographically random channel identifiers instead of sequential ObjectIdentifier.

## Comparison with Chrome

Chrome's port implementation binds port objects to specific execution contexts and uses per-port tokens for message routing. WebKit's implementation uses a global counter-based system that allows any caller with knowledge of the channel ID to inject messages.

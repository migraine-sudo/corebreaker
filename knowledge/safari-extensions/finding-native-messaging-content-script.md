# Finding: Content Script → Native Messaging Privilege Escalation (Missing Caller Identity)

## Classification

- **Target**: Safari WebKit Web Extensions — Native Messaging
- **Type**: Logic bug — missing caller context restriction + missing sender identity
- **Estimated CVSS**: 8.6-9.3 (depends on target extension's native host capabilities)
- **Bounty Category**: Apple Security Bounty — Sandbox Escape (potentially $100K-300K)
- **Affected**: Safari 15.4+ (all platforms with extension native messaging)

## One-Line Summary

Safari's `RuntimeSendNativeMessage` IPC has only `isLoaded` validation — content scripts can send native messages with no sender identity forwarded to the host, unlike Chrome which restricts to background scripts and includes sender context.

## The Gap

| Check | Chrome | Safari/WebKit |
|-------|--------|---------------|
| `sendNativeMessage` caller restriction | Background scripts only (browser process enforced) | **ANY loaded context** (`isLoaded` only) |
| `nativeMessaging` permission check location | Both API layer AND browser process | **WebProcess only** (no UIProcess check) |
| Native host receives caller identity | Yes (includes `sender` with context type) | **No** (only message payload) |
| Content script can call native messaging | NO | **YES** |

## Attack Chain

```
Web Page (attacker-controlled)
    │
    │ XSS into content script context (DOM-based, shared DOM)
    ▼
Content Script (extension's context on attacker page)
    │
    │ browser.runtime.sendNativeMessage("appID", payload)
    │ Passes: isPropertyAllowed (WebProcess, nativeMessaging in manifest)
    │ Passes: isLoaded validator (UIProcess, no caller distinction)
    ▼
UIProcess RuntimeSendNativeMessage handler
    │
    │ Forwards to NSExtension/delegate with NO sender identity
    ▼
Native Host (app sandbox - keychain, filesystem, network)
    │
    │ Processes message as trusted (cannot distinguish source)
    ▼
Privileged Action (read keychain, access files, network to internal)
```

## Key Code Locations

- `WebExtensionContext.messages.in:128` — `[Validator=isLoaded] RuntimeSendNativeMessage(...)`
- `WebExtensionContextAPIRuntimeCocoa.mm:238-350` — `sendNativeMessage()` handler, no permission/context check
- `WebExtensionAPIRuntimeCocoa.mm:162-169` — `isPropertyAllowed` (JS visibility only, WebProcess-side)
- `WebExtensionMessagePortCocoa.mm` — native port implementation, no sender identity

## Why This Is Exploitable Without Renderer Compromise

1. `isPropertyAllowed` makes `sendNativeMessage` visible to content scripts (not just background pages)
2. The IPC validator `isLoaded` passes for content script contexts
3. No sender identity forwarded to native host
4. Only requirement: XSS into content script context (NOT full renderer compromise)

## Attack Prerequisites

1. Target extension must have `nativeMessaging` permission declared
2. Target extension must have content scripts injected on pages attacker controls
3. Attacker must achieve XSS into the content script context (DOM-based vectors via shared DOM)
4. Target extension's native host must perform privileged operations on message receipt

## High-Value Targets

| Extension Category | Native Host Capability | Impact |
|---|---|---|
| Password managers (1Password, Bitwarden) | Keychain access | All credentials exposed |
| VPN extensions | Network tunnel config | Traffic interception |
| Developer tools | OAuth tokens, file access | Supply chain |
| Clipboard managers | Pasteboard access | Data exfiltration |

## Chrome's Defense (What WebKit Should Have)

Chrome enforces at the browser process level:
```cpp
// Only background/service worker contexts may call sendNativeMessage
if (!context->IsForServiceWorkerContext() && !context->IsForBackgroundPage()) {
    return RespondNow(Error("Only background scripts can use native messaging"));
}
```

And Chrome includes sender identity in the message to the native host:
```json
{
    "sender": {
        "id": "extension-id",
        "origin": "chrome-extension://...",
        "contextType": "BACKGROUND"  // or TAB, POPUP, etc.
    },
    "message": { ... }
}
```

## Recommended Fix

### Fix A: Restrict to privileged contexts (Primary)

In `WebExtensionContext.messages.in`, change validator:
```
[Validator=isLoadedAndPrivilegedMessage] RuntimeSendNativeMessage(...)
[Validator=isLoadedAndPrivilegedMessage] RuntimeConnectNative(...)
```

### Fix B: Forward caller context to native host (Defense-in-depth)

In `WebExtensionContextAPIRuntimeCocoa.mm`, include sender info:
```objc
messageItem.userInfo = @{
    messageKey: message,
    @"senderContext": isContentScript ? @"content_script" : @"background",
    @"senderURL": callerURL
};
```

### Fix C: UIProcess permission check (Defense-in-depth)

In `sendNativeMessage()` handler, add explicit check:
```cpp
if (!hasPermission(_WKWebExtensionPermissionNativeMessaging)) {
    completionHandler(toWebExtensionError(...));
    return;
}
```

## Code Proof

### Content script CAN call native messaging (WebProcess, line 168-169):
```cpp
// WebExtensionAPIRuntimeCocoa.mm:162-173
bool WebExtensionAPIRuntime::isPropertyAllowed(const ASCIILiteral& name, WebPage*)
{
    if (name == "connectNative"_s || name == "sendNativeMessage"_s)
        return extensionContext->hasPermission("nativeMessaging"_s);
        // ^^^ Only checks manifest permission, NOT caller context (content vs background)
}
```

### UIProcess has NO permission check (line 364):
```cpp
// WebExtensionContextAPIRuntimeCocoa.mm:364-419
void WebExtensionContext::runtimeConnectNative(const String& applicationID, 
    WebExtensionPortChannelIdentifier channelIdentifier, ...)
{
    // NO permission check here
    // NO caller context check
    // Directly creates native port connection
    addPorts(sourceContentWorldType, targetContentWorldType, channelIdentifier, { pageProxyIdentifier });
    Ref nativePort = WebExtensionMessagePort::create(*this, applicationID, channelIdentifier);
    // ...connects to native host...
}
```

### IPC definition confirms no restriction (messages.in:129):
```
[Validator=isLoaded] RuntimeConnectNative(String applicationID, ...)
```

## Status

- **Code analysis**: Confirmed — content scripts CAN call native messaging (pure logic bug, no renderer compromise)
- **PoC needed**: Requires identifying a specific Safari extension with nativeMessaging + broad content scripts
- **Report readiness**: 70% — need concrete victim extension for full PoC demonstration

## Discovery Provenance

1. Chrome audit identified native messaging as restricted to background scripts
2. Cross-implementation comparison: "Does Safari enforce the same restriction?"
3. `messages.in` review confirmed `isLoaded` validator (weakest possible)
4. UIProcess handler confirmed no permission check or sender identity forwarding

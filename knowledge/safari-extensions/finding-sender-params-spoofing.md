# Finding: WebExtension MessageSenderParameters Not Validated by UIProcess

## Summary

Safari's WebKit Web Extension implementation trusts `WebExtensionMessageSenderParameters` fields (`url`, `contentWorldType`, `frameIdentifier`) provided by the WebProcess without validation in the UIProcess. A compromised renderer can forge these fields to bypass `externally_connectable` access control and spoof sender identity to extension message handlers.

## Severity

**Medium-High** (renderer compromise required, but this is Apple's standard threat model for sandbox bypass findings)

## Affected Code

- **UIProcess handler**: `Source/WebKit/UIProcess/Extensions/Cocoa/API/WebExtensionContextAPIRuntimeCocoa.mm`
  - `runtimeSendMessage()` (line 129)
  - `runtimeWebPageSendMessage()` (line 441)
  - `runtimeConnect()` (line 177)
  - `runtimeWebPageConnect()` (line 498)
- **IPC definitions**: `Source/WebKit/UIProcess/Extensions/WebExtensionContext.messages.in` (lines 126-131)
- **WebProcess sender construction**: `Source/WebKit/WebProcess/Extensions/API/Cocoa/WebExtensionAPIRuntimeCocoa.mm` (lines 348-356, 455-463)

## Root Cause

The `WebExtensionMessageSenderParameters` struct is serialized and transmitted via IPC from WebProcess to UIProcess:

```cpp
struct WebExtensionMessageSenderParameters {
    std::optional<String> extensionUniqueIdentifier;
    std::optional<WebExtensionTabParameters> tabParameters;
    std::optional<WebExtensionFrameIdentifier> frameIdentifier;
    WebPageProxyIdentifier pageProxyIdentifier;
    WebExtensionContentWorldType contentWorldType;
    URL url;
    WTF::UUID documentIdentifier;
};
```

In the UIProcess handlers, only `tabParameters` is rebuilt from trusted UIProcess state:

```cpp
// runtimeSendMessage (line 139-141):
WebExtensionMessageSenderParameters completeSenderParameters = senderParameters;
if (RefPtr tab = getTab(senderParameters.pageProxyIdentifier))
    completeSenderParameters.tabParameters = tab->parameters();  // ONLY field rebuilt
// url, contentWorldType, frameIdentifier, documentIdentifier — all trusted from WebProcess
```

The IPC validator `isLoaded` (line 1028 of WebExtensionContext.h) performs no message source validation:
```cpp
bool isLoaded(IPC::Decoder&) const { return isLoaded(); }  // ignores decoder entirely
```

## Impact

### 1. externally_connectable Bypass (via `runtimeWebPageSendMessage`)

In `runtimeWebPageSendMessage` (line 462-464), the unvalidated `url` field is used for security decisions:

```cpp
auto url = completeSenderParameters.url;  // FROM WEBPROCESS — NOT VALIDATED
auto validMatchPatterns = destinationExtension->extension()->externallyConnectableMatchPatterns();
if (!hasPermission(url, tab.get()) || !WebExtensionMatchPattern::patternsMatchURL(validMatchPatterns, url)) {
    // REJECT — but url can be forged to bypass this check
}
```

A compromised renderer can set `url` to any domain in the target extension's `externally_connectable` manifest, bypassing the origin check and sending unauthorized messages to the extension.

### 2. User Gesture Spoofing (via `runtimeSendMessage`)

Line 151:
```cpp
bool resolvedUserGesture = userGesture && senderParameters.contentWorldType != WebExtensionContentWorldType::ContentScript;
```

By forging `contentWorldType = Main` instead of `ContentScript`, and setting `userGesture = true`, the compromised renderer propagates a fake user gesture to the receiving extension. The receiver then operates with `UserGestureIndicator::IsProcessingUserGesture::Yes`, enabling gesture-gated APIs (popup open, activeTab grant, etc.).

### 3. Sender Identity Spoofing (via `runtimeSendMessage` and `runtimeWebPageSendMessage`)

The `url` and `contentWorldType` fields are forwarded to the receiving extension's `runtime.onMessage` / `runtime.onMessageExternal` handler as the `sender` object. Extensions that make trust decisions based on `sender.url` or `sender.origin` can be deceived.

## Attack Scenario

1. Attacker achieves renderer compromise (e.g., via memory corruption in WebContent process)
2. Attacker directly crafts IPC message `RuntimeWebPageSendMessage`:
   - `senderParameters.url = "https://trusted-partner.com"` (in target extension's `externally_connectable`)
   - `senderParameters.pageProxyIdentifier = <valid page ID from same process>`
3. UIProcess validates:
   - `getTab(pageProxyIdentifier)` → finds tab ✓
   - `hasPermission(trusted-partner.com, tab)` → passes (if source extension has broad permissions) ✓  
   - `patternsMatchURL(externallyConnectable, trusted-partner.com)` → passes ✓
4. Message delivered to target extension's `onMessageExternal` with `sender.url = "https://trusted-partner.com"`
5. Target extension trusts the message and performs privileged actions

## Recommended Fix

UIProcess should rebuild security-critical fields from its own trusted state:

```cpp
WebExtensionMessageSenderParameters completeSenderParameters = senderParameters;
if (RefPtr tab = getTab(senderParameters.pageProxyIdentifier)) {
    completeSenderParameters.tabParameters = tab->parameters();
    completeSenderParameters.url = tab->url();  // Rebuild from UIProcess state
}

// For contentWorldType: UIProcess knows whether the message came from
// a privileged page (has privilegedIdentifier in IPC destinationID) or not.
// Use isPrivilegedMessage() to determine the actual world type.
```

Additionally, `runtimeWebPageSendMessage` should validate that the IPC source WebProcess actually hosts the claimed page, and that the page's actual URL matches what was claimed.

## Files Downloaded for This Analysis

- `UIProcess/Extensions/Cocoa/API/WebExtensionContextAPIRuntimeCocoa.mm` (602 lines)
- `WebProcess/Extensions/API/Cocoa/WebExtensionAPIRuntimeCocoa.mm` (871 lines)
- `Shared/Extensions/WebExtensionMessageSenderParameters.h`
- `Shared/Extensions/WebExtensionMessageSenderParameters.serialization.in`
- `UIProcess/Extensions/WebExtensionContext.messages.in`
- `UIProcess/Extensions/WebExtensionContext.h`

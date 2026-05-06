# Safari Native Messaging Content Script Escalation

## Vulnerability

Safari allows content scripts to call `browser.runtime.sendNativeMessage()` — Chrome restricts this to background scripts only. Native hosts (with Keychain, clipboard, filesystem access) cannot distinguish the caller context.

**CVSS 3.1**: 8.6-9.3 (High to Critical)  
**Bounty Category**: Sandbox Escape ($100K-$300K)  
**Affected**: Safari 15.4+ (all platforms)  
**Chrome equivalent defense**: Background-script-only restriction enforced at browser process level

## Real-World Target: Bitwarden

Bitwarden's Safari extension:
- Has `nativeMessaging` as REQUIRED permission
- Injects content scripts on `*://*/*` at `document_start` in all frames
- Native host (`SafariWebExtensionHandler.swift`) accesses macOS Keychain for vault keys
- No caller identity verification in native host

## Attack Chain

```
Attacker page (Bitwarden content script auto-injects)
    → XSS into content script context
    → browser.runtime.sendNativeMessage("com.8bit.bitwarden", {command: "readFromClipboard"})
    → Returns clipboard (may contain copied password)

Or for full vault compromise:
    → browser.runtime.sendNativeMessage("com.8bit.bitwarden", 
        {command: "unlockWithBiometricsForUser", userId: "TARGET_USER_ID"})
    → User sees biometric prompt → approves
    → Vault key returned from Keychain
    → All passwords compromised
```

## Root Cause

| Location | Issue |
|----------|-------|
| `WebExtensionContext.messages.in:128-129` | `[Validator=isLoaded]` — weakest validator, passes for content scripts |
| `WebExtensionAPIRuntimeCocoa.mm:162-169` | `isPropertyAllowed` only checks manifest permission, not caller type |
| `WebExtensionContextAPIRuntimeCocoa.mm:238-350` | `sendNativeMessage()` has zero permission/context checks |
| Native host message format | Only `{message: payload}` forwarded — no sender identity |

## PoC Status

This vulnerability requires:
1. A victim extension with nativeMessaging + broad content scripts (Bitwarden confirmed)
2. An XSS vector into the content script context (extension-specific)
3. Knowledge of the native messaging commands (Bitwarden source is public)

A complete PoC would need to demonstrate XSS into Bitwarden's content script, which is a separate vulnerability in Bitwarden itself. The WebKit bug is that **content scripts should not be able to call native messaging at all** — regardless of XSS.

## Fix

Change IPC validator from `isLoaded` to `isLoadedAndPrivilegedMessage`:
```
[Validator=isLoadedAndPrivilegedMessage] RuntimeSendNativeMessage(...)
[Validator=isLoadedAndPrivilegedMessage] RuntimeConnectNative(...)
```

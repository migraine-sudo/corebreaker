# Finding: Cross-Extension Script Injection via Missing Permission Check

## Classification

- **Target**: Safari WebKit Web Extensions
- **Type**: Logic bug — missing security boundary check
- **CVSS**: 9.1 (Critical)
- **Bounty Category**: Apple Security Bounty — Safari/WebKit
- **Affected**: Safari 15.4+ (macOS, iOS, iPadOS, visionOS)

## One-Line Summary

`<all_urls>` matches `webkit-extension://` URLs, allowing `scripting.executeScript` to inject into other extensions' pages — Chrome blocks this at `permissions_data.cc:164-168`, WebKit has no equivalent.

## The Gap

| Check | Chrome | WebKit |
|-------|--------|--------|
| `<all_urls>` matches extension scheme? | No | **Yes** |
| Cross-extension permission deny? | `permissions_data.cc:164-168` | **Missing** |
| `executeScript` cross-extension block? | Implicit via above | **None** |

## Key Code Locations

- `WebExtensionMatchPattern.cpp:62-65` — `supportedSchemes()` includes `Scheme::Extension`
- `WebExtensionContext.cpp:846-968` — `permissionState()` missing cross-extension deny
- `WebExtensionContextAPIScriptingCocoa.mm:142-155` — `executeScript` trusts permission state

## Discovery Provenance

1. Chrome audit identified `permissions_data.cc:164-168` as a cross-extension defense
2. Cross-implementation differential: "Does WebKit have an equivalent?"
3. Code audit of `permissionState()` confirms no equivalent check exists
4. Attack chain verified: `tabs.query` → find extension tab → `executeScript({world:"MAIN"})` → full API access

## Pattern

**Implicit trust in URL scheme ownership**: code checks "is this an extension URL?" without checking "is this MY extension's URL?"

Functions using `isURLForThisExtension` → safe.  
Functions using `isURLForAnyExtension` or no extension check → vulnerable.

## Relationship to DNR CSP Bypass

Both vulnerabilities share the same meta-pattern:
- Chrome has an explicit defense that WebKit lacks
- The defense exists because the attack is real and was previously exploited/reported against Chrome
- WebKit either never implemented the defense or implemented it incompletely

| | DNR CSP Bypass | Cross-Extension Injection |
|---|---|---|
| Chrome defense | `kAllowedTransformSchemes` | `permissions_data.cc:164-168` |
| WebKit equivalent | None | None |
| Severity | High (8.1) | Critical (9.1) |

## PoC Location

`poc/safari-cross-extension-injection/`

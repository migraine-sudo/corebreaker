# Apple Security Bounty Report: Cross-Extension Script Injection via Missing Extension URL Permission Check

## 1. Summary

Safari's WebKit Web Extensions permission system allows an extension with `<all_urls>` + `scripting` permission to execute arbitrary JavaScript in the main world of OTHER extensions' pages. This is because `<all_urls>` matches `webkit-extension://` URLs, and no check exists to block cross-extension script injection.

Chrome explicitly blocks this attack in `permissions_data.cc:164-168` by denying access when `document_url.SchemeIs(kExtensionScheme) && document_url.GetHost() != extension_id_`. WebKit has NO equivalent check.

The result: a malicious extension (e.g., "Dark Mode Pro") can read all stored data from a password manager extension, crypto wallet extension, or any other extension that stores sensitive data in `browser.storage`.

## 2. Security Boundary Analysis

### 2.1 The Extension Isolation Boundary

Extensions are isolated security contexts. Each extension:
- Has its own origin (`webkit-extension://<UUID>`)
- Has its own storage (`browser.storage.local`)
- Has its own API permissions
- Should NOT be able to access another extension's data or APIs

This is a fundamental security assumption: users trust that their password manager's data is inaccessible to other extensions.

### 2.2 What `<all_urls>` Should Mean

In Chrome, `<all_urls>` matches:
- `http://*/*`
- `https://*/*`
- `ftp://*/*`
- `file:///*`
- **NOT** `chrome-extension://*/*` (explicitly excluded)

In Safari/WebKit, `<all_urls>` matches:
- All of the above
- **ALSO `webkit-extension://*/*`** (NOT excluded)

### 2.3 The Missing Check

Chrome's defense (`permissions_data.cc:164-168`):
```cpp
if (document_url.SchemeIs(kExtensionScheme) &&
    document_url.GetHost() != extension_id_ &&
    !allow_on_extension_urls) {
    *error = manifest_errors::kCannotAccessExtensionUrl;
    return true;  // BLOCKED
}
```

WebKit's `permissionState(URL)` in `WebExtensionContext.cpp:846-968`:
- Line 851: `isURLForThisExtension(url)` grants implicit access to own pages
- **No equivalent block** for other extensions' URLs
- `<all_urls>` pattern matches `webkit-extension://other-uuid/...` via `supportedSchemes()`

### 2.4 Capability Before vs After This Bug

**Without this bug** (Chrome behavior):
- Extension A can inject scripts into web pages (`http://`, `https://`)
- Extension A CANNOT inject scripts into Extension B's pages
- Extension A CANNOT read Extension B's storage
- Each extension's data is isolated

**With this bug** (Safari behavior):
- Extension A can inject scripts into Extension B's pages via `scripting.executeScript`
- Injected script runs in Extension B's main world
- Has full access to Extension B's `browser.storage`, `browser.runtime`, etc.
- Can read ALL of Extension B's stored data (passwords, keys, tokens)

## 3. Root Cause Analysis

### 3.1 `supportedSchemes()` Includes Extension Scheme

File: `WebExtensionMatchPattern.cpp` line 62-65
```cpp
static OptionSet<Scheme> supportedSchemes() {
    return { Scheme::HTTP, Scheme::HTTPS, Scheme::File, 
             Scheme::FTP, Scheme::Extension };  // <-- Extension scheme included!
}
```

This means `<all_urls>` creates match patterns that match `webkit-extension://` URLs.

### 3.2 `permissionState()` Has No Cross-Extension Block

File: `WebExtensionContext.cpp` lines 846-968

The permission check flow:
1. `isURLForThisExtension(url)` → returns `PermissionState::GrantedImplicitly` for own pages ✓
2. For OTHER extensions' URLs → falls through to granted permission pattern matching
3. If `<all_urls>` is granted → matches `webkit-extension://other-uuid/*` → returns `PermissionState::GrantedExplicitly`
4. **NO check** that the URL belongs to a different extension

### 3.3 `scripting.executeScript` Trusts Permission State

File: `WebExtensionContextAPIScriptingCocoa.mm` line 142-155

```cpp
// Only checks hasPermission(url) — no cross-extension block
if (!hasPermission(tab->url())) {
    // permission denied
}
// If permission granted (via <all_urls>), injection proceeds
```

### 3.4 Main World Injection = Full API Access

File: `WebExtensionContextAPIScriptingCocoa.mm` line 155

When `world: "MAIN"` is specified, the injected script executes in the target extension's JavaScript context with full access to `browser.*` APIs — as if it were Extension B's own code.

## 4. Attack Chain

```
┌─────────────────────┐        ┌─────────────────────┐
│  Extension A         │        │  Extension B         │
│  "Dark Mode Pro"     │        │  "Secure Vault"      │
│                      │        │  (Password Manager)  │
│  Permissions:        │        │                      │
│  - <all_urls>        │        │  Storage:            │
│  - scripting         │        │  - bank.com: user/pw │
│  - tabs              │        │  - gmail: user/pw    │
└──────────┬───────────┘        └──────────┬───────────┘
           │                                │
           │ 1. tabs.query({})              │
           │    → finds tab with            │
           │    webkit-extension://B/popup  │
           │                                │
           │ 2. scripting.executeScript({   │
           │      target: {tabId},          │
           │      world: "MAIN",            │
           │      func: stealData           │
           │    })                           │
           │                                │
           │ 3. Injected code runs AS       │
           │    Extension B:                │
           │    browser.storage.local       │
           │      .get(null)                │
           │      → ALL passwords returned  │
           │                                │
           │ 4. Exfiltrate to               │
           │    attacker server             │
           └────────────────────────────────┘
```

## 5. Impact Assessment

### 5.1 Direct Impact

| Impact | Description |
|--------|-------------|
| Password Theft | Read all credentials from password manager extensions |
| Crypto Wallet Theft | Read seed phrases, private keys from wallet extensions |
| API Token Theft | Read OAuth tokens, API keys stored by extensions |
| Extension Impersonation | Execute actions as the victim extension |
| Universal Extension Breach | Affect ANY extension with stored sensitive data |

### 5.2 Real-World Attack Scenarios

**Scenario 1: Password Manager Exploitation**
- Victim uses 1Password/Bitwarden/LastPass Safari extension
- Attacker's "utility" extension reads all stored passwords
- No user interaction required after initial install

**Scenario 2: Crypto Wallet Drain**
- Victim uses MetaMask or similar wallet extension
- Attacker reads the seed phrase / private keys from extension storage
- Transfers all assets to attacker wallet

**Scenario 3: Developer Tool Exploitation**
- Victim uses a GitHub/GitLab extension storing OAuth tokens
- Attacker uses stolen tokens to access private repositories
- Supply chain attack vector

### 5.3 Scale

- Affects ANY extension with `<all_urls>` + `scripting` (many legitimate extensions have this)
- Many extensions store sensitive data in `browser.storage.local`
- Password managers, wallet extensions, developer tools, VPN extensions all affected
- A malicious extension only needs these common permissions to steal from ALL other extensions

### 5.4 Severity Justification

| Factor | Assessment |
|--------|-----------|
| Attack Complexity | Low — standard extension APIs, no exploits needed |
| Privileges Required | Low — `<all_urls>` + `scripting` (common, user-approved) |
| User Interaction | None (after approving extension install) |
| Scope | Changed — breaks inter-extension isolation boundary |
| Confidentiality | Critical — all extension-stored secrets exposed |
| Integrity | High — can modify victim extension's data |
| Availability | None |

**CVSS 3.1 estimate**: 9.1 (Critical)

## 6. Affected Versions

Safari's extension system has supported `scripting.executeScript` since Safari 15.4 (March 2022). The `<all_urls>` match pattern has included the extension scheme since initial implementation.

- Safari 15.4+ (all versions supporting scripting API)
- All platforms: macOS, iOS, iPadOS, visionOS

## 7. Reproduction Steps

### Prerequisites
- macOS with Xcode installed
- Safari with "Allow Unsigned Extensions" enabled

### Steps

1. **Build and install the victim extension:**
```bash
cd poc/safari-cross-extension-injection/victim-extension
xcrun safari-web-extension-converter . --project-location ../xcode-victim
# Build and run in Xcode
```

2. **Build and install the attacker extension:**
```bash
cd poc/safari-cross-extension-injection/attacker-extension
xcrun safari-web-extension-converter . --project-location ../xcode-attacker
# Build and run in Xcode
```

3. **Enable both extensions** in Safari > Settings > Extensions

4. **Open the victim extension's popup** (to create an extension page tab)

5. **Open the attacker extension's popup** and click "Scan & Steal Extension Data"

6. **Result:** The attacker extension displays all credentials stored by the victim extension

### Expected behavior (Chrome):
- `scripting.executeScript` targeting `chrome-extension://` URL → Permission denied error

### Actual behavior (Safari):
- `scripting.executeScript` targeting `webkit-extension://` URL → Code executes in victim's context

## 8. Recommended Fix

### Fix A: Block Cross-Extension URL Access in `permissionState()` (Primary)

In `WebExtensionContext.cpp`, add after line 852:

```cpp
// Block access to other extensions' pages
if (isURLForAnyExtension(url) && !isURLForThisExtension(url))
    return PermissionState::DeniedImplicitly;
```

### Fix B: Exclude Extension Scheme from `<all_urls>` (Defense-in-depth)

In `WebExtensionMatchPattern.cpp`, change `supportedSchemes()`:

```cpp
static OptionSet<Scheme> supportedSchemes() {
    return { Scheme::HTTP, Scheme::HTTPS, Scheme::File, Scheme::FTP };
    // Remove Scheme::Extension — <all_urls> should not match extension pages
}
```

### Fix C: Explicit Check in `scripting.executeScript` (Defense-in-depth)

In `WebExtensionContextAPIScriptingCocoa.mm`, before executing:

```cpp
if (isURLForAnyExtension(tab->url()) && !isURLForThisExtension(tab->url())) {
    completionHandler(toWebExtensionError(@"scripting_executeScript", nil, 
        @"Cannot inject script into another extension's page"));
    return;
}
```

**All three should be applied** for defense-in-depth.

## 9. Discovery Methodology

### 9.1 Finding Path

1. **Broad scan** of all messages in `WebExtensionContext.messages.in` with weak validators
2. Identified `isURLForAnyExtension` in `tabs.sendMessage` at line 486 — only checks scheme, not extension identity
3. Asked: "Does this pattern exist elsewhere in permission checks?"
4. Found: `permissionState()` has no cross-extension block → `<all_urls>` matches other extensions
5. Verified: `scripting.executeScript` → `hasPermission` → `permissionState` → grants access
6. Confirmed Chrome's explicit defense at `permissions_data.cc:164-168`

### 9.2 Pattern: Implicit Trust in URL Scheme Ownership

The bug pattern is: code checks "is this an extension URL?" without checking "is this MY extension's URL?" Functions that correctly use `isURLForThisExtension` work fine. Functions using `isURLForAnyExtension` or no extension-specific check are vulnerable.

## 10. Comparison with DNR CSP Bypass

| Property | DNR CSP Bypass | Cross-Extension Injection |
|----------|---------------|--------------------------|
| Permissions needed | declarativeNetRequest (minimal) | <all_urls> + scripting (common) |
| Target | Web pages | Other extensions |
| Impact | CSP bypass → XSS on websites | Full extension data theft |
| Severity | High (8.1) | Critical (9.1) |
| Requires | Extension install | Extension install |
| Stealth | High (looks like ad blocker) | Medium (needs scripting permission) |
| Chrome defense | kAllowedTransformSchemes | permissions_data.cc cross-extension block |
| WebKit gap | No scheme validation | No cross-extension permission block |

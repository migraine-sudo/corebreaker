# Finding 024: DNR regexSubstitution — Runtime DCHECK-Only javascript: Scheme Check

## Summary

The DeclarativeNetRequest (DNR) `regexSubstitution` redirect path checks for `javascript:` scheme only via a DCHECK (debug assertion) at runtime. In release builds, this check is completely absent. Additionally, `data:`, `chrome:`, and other privileged schemes are never checked at either parse time or runtime for `regexSubstitution` redirects.

## Affected Files

- `extensions/browser/api/declarative_net_request/regex_rules_matcher.cc:381,393`
- `extensions/browser/api/declarative_net_request/indexed_rule.cc:406-412`
- `extensions/browser/api/declarative_net_request/ruleset_matcher_base.cc:377-381`
- `extensions/browser/api/declarative_net_request/ruleset_manager.cc:370-377`

## Details

### Parse-time validation (indexed_rule.cc)

Different redirect types have different validation:
- `redirect.url` (line 374): Checks javascript: only, allows data:/chrome:/etc.
- `redirect.transform` (line 401-403): Validates scheme via `ValidateTransform` (only allows http/https/ftp/chrome-extension).
- `redirect.regex_substitution` (line 406-412): **NO scheme check at all.** Only checks non-empty.

### Runtime check (regex_rules_matcher.cc)

```cpp
// Line 391-395
if (redirect_url.SchemeIs(url::kJavaScriptScheme)) {
    return std::nullopt;
}
```

This is a **runtime** check for javascript: only. But the "sanity check" at ruleset_matcher_base.cc:381 is a DCHECK:

```cpp
// Line 377-381
// Sanity check that we don't redirect to a javascript url.
DCHECK(!redirect_url.SchemeIs(url::kJavaScriptScheme));
```

### RulesetManager URL scheme filtering (ruleset_manager.cc)

The only scheme checked at the manager level is `file://`:
```cpp
// Line 370-377
if (IsRedirectToFileUrl(action_info.action) &&
    !util::AllowFileAccess(ruleset->extension_id, browser_context_)) {
  action_info.action.reset();
}
```

No checks for `data:`, `chrome:`, `chrome-untrusted:`, `devtools:`, or other privileged schemes.

## Critical Evidence: Extension Redirects Bypass Safety Checks

### web_request_proxying_url_loader_factory.cc:460-476

Extension-originated redirects (including DNR) completely bypass redirect safety checks:

```cpp
// Lines 465-469
bool redirect_url_comes_from_extension =
    redirect_url_ == redirect_info.new_url;
if (redirect_url_comes_from_extension) {
  head->bypass_redirect_checks = true;
}
```

```cpp
// Lines 471-476
if (!redirect_url_comes_from_extension &&
    !IsRedirectSafe(request_.url, redirect_info.new_url,
                    info_->is_navigation_request)) {
  OnNetworkError(CreateURLLoaderCompletionStatus(net::ERR_UNSAFE_REDIRECT));
  return;
}
```

This means:
1. When a DNR `regexSubstitution` produces a `data:` URL, the redirect URL comes from the extension
2. `redirect_url_comes_from_extension` is `true`, so `bypass_redirect_checks = true`
3. `IsRedirectSafe` is NEVER called — even though `data:` is listed as unsafe (url_utils.cc:89)

### Complete Attack Chain

```
1. Extension with declarativeNetRequest + host_permissions for target site
2. DNR rule: regexSubstitution → "data:text/javascript,<malicious code>"
3. Victim page loads <script src="https://target.com/app.js">
4. DNR matches the request → produces data: URL redirect
5. web_request_proxying_url_loader_factory.cc sets bypass_redirect_checks = true
6. IsSafeRedirectTarget is NEVER called (data: would fail this check)
7. BlockedSchemeNavigationThrottle does NOT apply (subresource, not main_frame)
8. Net-layer URLRequestHttpJob::IsSafeRedirect: URLRequestJobFactory::IsSafeRedirectTarget defaults to true
9. data: URL script loads and executes in the context of the loading page
```

### Why This Is Worse Than webRequest.redirectUrl

- `webRequest.redirectUrl` also allows data: redirects, but requires `webRequestBlocking` permission (MV2 only)
- DNR `regexSubstitution` works in MV3, the current manifest version
- MV3 was explicitly designed to limit extension redirect capabilities
- DNR is positioned as the "safe" replacement for webRequestBlocking
- Yet it has LESS validation on the redirect target scheme

## Impact

An MV3 extension with `declarativeNetRequest` + host permissions can:
1. Redirect ANY subresource request to a `data:` URL via `regexSubstitution`
2. All redirect safety checks are bypassed (`bypass_redirect_checks = true`)
3. For `<script>` subresources, the data: URL JavaScript executes with the page's origin
4. This effectively gives the extension arbitrary script injection into any page it has host_permissions for

**Main frame mitigation**: `BlockedSchemeNavigationThrottle` blocks renderer-initiated data: navigations for main frame only.
**Subresource: NO mitigation**: No throttle, no safety check, `bypass_redirect_checks` is set.

## Exploitability

- **No compromised renderer needed**: Pure extension API capability
- **Requires**: `declarativeNetRequest` permission + host_permissions for target URLs
- **MV3 compatible**: Works with current manifest version
- **Stealthy**: DNR rules are declarative, no background script execution needed
- **The extension already has host_permissions**: But DNR + data: redirect provides a cleaner, harder-to-detect injection vector than content scripts

## VRP Value

**Medium-High** — This represents a gap in MV3's security model:
1. MV3 was designed to restrict extension redirect capabilities (removing webRequestBlocking)
2. DNR `regexSubstitution` bypasses scheme validation that exists for `redirect.url` and `redirect.transform`
3. Extension-originated redirects bypass `IsRedirectSafe` entirely
4. The combination enables subresource redirect to data: URLs, which was not intended

Even though the extension needs host_permissions (already powerful), the finding shows:
- An inconsistency in Chrome's redirect safety model
- A gap in MV3's design that was supposed to be more restrictive
- Missing scheme validation that exists in other redirect paths

## Chromium Awareness

Partial — TODO at regex_rules_matcher.cc:392 references counterintuitive behavior (crbug.com/40111509). No TODO specifically about missing scheme validation for regexSubstitution. The `bypass_redirect_checks` behavior is intentional for extensions but the interaction with DNR's missing scheme validation is likely unintended.

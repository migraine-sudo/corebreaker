# Chrome VRP Report: ExtensionNavigationRegistry::CanRedirect Dead-Code Logic Bug — Cross-Extension Resource Access Bypass

## Summary

`ExtensionNavigationRegistry::CanRedirect()` in `extensions/browser/extension_navigation_registry.cc` contains a logic bug: the function returns `true` regardless of whether the redirecting extension's ID matches the target extension. This makes the `extension_id` equality check at line 85 dead code. As a result, any extension with `webRequest` permission can redirect navigations to access non-web-accessible resources of other installed extensions, bypassing the MV3 `web_accessible_resources` security boundary.

## Affected Component

`extensions/browser/extension_navigation_registry.cc` (Copyright 2025)

## Chromium Version

Tested against Chromium HEAD as of 2026-04-27.

## Vulnerability Details

### The Bug

```cpp
// extension_navigation_registry.cc:66-90
bool ExtensionNavigationRegistry::CanRedirect(int64_t navigation_id,
                                              const GURL& gurl,
                                              const Extension& extension) {
  std::optional<Metadata> extension_redirect_recorded =
      GetAndErase(navigation_id);

  if (!extension_redirect_recorded.has_value()) {
    return false;
  }

  auto metadata = extension_redirect_recorded.value();
  if (metadata.gurl != gurl) {
    return false;
  }

  if (metadata.extension_id == extension.id()) {  // ← Dead code
    return true;
  }

  return true;  // ← BUG: Always returns true even when IDs don't match
}
```

Lines 85-87 check whether the extension that initiated the redirect matches the target extension. However, both branches of this conditional return `true`, making the check meaningless. The function should return `false` at line 89 when the extension IDs don't match.

### Security Check Bypass

The calling code in `extension_navigation_throttle.cc:340-344`:

```cpp
if (!is_accessible &&
    !ExtensionNavigationRegistry::Get(browser_context)
         ->CanRedirect(navigation_handle()->GetNavigationId(), url,
                       *target_extension)) {
  return content::NavigationThrottle::BLOCK_REQUEST;
}
```

When a navigation targets a non-web-accessible extension resource (`!is_accessible`), the throttle checks `CanRedirect()`. If `CanRedirect()` returns `true`, the navigation is allowed. Due to the bug, it always returns `true` when a redirect record exists (regardless of which extension recorded it), so the security check is bypassed.

### How Redirect Records Are Created

```cpp
// extension_web_request_event_router.cc:441-457
void RecordThatNavigationWasInitiatedByExtension(
    const WebRequestInfo* request,
    content::BrowserContext* browser_context,
    GURL* new_url,
    const ExtensionId& extension_id) {
  GURL new_location = new_url ? *new_url : GURL();
  if (request->navigation_id.has_value()) {
    ExtensionNavigationRegistry::Get(browser_context)
        ->RecordExtensionRedirect(request->navigation_id.value(), new_location,
                                  extension_id);
  }
}
```

Any extension with `webRequest` permission that intercepts a navigation via `onBeforeRequest` and issues a redirect will create a record.

## Attack Scenarios

### Scenario 1: webRequest API (requires `webRequestBlocking`)

**Prerequisites**: Malicious extension A (with `webRequest` + `webRequestBlocking` permission), target extension B installed.

1. User navigates to any page.
2. Extension A uses `chrome.webRequest.onBeforeRequest` listener to intercept the navigation and redirect it to `chrome-extension://<B-extension-id>/secret-resource.html`.
3. `RecordThatNavigationWasInitiatedByExtension()` records this redirect with Extension A's ID and the target URL.
4. `ExtensionNavigationThrottle::WillStartRequest()` runs:
   - Determines the resource is not web-accessible (`!is_accessible`)
   - Calls `CanRedirect(navigation_id, url, *target_extension_B)`
5. `CanRedirect()` executes:
   - Finds the redirect record (returns non-nullopt)
   - URL matches (`metadata.gurl == gurl`) → doesn't return false
   - `metadata.extension_id` (A's ID) != `extension.id()` (B's ID) → condition is false
   - Falls through to `return true` at line 89
6. Navigation is allowed. Extension A successfully accesses Extension B's private resource.

### Scenario 2: Declarative Net Request (requires only `declarativeNetRequest`)

This variant is **more practical** because `declarativeNetRequest` is more commonly granted than `webRequestBlocking`, and DNR rules work in MV3 without host permissions for redirect rules targeting extension URLs.

**Prerequisites**: Malicious extension A (with `declarativeNetRequest` permission), target extension B installed.

**Additional code evidence** (`extensions/browser/api/declarative_net_request/indexed_rule.cc:368-379`):
```cpp
if (redirect.url) {
    GURL redirect_url = GURL(*redirect.url);
    if (!redirect_url.is_valid()) { return ERROR_INVALID_REDIRECT_URL; }
    if (redirect_url.SchemeIs(url::kJavaScriptScheme)) { return ERROR_JAVASCRIPT_REDIRECT; }
    indexed_rule->redirect_url = std::move(*redirect.url);
    return ParseResult::SUCCESS;
}
```
No check prevents `redirect.url` from targeting `chrome-extension://<other-extension-id>/...`. Additionally, `constants.cc:12-14` explicitly includes `extensions::kExtensionScheme` in `kAllowedTransformSchemes`, meaning URL transforms can also target other extensions.

**Steps**:
1. Extension A declares a DNR rule:
   ```json
   {
     "id": 1,
     "priority": 1,
     "action": {"type": "redirect", "redirect": {"url": "chrome-extension://<B-id>/secret.html"}},
     "condition": {"urlFilter": "trigger.example.com", "resourceTypes": ["main_frame"]}
   }
   ```
2. User navigates to `trigger.example.com`.
3. DNR redirect fires at `extension_web_request_event_router.cc:1139-1156`, calling `RecordThatNavigationWasInitiatedByExtension(request, browser_context, new_url, extension_A_id)`.
4. Same bypass path as Scenario 1: `CanRedirect()` returns `true` despite extension ID mismatch.
5. Navigation to Extension B's non-WAR resource is allowed.

**Note**: `ShouldEvaluateRequest` at `ruleset_manager.cc:536` prevents DNR evaluation for requests already targeting `chrome-extension://`, but does NOT prevent redirecting FROM `https://` TO `chrome-extension://`.

### What Can Be Accessed

- Extension B's non-web-accessible HTML pages (potentially containing sensitive UI or data)
- Extension B's internal configuration files
- Extension B's private scripts (which may contain API keys, authentication tokens, etc.)
- Any resource in Extension B's package that is not in `web_accessible_resources`

## Impact

### Cross-Extension Isolation Bypass (Medium-High)

The `web_accessible_resources` mechanism in MV3 is a core security boundary that prevents unauthorized access to extension resources. This bug allows any extension with `webRequest` permission to bypass this boundary for all other installed extensions.

Specific impacts:
- **Privacy**: Password manager extensions store sensitive UI in non-WAR pages
- **Security**: Crypto wallet extensions have private signing pages
- **Integrity**: Enterprise policy extensions have internal configuration
- **Information disclosure**: Any extension's internal resources become accessible

### Code Quality Indicator

This is Copyright 2025 code. The pattern suggests a copy-paste error or incomplete implementation: the developer likely intended `return false` at line 89 but wrote `return true`.

## Suggested Fix

```cpp
if (metadata.extension_id == extension.id()) {
    return true;
}

return false;  // Don't allow cross-extension redirects
```

Or, as the TODO at line 78-79 suggests (`crbug.com/40060076`), verify that the recorded extension has WAR access to the target resource:

```cpp
if (metadata.extension_id == extension.id()) {
    return true;
}

// Check if the redirecting extension has WAR access to the target
return WebAccessibleResourcesInfo::IsResourceWebAccessible(
    &extension, gurl, url::Origin::Create(GURL("chrome-extension://" + 
    metadata.extension_id + "/")));
```

## Related

- `crbug.com/40060076` — The referenced TODO discusses verifying WAR access, but does not mention the `return true` logic error
- The dead-code pattern (conditional that doesn't affect control flow) is a distinct bug from the missing WAR verification
- MV3 `web_accessible_resources` documentation: this bypass undermines the "matches" field restriction

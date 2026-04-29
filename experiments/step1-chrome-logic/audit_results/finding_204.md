# Finding 204: WebRequest HasWebRequestScheme Allows Broader Scheme Set Than Event Filter

## Summary
The `HasWebRequestScheme()` function in `web_request_permissions.cc` allows extensions to observe requests for more URL schemes than the `ExtensionWebRequestEventRouter::RequestFilter` specifies for event listeners. The TODO (by karandeepb) acknowledges this inconsistency: "This allows more schemes than ExtensionWebRequestEventRouter::RequestFilter, which specifies the schemes allowed by web request event listeners. Consolidate the two." The broader scheme set in permissions checking means that some scheme-based access controls may be bypassed depending on which function is used for validation.

## Affected Files
- `extensions/browser/api/web_request/web_request_permissions.cc` (lines 46-55)

## Details

```cpp
// TODO(karandeepb): This allows more schemes than
// ExtensionWebRequestEventRouter::RequestFiler, which specifies the schemes
// allowed by web request event listeners. Consolidate the two.
bool HasWebRequestScheme(const GURL& url) {
  return (url.SchemeIs(url::kAboutScheme) || url.SchemeIs(url::kFileScheme) ||
          url.SchemeIs(url::kFileSystemScheme) ||
          url.SchemeIs(url::kFtpScheme) || url.SchemeIsHTTPOrHTTPS() ||
          url.SchemeIs(extensions::kExtensionScheme) || url.SchemeIsWSOrWSS() ||
          url.SchemeIs(url::kUuidInPackageScheme));
}
```

This function includes:
1. `about:` - Internal browser pages
2. `file:` - Local files
3. `filesystem:` - Sandboxed filesystem API
4. `ftp:` - FTP protocol (deprecated but still in the check)
5. `http:` / `https:` - Standard web traffic
6. `chrome-extension:` - Extension-to-extension requests
7. `ws:` / `wss:` - WebSocket connections
8. `uuid-in-package:` - Web bundles

The `HasWebRequestScheme` function is called at line 250 as an early-out for `CanRequestAccessToUrl()`:
```cpp
if (!HasWebRequestScheme(request.url)) {
  return PermissionsData::PageAccess::kDenied;
}
```

If the `RequestFilter` in the event router rejects certain schemes (e.g., `uuid-in-package:`) but `HasWebRequestScheme` allows them, then:
- The event filter might prevent the extension from receiving the event
- But the permissions check would say the extension CAN access the URL
- This inconsistency could lead to confused deputy issues where internal code checks `HasWebRequestScheme` for access decisions but the event never fires

Additionally, the inclusion of `about:` scheme URLs is notable. While `about:` URLs are also checked separately for host access (at line 63: "about: URLs are not covered in host permissions, but are allowed anyway"), this means any extension with webRequest permissions can observe `about:blank` and `about:srcdoc` frames' requests.

## Attack Scenario
1. An extension registers a webRequest listener with specific URL filter patterns.
2. The `RequestFilter` on the event router side blocks events for certain schemes (e.g., `filesystem:` or `uuid-in-package:`).
3. However, if the extension directly calls an API that uses `HasWebRequestScheme` for permission checking, it may gain access to requests for these schemes that the event filter would otherwise block.
4. The extension observes `filesystem:` or `uuid-in-package:` requests that should not be visible to it based on the event filter scheme restrictions.

More concretely for `about:` scheme:
5. The `about:` scheme is allowed by `HasWebRequestScheme`, and `GetHostAccessForURL` explicitly grants `kAllowed` for `about:` URLs.
6. This means any extension with webRequest permissions can observe requests from `about:blank` and `about:srcdoc` frames without needing host permissions for the parent frame's origin.

## Impact
Low. The scheme set inconsistency between `HasWebRequestScheme` and the event filter is primarily a code quality issue that could lead to unexpected behavior. The `about:` scheme access without host permission checking is a minor information disclosure vector.

## VRP Value
Low

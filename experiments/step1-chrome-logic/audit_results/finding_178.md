# Finding 178: WebUI Network Request Validation is DCHECK-Only, Extensions Can Observe WebUI Traffic in Release

## Summary
In `WebRequestPermissions::HideRequest`, the check ensuring WebUI renderers should not make network requests is gated behind `DCHECK_IS_ON()`. In release builds, this entire block is stripped. While the function still returns `true` (hiding the request) unconditionally for WebUI renderers, the validation that flags unexpected WebUI network requests only fires in debug builds. More critically, the `request.initiator` validation for hiding requests from certain origins uses `DCHECK` to enforce that the initiator exists. If a WebUI frame somehow issues a request without an initiator in release builds, the DCHECK wouldn't fire and the request would not be hidden from extensions.

## Affected Files
- `extensions/browser/api/web_request/web_request_permissions.cc` (lines 318-336)

## Details

```cpp
if (is_request_from_webui_renderer) {
#if DCHECK_IS_ON()
    const bool is_network_request =
        url.SchemeIsHTTPOrHTTPS() || url.SchemeIsWSOrWSS();
    if (is_network_request) {
      // WebUI renderers should never be making network requests, but we may
      // make some exceptions for now. See https://crbug.com/40091019 for
      // details.
      //
      // The DCHECK helps avoid proliferation of such behavior.
      DCHECK(request.initiator.has_value());
      DCHECK(extensions::ExtensionsBrowserClient::Get()
                 ->IsWebUIAllowedToMakeNetworkRequests(*request.initiator))
          << "Unsupported network request from "
          << request.initiator->GetTupleOrPrecursorTupleIfOpaque().GetURL()
          << " for " << url << " with request type "
          << WebRequestResourceTypeToString(request.web_request_type);
    }
#endif  // DCHECK_IS_ON()

    // In any case, we treat the requests as sensitive to ensure that the Web
    // Request API doesn't see them.
    return true;
  }
```

The defensive `return true` at line 340 ensures WebUI requests are always hidden from extensions. However, the DCHECK block is the only mechanism that validates:
1. That WebUI renderers have proper initiators on network requests.
2. That only approved WebUI origins make network requests.

In release builds, a WebUI renderer that makes unauthorized network requests (e.g., due to a WebUI XSS or a compromised WebUI renderer) will not trigger any warning or detection. The requests will be hidden from extensions (good), but the violation itself goes undetected in production (bad for defense-in-depth).

## Attack Scenario
1. An attacker finds a WebUI XSS vulnerability (e.g., in chrome://settings or chrome://extensions).
2. The XSS injects JavaScript that makes fetch requests to external URLs.
3. In debug builds, these would trigger DCHECKs and be flagged immediately.
4. In release builds, the network requests silently proceed with full WebUI privileges.
5. The requests are hidden from extension-based security tools (ad blockers, security extensions), making detection harder.
6. The attacker exfiltrates sensitive data from the WebUI page through these undetected network requests.

## Impact
Low-Medium. The primary defense (hiding WebUI requests from extensions) is properly enforced in release builds. The finding is about the missing detection/enforcement of unauthorized WebUI network requests in release builds, which is a defense-in-depth gap.

## VRP Value
Low

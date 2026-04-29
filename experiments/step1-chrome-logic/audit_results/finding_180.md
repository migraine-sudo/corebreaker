# Finding 180: Extension ContextType Validation Uses URL Scheme Instead of Origin for Untrusted WebUI

## Summary
When the renderer claims to be an `kUntrustedWebUi` context type, the browser validates this by checking only the URL scheme (`chrome-untrusted://`), not the full origin. The TODO (crbug.com/40265193) explicitly states: "We should, at minimum, be using an origin here." This means any `chrome-untrusted://` URL in the process can claim the untrusted WebUI context type, regardless of which specific untrusted WebUI it actually is. This is relevant because different `chrome-untrusted://` origins have different security properties and access to different APIs.

## Affected Files
- `extensions/browser/extension_function_dispatcher.cc` (lines 313-326)

## Details

```cpp
if (params->context_type == mojom::ContextType::kUntrustedWebUi) {
    // TODO(crbug.com/40265193): We should, at minimum, be using an
    // origin here. It'd be even better if we could have a more robust way of
    // checking that a process can host untrusted webui.
    if (extension || !render_frame_host_url ||
        !render_frame_host_url->SchemeIs(content::kChromeUIUntrustedScheme)) {
      constexpr char kInvalidWebUiUntrustedContext[] =
          "Context indicated it was untrusted webui, but is invalid.";
      ResponseCallbackOnError(std::move(callback),
                              ExtensionFunction::ResponseType::kFailed,
                              kInvalidWebUiUntrustedContext);
      return;
    }
}
```

The check `render_frame_host_url->SchemeIs(content::kChromeUIUntrustedScheme)` only verifies that the URL has the `chrome-untrusted://` scheme. It does not verify:
1. Which specific `chrome-untrusted://` host the request is from.
2. Whether that specific host should have access to the requested API.
3. Whether the process is locked to that specific untrusted WebUI origin.

Different `chrome-untrusted://` pages have different trust levels:
- `chrome-untrusted://print/` (Print Preview)
- `chrome-untrusted://media-app/` (Gallery)
- `chrome-untrusted://crosh/` (Chrome OS shell)
- `chrome-untrusted://terminal/` (Linux terminal)

A compromised renderer hosting one untrusted WebUI could claim access to APIs that should only be available to a different untrusted WebUI.

## Attack Scenario
1. An attacker compromises the renderer process hosting `chrome-untrusted://print/` (e.g., via a malicious PDF exploit).
2. The compromised renderer sends API requests with `context_type = kUntrustedWebUi`.
3. The browser checks only that the URL scheme is `chrome-untrusted://`, which it is.
4. The browser processes the API call, potentially granting access to APIs intended only for higher-privilege untrusted WebUI origins like `chrome-untrusted://terminal/`.
5. The attacker leverages this to access APIs beyond what `chrome-untrusted://print/` should have.

## Impact
Medium. The scheme-only check instead of a proper origin check means the browser cannot distinguish between different `chrome-untrusted://` origins for API access control. This is a defense-in-depth weakness that could be exploited in a renderer compromise scenario to pivot between untrusted WebUI capabilities.

## VRP Value
Medium

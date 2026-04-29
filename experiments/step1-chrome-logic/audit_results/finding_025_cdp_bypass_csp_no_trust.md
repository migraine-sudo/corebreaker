# Finding 025: CDP Page.SetBypassCSP Has No Trust Check

## Summary

The Chrome DevTools Protocol command `Page.SetBypassCSP` does not check `is_trusted_` or `allow_unsafe_operations_` before disabling Content Security Policy for the attached target. An untrusted CDP client (e.g., a Chrome extension using `chrome.debugger` API) can bypass CSP on any attached page.

## Affected Files

- `content/browser/devtools/protocol/page_handler.cc:1844-1847`

## Details

```cpp
// page_handler.cc:1844-1847
Response PageHandler::SetBypassCSP(bool enabled) {
  bypass_csp_ = enabled;
  return Response::FallThrough();
}
```

Compare with other security-sensitive commands that DO check trust:
- `Navigate` (line 903-907): Checks `is_trusted_` for chrome-untrusted:// and devtools:// schemes
- `HandleJavaScriptDialog` (line 1357): Checks `is_trusted_`

## Attack Scenario

1. A Chrome extension with the `debugger` permission attaches to a target page
2. The extension calls `Page.SetBypassCSP(true)`
3. CSP is now disabled for that page
4. The extension can inject arbitrary scripts via other CDP commands (e.g., `Runtime.evaluate`)

## Impact

- Bypasses Content Security Policy protections on any page the extension attaches to
- Combined with `Fetch.FulfillRequest` (which also lacks trust checks), an extension can both bypass CSP and modify response headers

## Exploitability

- **No compromised renderer needed**: Chrome extension with `debugger` permission
- **Limitation**: `debugger` permission requires explicit user interaction (attach + confirmation dialog)
- **Trust model concern**: Extensions with `debugger` permission already have significant power, but CSP bypass is not an expected capability of the debugger API

## VRP Value

Low-Medium — The `debugger` permission already grants extensive capabilities. However, the missing trust check is inconsistent with other security-sensitive commands.

## Chromium Awareness

No explicit TODO or crbug reference for this gap.

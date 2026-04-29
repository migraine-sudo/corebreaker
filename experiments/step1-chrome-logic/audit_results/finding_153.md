# Finding 153: Payment Handler Navigation Throttle MIME Type Allowlist Bypass via text/* and image/*

## Summary
The `PaymentHandlerNavigationThrottle` uses a prefix-based MIME type allowlist to restrict what content types can be loaded in a payment handler window. The allowlist uses `base::StartsWith` checks for `text/`, `image/`, and `video/` prefixes, which is overly broad. This allows loading content types like `text/csv`, `text/x-c` (C source code), or `image/svg+xml` (which can contain JavaScript) in the payment handler context.

## Affected Files
- `components/payments/content/payment_handler_navigation_throttle.cc:54-84` - MIME type allowlist

## Details
```cpp
// payment_handler_navigation_throttle.cc
content::NavigationThrottle::ThrottleCheckResult
PaymentHandlerNavigationThrottle::WillProcessResponse() {
  ...
  std::string mime_type;
  response_headers->GetMimeType(&mime_type);
  if (base::StartsWith(mime_type, "text/",
                       base::CompareCase::INSENSITIVE_ASCII) ||
      base::StartsWith(mime_type, "image/",
                       base::CompareCase::INSENSITIVE_ASCII) ||
      base::StartsWith(mime_type, "video/",
                       base::CompareCase::INSENSITIVE_ASCII) ||
      mime_type == kApplicationJavascript || mime_type == kApplicationXml ||
      mime_type == kApplicationJson) {
    return PROCEED;
  }
  ...
  return BLOCK_RESPONSE;
}
```

The allowlist blocks `application/pdf` (per crbug.com/1159267) but the broad `text/*` and `image/*` prefixes allow:
- `image/svg+xml` -- SVG files can contain inline JavaScript via `<script>` elements. In the context of a payment handler window, this could enable script injection if the SVG is served from a same-origin payment handler URL.
- `text/csv` -- Could trigger download dialogs or be used for data exfiltration
- `text/x-c`, `text/x-python`, etc. -- Source code that could leak information

The comment explicitly mentions the PDF vulnerability fix (crbug.com/1159267) as the motivation for the allowlist, but the prefix-based approach is less restrictive than necessary.

## Attack Scenario
1. Attacker operates a payment handler at `https://evil-pay.com`
2. During the payment flow, the handler opens a window (via the payment handler API)
3. The handler navigates the payment window to an SVG file on its own origin containing malicious JavaScript
4. The SVG with `<script>` content passes the MIME type check (starts with `image/`)
5. The script executes in the payment handler window context

Note: This is limited because the payment handler already controls the window and its own origin's content. The MIME type check is primarily to prevent rendering of dangerous content types like PDF plugins. The SVG case is notable because SVG is the only image format that can contain executable scripts.

## Impact
The `image/svg+xml` case could be used if a payment handler window navigates to an SVG on a different origin (if allowed by the content security model), but in practice the payment handler controls its own window. Low additional attack surface beyond what the payment handler already has.

## VRP Value
Low

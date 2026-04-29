# Finding 216: Invalid iframe CSP Attribute Silently Cleared Instead of Blocking Load

## Summary

When an iframe element has an invalid `csp` attribute (containing newlines, not matching the serialized CSP grammar, or exceeding 4096 bytes), the attribute is silently cleared to null rather than blocking the iframe from loading. This means an iframe intended to be loaded with a required CSP can be loaded without any CSP constraint if the attribute value is made invalid.

## Affected Files

- `third_party/blink/renderer/core/html/html_iframe_element.cc:264-266` — Invalid CSP cleared, not blocked
- `third_party/blink/renderer/core/html/html_iframe_element.cc:272-274` — Overlong CSP cleared, not blocked

## Details

```cpp
// html_iframe_element.cc:260-282
} else if (name == html_names::kCspAttr) {
    static const size_t kMaxLengthCSPAttribute = 4096;
    if (value && (value.contains('\n') || value.contains('\r') ||
                  !MatchesTheSerializedCSPGrammar(value.GetString()))) {
        // TODO(antoniosartori): It would be safer to block loading iframes with
        // invalid 'csp' attribute.
        required_csp_ = g_null_atom;  // CSP cleared! iframe loads without CSP
        // ... console message ...
    } else if (value && value.length() > kMaxLengthCSPAttribute) {
        // TODO(antoniosartori): It would be safer to block loading iframes with
        // invalid 'csp' attribute.
        required_csp_ = g_null_atom;  // CSP cleared! iframe loads without CSP
        // ... console message ...
    } else if (required_csp_ != value) {
        required_csp_ = value;  // Normal case: valid CSP applied
    }
```

## Attack Scenario

### CSP requirement bypass via attribute manipulation
1. A page creates an iframe with: `<iframe src="child.html" csp="script-src 'none'">`
2. This is supposed to enforce that child.html cannot execute scripts
3. An attacker (via DOM manipulation in the parent page, XSS, etc.) modifies the csp attribute:
   `iframe.setAttribute('csp', 'script-src \'none\'\n')`  (adds newline)
4. The newline makes the CSP value invalid
5. `required_csp_` is set to `g_null_atom` — the iframe loads without any CSP requirement
6. child.html can now execute scripts freely

### Overlong CSP bypass
1. Page wants to restrict an iframe with a detailed CSP
2. Attacker appends padding to make the attribute exceed 4096 bytes:
   `iframe.setAttribute('csp', legitimate_csp + 'a'.repeat(4000))`
3. The CSP is cleared due to length, iframe loads without restriction

### Combined with third-party content
1. A web application uses iframe `csp` attribute to sandbox third-party content
2. If the CSP string can be influenced by the third-party (e.g., via URL parameters), the third-party can inject a newline character
3. This causes the CSP to be cleared, giving the iframe full execution privileges

## Impact

- **No compromised renderer required**: Standard DOM manipulation
- **CSP bypass**: iframe loads without required CSP when attribute is invalid
- **Fail-open**: Invalid CSP leads to NO CSP rather than blocking the load
- **Two attack vectors**: Newline injection and length overflow both clear CSP
- **Acknowledged**: Two separate TODOs say blocking would be safer

## VRP Value

**Medium** — The iframe `csp` attribute is a security mechanism for restricting embedded content. Making it fail-open (invalid → no restriction) rather than fail-closed (invalid → don't load) allows CSP bypass. This requires the attacker to control or influence the CSP attribute value, which is possible in various scenarios including DOM XSS.

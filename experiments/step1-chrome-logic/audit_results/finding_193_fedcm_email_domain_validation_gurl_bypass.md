# Finding 193: Email Verification Domain Validation Uses GURL Parsing with Bypass Potential

## Summary
The `GetDomainFromEmail()` function in `email_verification_request.cc` validates the email domain by constructing a GURL from `"https://" + domain`. The function then checks `url.GetHost() != parts->second`, but this comparison may not catch all edge cases. The TODO at line 38-39 acknowledges the validation method is not robust. Additionally, the extracted domain is used directly in DNS lookups (`_email-verification.DOMAIN`), which could be exploited if the domain validation is insufficient.

## Affected Files
- `content/browser/webid/delegation/email_verification_request.cc:26-46` -- `GetDomainFromEmail()` with weak validation
- `content/browser/webid/delegation/email_verification_request.cc:119` -- Domain used in DNS hostname construction

## Details
```cpp
std::optional<std::string> GetDomainFromEmail(const std::string& email) {
  auto parts = base::RSplitStringOnce(email, "@");
  if (!parts) { return std::nullopt; }
  if (parts->first.empty() || parts->second.empty()) { return std::nullopt; }

  // Use GURL to validate that the domain is a valid host.
  // TODO(crbug.com/380367784): consider better ways to validate if
  // the email domain is well formed.
  GURL url("https://" + std::string(parts->second));
  if (!url.is_valid() || !url.has_host() || url.GetHost() != parts->second) {
    return std::nullopt;
  }

  return std::string(parts->second);
}
```

The domain is then used:
```cpp
std::string hostname = "_email-verification." + *domain;
dns_request_->SendRequest(hostname, ...);
```

GURL's parsing may normalize the host (e.g., lowercasing, punycode encoding), and the comparison `url.GetHost() != parts->second` could fail to catch domains with unusual characters that GURL normalizes but DNS does not treat equivalently.

## Attack Scenario
1. An attacker provides an email address with a carefully crafted domain part that passes GURL validation but resolves differently in DNS.
2. The domain is used to construct `_email-verification.DOMAIN` for a DNS TXT lookup.
3. The DNS response directs the browser to an attacker-controlled issuer.
4. The attacker's issuer returns an SD-JWT for the crafted email domain.
5. Since the email domain validation was insufficient, the browser accepts a token for what appears to be a different email domain.

## Impact
- Potential email domain spoofing in the email verification protocol.
- DNS-based redirection to attacker-controlled issuers.
- Limited by the GURL normalization check, but edge cases may exist.

## VRP Value
**Low** -- The email verification protocol is behind a feature flag, and GURL's validation is generally robust. The TODO acknowledges the validation method is not ideal, but a concrete bypass would require finding a GURL normalization edge case. This is a code quality issue with potential security implications.

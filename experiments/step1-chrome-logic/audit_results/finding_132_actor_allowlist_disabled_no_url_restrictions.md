# Finding 132: Actor URL Allowlist Feature Disabled by Default, Allowing Actions on Any Domain

## Severity: MEDIUM

## Summary

The `kGlicActionAllowlist` feature is `FEATURE_DISABLED_BY_DEFAULT`. When disabled, the entire domain allowlist/blocklist system is bypassed -- the Actor can act on ANY domain that passes the scheme check. This means in the default configuration, there is no positive allowlist restricting which sites the AI agent can interact with.

## Affected Files

- `components/actor/core/actor_features.cc:15` -- FEATURE_DISABLED_BY_DEFAULT
- `chrome/browser/actor/site_policy.cc:181-222` -- Allowlist check gated behind feature flag

## Details

```cpp
// actor_features.cc:15
BASE_FEATURE(kGlicActionAllowlist, base::FEATURE_DISABLED_BY_DEFAULT);

// site_policy.cc:181
if (base::FeatureList::IsEnabled(kGlicActionAllowlist)) {
    // ... allowlist checks ...
    // If kAllowlistOnly is true, reject URLs not on the allowlist
    // If false, fall through to other checks
}
// When the feature is DISABLED, this entire block is skipped
```

When `kGlicActionAllowlist` is disabled (the default):
1. No domain allowlist is applied
2. No `kAllowlistOnly` restriction is applied
3. The only remaining URL-level checks are:
   - Scheme check (HTTPS required, HTTP allowed in some paths)
   - IP address blocking
   - SafeBrowsing / Optimization Guide blocklist (which can fail-open per Finding 121)
   - Lookalike domain detection
   - Enterprise policy (if configured)

This means any site with a valid HTTPS URL that is not explicitly blocked by the optimization guide or lookalike detection can be acted upon by the AI agent.

## Attack Scenario

1. Default Chrome installation with Actor feature enabled
2. `kGlicActionAllowlist` is disabled (default)
3. Attacker's newly-created phishing domain `https://secure-bank-login.com` is not yet known to any blocklist
4. Via prompt injection, AI agent is directed to navigate to this domain
5. No allowlist check prevents the navigation
6. Optimization guide may not have data for this new domain (fail-open per Finding 121)
7. Actor interacts with the phishing page

## Impact

- No positive domain restriction in default configuration
- Relies entirely on blocklists, which cannot cover unknown malicious domains
- The allowlist feature exists but is disabled, suggesting it is intended for more restrictive deployments
- Combined with other findings (fail-open, implicit grants), the default security posture is very permissive

## Remediation

For the initial launch of the Actor feature, consider enabling the allowlist with a curated set of trusted domains. A positive allowlist provides much stronger security than a blocklist-only approach for a feature that can interact with arbitrary web pages.

# Finding 135: HTTP Auth Cache Not Partitioned by Network Isolation Key

## Summary

The `kSplitAuthCacheByNetworkIsolationKey` feature is **DISABLED by default**. HTTP authentication credentials (Basic, Digest, NTLM) are cached globally without regard to the first-party context. A cross-site iframe can reuse authentication credentials cached from a different site context, enabling cross-site tracking and credential leakage.

## Affected Files

- `services/network/public/cpp/features.cc:92-93` — Feature DISABLED_BY_DEFAULT

## Details

```cpp
// features.cc:92-93
BASE_FEATURE(kSplitAuthCacheByNetworkIsolationKey,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

When disabled (current default):
- HTTP auth credentials are cached once per (scheme, host, port, realm) tuple
- A site A that triggers HTTP Basic auth to `api.service.com` stores credentials globally
- When site B embeds an iframe to `api.service.com`, the cached credentials are reused
- This enables cross-site tracking: site B can detect if the user has authenticated to `api.service.com` via site A

When enabled:
- HTTP auth credentials are partitioned by Network Isolation Key (top-level site)
- Credentials cached in site A's context are NOT available in site B's context

## Attack Scenario

### Cross-Site Credential Probing
1. Attacker's site embeds a hidden iframe to `https://corporate-intranet.com/auth-page`
2. If the user has previously authenticated to the intranet from another site, the cached credentials are automatically sent
3. The corporate intranet processes the authenticated request
4. Attacker can detect authentication status by timing the response or checking for side channels

### Cross-Site Tracking
1. Tracker site prompts HTTP auth, stores unique identifier as username
2. Any other site embedding the same tracker domain receives the cached credentials
3. Tracker can correlate the user across different sites using the shared auth cache

## Impact

- **No compromised renderer required**: Standard web embedding
- **Cross-site tracking**: HTTP auth cache acts as a cross-site tracking vector
- **Credential leakage**: Auth credentials shared across site contexts
- **Privacy violation**: Breaks expected privacy partitioning

## VRP Value

**Medium** — By design (feature not yet launched), but this is a known privacy gap that other browsers have addressed. The lack of partitioning in the auth cache is inconsistent with cookie partitioning and other state partitioning efforts.

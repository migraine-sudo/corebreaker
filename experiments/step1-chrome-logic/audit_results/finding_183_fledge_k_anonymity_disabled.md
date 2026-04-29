# Finding 183: FLEDGE k-Anonymity Enforcement Completely Disabled

## Summary

Both `kFledgeConsiderKAnonymity` and `kFledgeEnforceKAnonymity` are DISABLED by default. The k-anonymity threshold is a critical privacy protection in the Protected Audience API — it prevents showing unique (fingerprinting) ads to individual users by requiring ad creatives to be shown to a minimum number of users before they can win auctions. With both flags disabled, any ad creative can win regardless of how many users have seen it.

## Affected Files

- `third_party/blink/common/features.cc:856-857` — Both features DISABLED_BY_DEFAULT

## Details

```cpp
// features.cc:856-857
BASE_FEATURE(kFledgeConsiderKAnonymity, base::FEATURE_DISABLED_BY_DEFAULT);
BASE_FEATURE(kFledgeEnforceKAnonymity, base::FEATURE_DISABLED_BY_DEFAULT);
```

Additionally:
- `kFledgeEnforcePermissionPolicyContributeOnEvent` is also DISABLED (features.cc:955-956)
- `kFencedFramesLocalUnpartitionedDataAccess` is DISABLED (features.cc:780-781)

The k-anonymity mechanism is designed to prevent:
1. **Microtargeting**: Ads tailored to individual users (a privacy violation)
2. **Fingerprinting via ad creatives**: Using unique ad URLs to identify users
3. **Information leakage**: Ad tech learning that specific users visited specific sites via unique creatives

## Attack Scenario

1. Ad tech company creates N unique ad creatives, one per user
2. Each creative URL encodes a user-specific tracking identifier
3. When the ad wins an auction, the unique URL is loaded in a fenced frame
4. Even though fenced frames restrict direct data exfiltration, the unique ad URL reveals the user's identity to the ad server
5. k-anonymity would prevent this by requiring each creative to be shown to at least k users — but it's disabled

### Combined with kFencedFramesLocalUnpartitionedDataAccess

If this feature is also enabled (it's currently disabled but available):
1. Fenced frames could access local unpartitioned data
2. Combined with no k-anonymity enforcement, ad tech can both target individual users AND access cross-site data

## Impact

- **No compromised renderer required**: Standard Protected Audience API
- **Privacy violation**: Individual user targeting defeats the purpose of Privacy Sandbox
- **Fingerprinting**: Unique ad creatives identify users
- **Design gap**: k-anonymity is the core privacy protection of FLEDGE, and it's off

## VRP Value

**Medium** — Privacy Sandbox privacy guarantee not enforced. While this may be "expected" during the rollout phase, it means the current FLEDGE implementation provides none of its advertised privacy guarantees regarding microtargeting.

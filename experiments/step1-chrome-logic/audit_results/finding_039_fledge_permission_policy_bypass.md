# Finding 039: FLEDGE/Protected Audiences Cross-Origin Permission Policy Check Disabled

## Summary

The `kFledgeModifyInterestGroupPolicyCheckOnOwner` feature flag is **DISABLED_BY_DEFAULT**, causing the cross-origin interest group permission policy check to be detected but **not enforced**. A page can call `joinAdInterestGroup()` or `leaveAdInterestGroup()` for a cross-origin owner even when that owner's permissions policy would forbid it.

Additionally, at 4 separate Mojo IPC entry points (crbug.com/382786767), browser-renderer permission policy inconsistencies are silently ignored instead of killing the renderer with `ReportBadMessageAndDeleteThis()`.

## Affected Files

- `content/browser/interest_group/ad_auction_service_impl.cc:862-882` — Cross-origin policy check gated behind disabled flag
- `content/browser/interest_group/ad_auction_service_impl.cc:379` — TODO: should call ReportBadMessageAndDeleteThis
- `content/browser/interest_group/ad_auction_service_impl.cc:416` — TODO: should call ReportBadMessageAndDeleteThis
- `content/browser/interest_group/ad_auction_service_impl.cc:613` — TODO: should call ReportBadMessageAndDeleteThis
- `content/browser/interest_group/ad_auction_service_impl.cc:856` — TODO: should call ReportBadMessageAndDeleteThis
- `content/browser/interest_group/interest_group_features.cc` — Feature flag DISABLED_BY_DEFAULT

## Details

### Cross-origin owner check: detected but not enforced

```cpp
// ad_auction_service_impl.cc:862-882
auto* permissions_policy = static_cast<RenderFrameHostImpl*>(
    &render_frame_host())->GetPermissionsPolicy();

if (!permissions_policy->IsFeatureEnabledForOrigin(
        kJoinAdInterestGroup, owner,
        /*override_default_policy_to_all=*/true)) {
  // Logs a WebFeature metric (detection)
  GetContentClient()->browser()->LogWebFeatureForCurrentPage(...);

  // But only blocks if flag is enabled (which it's not)
  if (base::FeatureList::IsEnabled(
          features::kFledgeModifyInterestGroupPolicyCheckOnOwner)) {
    return false;  // DEAD CODE in production
  }
}
return true;  // Check fails but operation proceeds
```

### Missing renderer kill at 4 IPC entry points

```cpp
// ad_auction_service_impl.cc:379, 416, 613, 856
// TODO(https://crbug.com/382786767): Figure out why permission policy can
// be inconsistent between the browser and renderer policy, fix it, and then
// call ReportBadMessageAndDeleteThis() here.
```

When the browser-side permissions policy check fails but the renderer was allowed to make the call (inconsistency), the renderer should be killed. Instead, the call is silently dropped. This means a compromised renderer that ignores permissions policy is never terminated.

## Attack Scenario

### Cross-origin interest group manipulation

1. `evil.com` embeds an iframe or navigates to a page that sets `Permissions-Policy: join-ad-interest-group=()` (deny all)
2. Despite this policy, `evil.com` calls:
   ```javascript
   navigator.joinAdInterestGroup({
     owner: 'https://ad-network.com',
     name: 'tracking-group',
     biddingLogicUrl: 'https://ad-network.com/bid.js'
   }, 30 * 24 * 3600 * 1000);
   ```
3. The browser detects the policy violation but allows the operation because `kFledgeModifyInterestGroupPolicyCheckOnOwner` is disabled
4. `evil.com` can join/leave interest groups for `ad-network.com` without that origin's consent

### Compromised renderer persistence

1. A compromised renderer calls `updateAdInterestGroups()` / `runAdAuction()` even when permissions policy should block it
2. The browser silently drops the call instead of calling `ReportBadMessageAndDeleteThis()`
3. The compromised renderer survives and can continue attacking other APIs

## Impact

- **No compromised renderer needed** (for the cross-origin bypass): Standard JavaScript API usage
- **Privacy Sandbox violation**: Interest groups can be joined/left for cross-origin owners without their consent
- **User tracking**: An attacker page can add users to arbitrary interest groups, affecting what ads they see
- **Compromised renderer tolerance**: Renderer sending unauthorized IPC is not terminated
- **Acknowledged issues**: Both crbug.com/382786767 (renderer kill) and the feature flag TODO are known

## VRP Value

**Medium-High** — The cross-origin permission policy bypass is exploitable from standard JavaScript without a compromised renderer. The Privacy Sandbox interest group system is designed to be tightly controlled, and this bypass allows unauthorized cross-origin manipulation. The 4 missing `ReportBadMessageAndDeleteThis()` calls represent a defense-in-depth failure for compromised renderers.

# Finding 085: FLEDGE K-Anonymity Not Enforced (kFledgeEnforceKAnonymity Disabled)

## Summary

The `kFledgeEnforceKAnonymity` feature flag is DISABLED by default. When disabled, k-anonymity checks in Protected Audience (FLEDGE) auctions are simulated but not enforced. This means winning ads and their reporting don't need to meet k-anonymity thresholds, undermining a core privacy protection.

## Affected Files

- `third_party/blink/common/features.cc:857` — `kFledgeEnforceKAnonymity` DISABLED_BY_DEFAULT
- `content/browser/interest_group/auction_runner.cc:47-61` — DetermineKAnonMode()
- `content/browser/interest_group/interest_group_auction_reporter.cc:80-85` — IsKAnonForReporting()

## Details

```cpp
// auction_runner.cc:47-61
auction_worklet::mojom::KAnonymityBidMode DetermineKAnonMode() {
  if (base::FeatureList::IsEnabled(blink::features::kFledgeConsiderKAnonymity)) {
    if (base::FeatureList::IsEnabled(blink::features::kFledgeEnforceKAnonymity)) {
      return KAnonymityBidMode::kEnforce;
    } else {
      return KAnonymityBidMode::kSimulate;  // ← Current default
    }
  } else {
    return KAnonymityBidMode::kNone;
  }
}

// interest_group_auction_reporter.cc:80-85
bool IsKAnonForReporting(...) {
  if (!IsEnabled(kFledgeConsiderKAnonymity) ||
      !IsEnabled(kFledgeEnforceKAnonymity)) {
    return true;  // ← Always k-anonymous when not enforced
  }
  // ... actual k-anonymity check ...
}
```

## Attack Scenario

1. Advertiser creates highly targeted interest groups (e.g., one user per group)
2. These interest groups bid in auctions and win
3. Without k-anonymity enforcement, the winning ad's render URL and reporting IDs are not checked against k-anonymity thresholds
4. The reporting origin receives unique identifiers for individual users via `buyer_reporting_id` and `selected_buyer_and_seller_reporting_id`
5. This enables micro-targeting and individual user tracking through the auction mechanism

## Impact

- **No compromised renderer required**: Standard auction API usage
- **Privacy bypass**: K-anonymity is a core privacy guarantee of Protected Audience
- **User tracking**: Without k-anonymity, auction reporting can identify individual users
- **By design (currently)**: Chrome is gradually rolling out k-anonymity enforcement

## VRP Value

**Medium** — K-anonymity is a stated privacy goal of the Protected Audience API. Not enforcing it allows micro-targeting that the API was designed to prevent.

# Finding 232: Private Aggregation Filtering ID Multiplies Information Capacity Beyond Budget Intent

## Summary

The Private Aggregation API's L1 privacy budget only charges based on contribution `value` sums, but each unique `filtering_id` creates an independent aggregation channel at the server side. An attacker can submit many contributions with value=1 and distinct filtering_ids, consuming only 1 budget unit per contribution while extracting 1 independent bit per contribution. With `max_contributions=1000` (customizable), this allows encoding 1000 bits of cross-site information per report for only 1000 budget units — far exceeding the intended ~16 bits per budget period.

## Severity: Medium (Privacy Budget Design Flaw)

## Affected Component

- Private Aggregation API
- SharedStorage worklets
- Protected Audience worklets

## Root Cause

`content/browser/private_aggregation/private_aggregation_budgeter.cc:665-670`:
```cpp
base::CheckedNumeric<int> total_budget_needed = std::accumulate(
    contributions.begin(), contributions.end(),
    /*init=*/base::CheckedNumeric<int>(0), /*op=*/
    [](base::CheckedNumeric<int> running_sum,
       const blink::mojom::AggregatableReportHistogramContribution&
           contribution) { return running_sum + contribution.value; });
```

Budget only sums `contribution.value`. The `filtering_id` field is ignored entirely in the budget calculation.

## How Filtering IDs Create Independent Channels

The aggregation service processes reports by grouping contributions into separate aggregation outputs per `(bucket, filtering_id)` pair. Each unique filtering_id produces a separate query result with independent noise added. From the API user's perspective:
- contribution(bucket=X, value=1, filtering_id=0) → Aggregation channel 0
- contribution(bucket=X, value=1, filtering_id=1) → Aggregation channel 1
- contribution(bucket=X, value=1, filtering_id=N) → Aggregation channel N

Each channel encodes 1 bit of information (present vs absent), but only costs 1 unit of budget.

## Budget Model Discrepancy

**Intended model**: Budget = 65536 per 10 minutes. Intended information capacity ≈ log2(65536) = 16 bits.

**Actual model with filtering IDs**: Budget = 65536, but each unit of budget creates an independent bit channel via filtering_id. Actual information capacity = min(max_contributions_per_report × reports_per_budget_window, 65536) bits.

With `kMaxContributionsWhenCustomized = 1000` and budget per 10min = 65536:
- Max reports per 10min window = 65536/1000 = 65 reports
- Information per report = 1000 bits (one per contribution with unique filtering_id)  
- Total = 65,000 bits per 10 minutes (vs intended 16 bits)

## Configuration Limits

| Parameter | Value | Source |
|---|---|---|
| `kMaximumFilteringIdMaxBytes` | 8 | `aggregatable_report.h:45` |
| `kDefaultFilteringIdMaxBytes` | 1 | `private_aggregation_host.h:103` |
| `kMaxContributionsSharedStorage` | 20 | `private_aggregation_host.cc:243` |
| `kMaxContributionsProtectedAudience` | 100 | `private_aggregation_host.cc:244` |
| `kMaxContributionsWhenCustomized` | 1000 | `private_aggregation_host.cc:245` |
| Per-10min budget | 65536 | `kSmallerScopeValues` |
| Per-day budget | 65536 | `kLargerScopeValues` |

## Attack Scenario

```javascript
// In a SharedStorage worklet:
class LeakDataOp {
  async run(data) {
    const crossSiteData = await sharedStorage.get('user-profile');
    // Encode each bit of cross-site data as a distinct filtering_id
    for (let i = 0; i < crossSiteData.length; i++) {
      const bit = crossSiteData.charCodeAt(i);
      for (let b = 0; b < 8; b++) {
        if ((bit >> b) & 1) {
          privateAggregation.contributeToHistogram({
            bucket: BigInt(i * 8 + b),
            value: 1,
            filteringId: BigInt(i * 8 + b)  // Unique filtering ID per bit
          });
        }
      }
    }
  }
}
register('leak-data', LeakDataOp);
```

Budget cost: (number of 1-bits in data) × 1 ≤ max_contributions
Information leaked: up to max_contributions bits per report

## Mitigation Considerations

1. **Budget should account for filtering_id diversity**: Charge budget proportional to `log2(unique_filtering_ids + 1)` or cap the number of distinct filtering_ids per report.
2. **Alternatively**: The aggregation service's noise should scale with the number of distinct filtering_ids, but this is outside Chrome's control.
3. **Default filtering_id_max_bytes = 1** limits to 256 possible IDs per report, which still allows 256 independent channels for 256 budget.

## Files

- `content/browser/private_aggregation/private_aggregation_budgeter.cc:665-670` (budget calculation)
- `content/browser/private_aggregation/private_aggregation_host.cc:243-262` (max contributions)
- `content/browser/aggregation_service/aggregatable_report.h:45` (max filtering ID bytes)
- `content/browser/private_aggregation/private_aggregation_pending_contributions.h:42-58` (ContributionMergeKey includes filtering_id)

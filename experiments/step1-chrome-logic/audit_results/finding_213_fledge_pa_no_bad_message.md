# Finding 213: FLEDGE Private Aggregation Doesn't Report Bad Messages for Invalid Values

## Summary

Multiple functions in FLEDGE Private Aggregation utility code clamp or ignore invalid values from the worklet process instead of reporting bad messages. NaN/infinity bucket scales, negative contribution values, and invalid signal values are all silently handled rather than killing the compromised worklet process. This is acknowledged in multiple TODOs.

## Affected Files

- `content/browser/interest_group/interest_group_pa_report_util.cc:125` — NaN/infinity bucket scale not reported
- `content/browser/interest_group/interest_group_pa_report_util.cc:183` — Same for signal bucket
- `content/browser/interest_group/interest_group_pa_report_util.cc:241` — Negative value not reported
- `content/browser/interest_group/interest_group_pa_report_util.cc:359` — Invalid contribution not reported

## Details

```cpp
// interest_group_pa_report_util.cc:124-128
// TODO(crbug.com/40254312): Throw a bad message if scale is NaN or infinity.
if (std::isnan(scaled_base_value)) {
    return std::nullopt;  // Just returns nullopt, no kill
}

// interest_group_pa_report_util.cc:236-243
if (value < 0) {
    // ...the worklet process may be compromised. Since it has no
    // effect on the result of the auction, we just clamp it to 0 instead of
    // terminate the auction.
    // TODO(crbug.com/40254406): Report a bad mojom message when int value is
    // negative.
    value = 0;  // Clamp and continue, no kill
}
```

The comments explicitly acknowledge that negative values could indicate a compromised worklet process but choose not to terminate it.

## Attack Scenario

1. Compromised auction worklet sends Private Aggregation contributions with invalid values
2. NaN/infinity scales are silently converted to nullopt (skipped)
3. Negative contribution values are clamped to 0
4. The worklet is NOT terminated and can continue participating in auctions
5. The compromised worklet can:
   - Continue manipulating auction outcomes
   - Send further malicious Private Aggregation reports
   - Probe for edge cases in the aggregation pipeline
   - Use timing differences between NaN/valid values as a side channel

## Impact

- **Requires compromised worklet process**: Not standard API usage
- **Defense-in-depth failure**: Known compromised process not terminated
- **Auction integrity**: Compromised worklet continues affecting auctions
- **Systematic pattern**: 4+ locations with the same missing check

## VRP Value

**Low-Medium** — Defense-in-depth issue in FLEDGE Private Aggregation. Requires compromised worklet process, but the code explicitly acknowledges the compromise possibility and still doesn't terminate the process. The systematic nature (4+ locations) suggests a broader gap in worklet process validation.

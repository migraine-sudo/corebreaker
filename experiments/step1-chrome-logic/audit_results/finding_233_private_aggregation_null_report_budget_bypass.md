# Finding 233: Private Aggregation Null Reports Bypass Budget, Leaking Timing Information

## Summary

When Private Aggregation sends null reports (empty contributions), the budget system is completely bypassed. The existence and timing of these null reports reveals 1 bit of cross-site information per report without any budget cost. An attacker's reporting server can distinguish "worklet ran but had no data" from "worklet ran and had data but budget was exhausted" by observing which type of report arrives.

## Severity: Low-Medium (Budget-Free Side Channel)

## Affected Component

- Private Aggregation API
- SharedStorage worklets
- Protected Audience worklets

## Root Cause

`content/browser/private_aggregation/private_aggregation_manager_impl.cc:154-168`:
```cpp
if (contributions_wrapper.GetPendingContributions().IsEmpty()) {
    CHECK_EQ(null_report_behavior,
             PrivateAggregationHost::NullReportBehavior::kSendNullReport);
    RecordManagerResultHistogram(RequestResult::kSentWithoutContributions);
    OnContributionsFinalized(std::move(report_request_generator),
                             /*contributions=*/{}, budget_key.caller_api());
    return;  // Skips budgeter entirely
}
```

Also in `private_aggregation_manager_impl.cc:345-376`:
When budget is denied and `NullReportBehavior::kSendNullReport` is set, the denied contributions are cleared and a null report is sent — the budget denial itself becomes a signal.

## Information Leakage Model

From the attacker's reporting endpoint:
1. **Null report arrives quickly** → worklet completed without making contributions → user has no cross-site data matching the attacker's query
2. **Regular report arrives** → user has cross-site data (contributions were made)
3. **Null report arrives after delay** → budget was exhausted (contributions existed but were denied), revealing prior Private Aggregation activity

Each of these distinguishable outcomes leaks at least 1 bit of information without consuming any privacy budget.

## Feature Gate

Requires `kPrivateAggregationApiErrorReporting` to be ENABLED for the null report path to be active for budget denial cases. For the empty-contributions case, it requires `NullReportBehavior::kSendNullReport` (active for Protected Audience worklets).

## Files

- `content/browser/private_aggregation/private_aggregation_manager_impl.cc:154-168` (empty contributions bypass)
- `content/browser/private_aggregation/private_aggregation_manager_impl.cc:345-376` (budget-denied null report)

# Finding 243: COOP Reporting Always-True Self-Comparison Bug

## Summary

In `content/browser/security/coop/cross_origin_opener_policy_status.cc`, the COOP violation reporting logic at lines 275 and 303 contains a self-comparison bug: `response_origin.IsSameOriginWith(response_origin)` — comparing `response_origin` with itself is always `true`. This causes COOP navigation reports to always be queued regardless of the actual origin relationship, potentially sending reports to websites that shouldn't receive them.

## Root Cause

**File:** `content/browser/security/coop/cross_origin_opener_policy_status.cc:275,303`

```cpp
// Line 270-278: Within cross_origin_policy_swap block:
if (cross_origin_policy_swap) {
    if (has_other_window_in_browsing_context_group) {
      if (response_origin.IsSameOriginWith(response_origin)) {  // BUG: always true
        response_reporter->QueueNavigationToCOOPReport(
            current_url_, current_origin_.IsSameOriginWith(response_origin),
            false /* is_report_only */);
      }
      ...
    }
}

// Line 301-307: Same pattern in report-only block:
if (virtual_browsing_instance_swap) {
    if (has_other_window_in_browsing_context_group) {
      if (response_origin.IsSameOriginWith(response_origin)) {  // BUG: always true
        response_reporter->QueueNavigationToCOOPReport(
            current_url_, current_origin_.IsSameOriginWith(response_origin),
            true /* is_report_only */);
      }
      ...
    }
}
```

## Analysis

The condition at line 275 appears to be a copy-paste error. Looking at the context:

- The check should gate whether the `QueueNavigationToCOOPReport` is generated
- The second parameter to `QueueNavigationToCOOPReport` (line 277, 305) correctly passes `current_origin_.IsSameOriginWith(response_origin)` — indicating the code DID intend to compare different origins
- The gating condition was likely meant to check something like `current_origin_.IsSameOriginWith(response_origin)` or a condition on the reporter's origin

Since the self-comparison is always true, the `if` guard is effectively dead code — the report is always queued.

## Security Severity

**Low (reporting only).** 

The COOP enforcement itself is NOT affected:
- Line 237: `browsing_instance_swap_ |= cross_origin_policy_swap;` correctly uses `ShouldSwapBrowsingInstanceForCrossOriginOpenerPolicy()`
- The BrowsingInstance swap (the actual security mechanism) is properly computed

The impact is limited to:
1. COOP violation reports being generated unconditionally (could leak the previous document URL to the response reporter when it shouldn't)
2. `QueueNavigationToCOOPReport` receives `current_url_` which contains the URL of the previous document. If the condition were properly gated, some navigations might NOT report the previous URL.
3. This is an information leak in the Reporting API context — the response's COOP report endpoint receives `current_url_` (the URL the user navigated FROM) in cases where it perhaps shouldn't.

## Potential Privacy Impact

When a user navigates from `https://sensitive.com/private-page` to `https://attacker.com` (which has `COOP: same-origin` with a reporting endpoint), the attacker's reporting endpoint will receive a report containing `https://sensitive.com/private-page` as the "previousResponseURL" in the COOP report body.

If the gating condition at line 275 were properly implemented (e.g., checking whether the origins differ, which is when cross-origin URL exposure should be restricted), this leak might be prevented.

## Suggested Fix

The intent is likely to check whether the current (previous) document's origin matches the response origin, to decide whether to expose the previous URL in the report:

```cpp
// Option A: Gate on whether origins differ (only report cross-origin navigations)
if (!current_origin_.IsSameOriginWith(response_origin)) {
    response_reporter->QueueNavigationToCOOPReport(...);
}

// Option B: Always report (if the self-comparison was intentionally always-true)
// Then just remove the dead-code if statement entirely:
response_reporter->QueueNavigationToCOOPReport(...);
```

The correct fix depends on the spec's intent for COOP reporting.

## References

- `content/browser/security/coop/cross_origin_opener_policy_status.cc:275,303`
- https://gist.github.com/annevk/6f2dd8c79c77123f39797f6bdac43f3e (COOP spec)
- COOP reporting spec: https://html.spec.whatwg.org/#cross-origin-opener-policy-reporting

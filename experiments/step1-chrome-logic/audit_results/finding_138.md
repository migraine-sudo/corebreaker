# Finding 138: Contamination Delay Timing Side Channel in Cross-Site Prefetch

## Summary
The `ContaminationDelayNavigationThrottle` attempts to mitigate a timing side channel when a cross-site prefetch response is served. However, the delay calculation uses the actual network timing from the prefetched response (`receive_headers_end - send_start`), which can be manipulated by the target server. If the target server responds very quickly, the delay is minimal and the attacker page can still distinguish between "user has cookies for target.com" (prefetch blocked, fresh network request) vs. "user has no cookies" (prefetch served with short artificial delay) by measuring navigation timing.

## Affected Files
- `content/browser/preloading/prefetch/contamination_delay_navigation_throttle.cc` (lines 26-46)
- `content/browser/preloading/prefetch/prefetch_features.cc` (lines 37-42) - `kPrefetchStateContaminationMitigation` flag
- `content/browser/preloading/prefetch/prefetch_service.cc` (lines 1072-1089) - Cookie check and contamination marking

## Details
```cpp
// contamination_delay_navigation_throttle.cc:30-42
if (response && response->is_prefetch_with_cross_site_contamination) {
    CHECK(navigation_request->IsInMainFrame())
        << "subframes should not use prefetches which may span network "
           "partitions";
    // This delay is approximately the amount of the the request would take if
    // we were sending a fresh request over a warm connection.
    base::TimeDelta delay = response->load_timing.receive_headers_end -
                            response->load_timing.send_start;
    timer_.Start(FROM_HERE, delay,
                 base::BindOnce(&ContaminationDelayNavigationThrottle::Resume,
                                base::Unretained(this)));
    return DEFER;
}
```

The contamination delay mechanism works as follows:
1. When a cross-site prefetch is served and the user had no cookies (so the prefetch was eligible), the response is marked with `is_prefetch_with_cross_site_contamination = true`
2. On navigation, the throttle adds a delay equal to `receive_headers_end - send_start` of the original prefetch
3. This delay is meant to simulate a fresh request, hiding whether the response was prefetched

**The flaw**: The delay is based on the *prefetched response's own timing*, which is controlled by the target server. An attacker colluding with the target server (or an attacker controlling both the referring page and the prefetch target) can ensure the prefetch response arrives very quickly (< 1ms). In this case, the contamination delay is near-zero, and the attacker can distinguish between:
- **No cookies**: Prefetch succeeds, navigation is instant (~0ms contamination delay + cached response)  
- **Has cookies**: Prefetch is ineligible, navigation requires a fresh network request (>50ms typically)

Additionally, when `kPrefetchStateContaminationMitigation` is enabled but the delegate reports `IsContaminationExempt`, the contamination marking is skipped entirely.

## Attack Scenario
1. `https://evil.com` includes speculation rules to prefetch `https://tracking-service.com/pixel`
2. `tracking-service.com` is configured to respond in < 1ms
3. The user navigates to `https://tracking-service.com/pixel`
4. If the user had no cookies for `tracking-service.com`: response is instant (prefetch served, ~0ms delay)
5. If the user had cookies: fresh network request required (measurable delay of 50-200ms)
6. `evil.com` can observe navigation timing via `performance.getEntriesByType('navigation')` or `PerformanceObserver` on a subsequent page load

## Impact
Medium - Allows cross-site cookie presence detection, which is a privacy violation. The contamination delay mitigation is insufficient when the target server has very low latency.

## VRP Value
Medium

# Finding 137: Prefetch NIK Scope Disabled by Default Allows Cross-Partition Cache Probing

## Summary
The `kPrefetchNIKScope` feature flag is `FEATURE_DISABLED_BY_DEFAULT`. When disabled, navigational prefetches are scoped to the referring document token rather than the Network Isolation Key (NIK). This means prefetch requests are not properly partitioned by the top-level site, potentially allowing an attacker to use prefetch timing to probe whether a cross-origin resource exists in a different partition's cache, or to use prefetch responses in a way that crosses partition boundaries.

## Affected Files
- `content/browser/preloading/prefetch/prefetch_features.cc` (line 21) - Flag defined disabled
- `content/browser/preloading/prefetch/prefetch_features.h` (lines 33-35) - Flag with comment explaining the issue
- `content/browser/preloading/prefetch/prefetch_key.cc` (lines 15-30) - Different key construction based on flag
- `content/browser/preloading/prefetch/prefetch_params.cc` (lines 291-293) - `PrefetchNIKScopeEnabled()` function

## Details
```cpp
// prefetch_features.h:33-35
// If enabled, navigational prefetch is scoped to the referring document's
// network isolation key instead of the old behavior of the referring document
// itself. See crbug.com/1502326
BASE_DECLARE_FEATURE(kPrefetchNIKScope);
```

```cpp
// prefetch_key.cc:15-21
PrefetchKey::PrefetchKey(
    std::optional<blink::DocumentToken> referring_document_token,
    GURL url)
    : referring_document_token_or_nik_(std::move(referring_document_token)),
      url_(std::move(url)) {
  CHECK(!PrefetchNIKScopeEnabled());
}
```

When `kPrefetchNIKScope` is disabled (the default), prefetch keys are scoped by `DocumentToken` rather than `NetworkIsolationKey`. This means:
1. Prefetch cache lookups are not partition-aware at the NIK level
2. Two documents from different top-level sites that navigate to the same URL could potentially interact through the prefetch cache
3. The prefetch's network isolation does not align with the cache partitioning that regular navigations use

## Attack Scenario
1. Attacker page `https://evil.com` adds speculation rules to prefetch `https://target.com/api/user-data`
2. The prefetch is keyed by the document token, not by NIK
3. When the user navigates to `https://target.com`, the prefetched response may be served from a context that was fetched under a different partition scope
4. Timing of whether the prefetch was served vs. needed a fresh fetch could leak information about the user's prior visits to `target.com` from a different context

## Impact
Low-Medium - The practical exploitability depends on the exact interaction between prefetch caching and network partitioning. The fix (crbug.com/1502326) has been pending but remains disabled.

## VRP Value
Low

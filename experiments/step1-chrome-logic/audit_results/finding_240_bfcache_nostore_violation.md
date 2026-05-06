# Finding 240: BFCache Stores and Restores Cache-Control: no-store Pages by Default

## Summary

Chrome's `kCacheControlNoStoreEnterBackForwardCache` feature is ENABLED by default, causing pages with `Cache-Control: no-store` headers to be stored in BFCache and restored on back/forward navigation without re-fetching from the server. The only guard is a cookie-change check. This violates the HTTP semantics of `no-store` and can expose stale sensitive content.

## Severity: Low-Medium (Privacy/Spec Compliance)

## Affected Component

- Back/Forward Cache implementation
- `content/browser/renderer_host/back_forward_cache_impl.cc`
- `content/public/common/content_features.cc:232-233`

## Root Cause

`content/public/common/content_features.cc:232-233`:
```cpp
BASE_FEATURE(kCacheControlNoStoreEnterBackForwardCache,
             base::FEATURE_ENABLED_BY_DEFAULT);
```

With default parameter `kStoreAndRestoreUnlessCookieChange` (line 393-403):
```cpp
const base::FeatureParam<CacheControlNoStoreExperimentLevel>
    cache_control_level{
        &features::kCacheControlNoStoreEnterBackForwardCache,
        kCacheControlNoStoreExperimentLevelName,
        CacheControlNoStoreExperimentLevel::kStoreAndRestoreUnlessCookieChange,
        &cache_control_levels};
```

## Security/Privacy Implications

### 1. Stale Content Exposure
A banking app that sets `Cache-Control: no-store` on account balance pages intends for fresh content on every access. With BFCache, the user navigating back sees the old balance/transaction list without a re-fetch.

### 2. Session State Leak After Logout
If a user logs out (clearing session cookie), then presses back:
- Cookie-change detection MAY work (if the session cookie is `HttpOnly`)
- But with level `kStoreAndRestoreUnlessCookieChange`, ALL cookies must be checked
- Level `kStoreAndRestoreUnlessHTTPOnlyCookieChange` only checks HttpOnly cookies — a JavaScript-set session indicator won't trigger eviction

### 3. Shared Computer Risk
On shared computers, `no-store` pages were previously guaranteed to not be cached. Now they persist in BFCache memory. If the browser isn't fully closed, the next user pressing back could see previous user's content.

### 4. Spec Violation
RFC 9111 §5.2.2.5: "The no-store response directive indicates that a cache MUST NOT store any part of either the immediate request or the response."

While BFCache is technically different from HTTP cache, the intent of `no-store` is clear: the server does not want this content persisted. Many security-sensitive applications rely on this directive.

## Limitations

- The page IS evicted if cookies change (providing some protection for session-based auth)
- BFCache only stores content for the same user session
- The restored page runs with its original security context
- No cross-origin access to the restored content is possible

## Why This Might Be VRP-Reportable

While Chrome team is aware of this behavior (they implemented it), the combination of:
1. ENABLED by default
2. Violates established HTTP semantics that security architects rely on
3. Can expose sensitive content to the same physical device user after session invalidation

makes this a potential VRP candidate under "user-facing security guarantee that doesn't hold."

## Platform

All platforms (desktop and mobile Chrome).

## Files

- `content/public/common/content_features.cc:232-233` (feature ENABLED by default)
- `content/browser/renderer_host/back_forward_cache_impl.cc:374-413` (experiment levels)
- `content/browser/renderer_host/back_forward_cache_impl.cc:223-245` (disallowed features for no-store)

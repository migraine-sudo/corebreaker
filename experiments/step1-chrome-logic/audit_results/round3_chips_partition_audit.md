# Round 3: CHIPS / Cookie Partitioning Security Audit

**Auditor**: Claude Opus 4.6 automated audit  
**Date**: 2026-04-30  
**Scope**: Chromium CHIPS implementation, CookiePartitionKey, AncestorChainBit, SAA+CHIPS interaction, Service Worker partition keys  
**Threat Model**: Attacker controls their own site, can create iframes/popups. No compromised renderer.

---

## Executive Summary

Audit of the Chromium CHIPS (Cookies Having Independent Partitioned State) implementation identified several areas of concern, including one medium-severity finding related to ancestor chain bit computation in Service Worker forwarded navigation requests, and multiple design observations that represent hardened-but-notable attack surface areas.

---

## FINDING-242: Service Worker Navigation Forwarding Forces kSameSite AncestorChainBit

**Severity**: Medium  
**Type**: Partition Key Confusion / AncestorChainBit Misassignment  
**Status**: Needs verification  

### Description

When a Service Worker intercepts and forwards a main-frame navigation request, the flag `force_main_frame_for_same_site_cookies` is set to `true` in `url_loader_util.cc:508-511`:

```cpp
url_request.set_force_main_frame_for_same_site_cookies(
    request.mode == mojom::RequestMode::kNavigate &&
    request.destination == mojom::RequestDestination::kEmpty &&
    request.original_destination == mojom::RequestDestination::kDocument);
```

This flag propagates into the cookie partition key computation in `url_request.cc:525-533`:

```cpp
bool is_main_frame_navigation = isolation_info.IsMainFrameRequest() ||
                                force_main_frame_for_same_site_cookies();

cookie_partition_key_ = CookiePartitionKey::FromNetworkIsolationKey(
    isolation_info.network_isolation_key(), isolation_info.site_for_cookies(),
    net::SchemefulSite(redirect_info_new_url.has_value()
                           ? redirect_info_new_url.value()
                           : url_chain_.back()),
    is_main_frame_navigation);
```

In `CookiePartitionKey::FromNetworkIsolationKey` (cookie_partition_key.cc:170-171):

```cpp
} else if (main_frame_navigation) {
    ancestor_chain_bit = AncestorChainBit::kSameSite;
}
```

The issue: when a Service Worker registered in a first-party context intercepts a navigation that is being loaded in a cross-site subframe, the `force_main_frame_for_same_site_cookies` causes `is_main_frame_navigation` to be true. This forces the `ancestor_chain_bit` to `kSameSite`, even though the actual browsing context is cross-site (it's a subframe navigation being forwarded through a SW).

This means the Set-Cookie response for this forwarded navigation could set partitioned cookies with `(top_level_site, kSameSite)` partition key, when the correct key should be `(top_level_site, kCrossSite)`. A cookie set with `kSameSite` is distinct from one with `kCrossSite`, so this could allow:

1. A third-party iframe whose navigation goes through a SW to set cookies into the same-site partition, which it would not normally be able to do
2. These same-site-partitioned cookies might later be read by a same-site first-party context that shouldn't see third-party data

### Attack Scenario

1. Attacker registers a Service Worker on `https://evil.example`
2. Attacker's page is embedded as an iframe on `https://target.example`
3. A navigation within the iframe is intercepted by the SW and forwarded
4. The forwarded request gets `force_main_frame_for_same_site_cookies = true`
5. Cookies set in the response get partition key `(target.example, kSameSite)` instead of `(target.example, kCrossSite)`
6. If target.example later checks for same-site-partitioned cookies from evil.example, these cookies are visible

### Mitigation Note

The `cors_url_loader_factory.cc:684-691` validates that `original_destination == kDocument` only when `mode == kNavigate` and `destination == kEmpty`, which limits this to SW-forwarded navigations. The practical exploitability depends on whether the IsolationInfo passed to the SW URL loader factory correctly identifies this as a subframe request (in which case `IsMainFrameRequest()` would already return false and the flag would only affect the `||` branch).

### Files

- `/Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step1-chrome-logic/chromium-src/services/network/url_loader_util.cc:508-511`
- `/Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step1-chrome-logic/chromium-src/net/url_request/url_request.cc:525-533`
- `/Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step1-chrome-logic/chromium-src/net/cookies/cookie_partition_key.cc:164-177`

---

## FINDING-243: site_for_cookies Divergence Between URLRequest Member and IsolationInfo During Subframe Redirects

**Severity**: Low (defense-in-depth concern)  
**Type**: Inconsistency in partition key computation  
**Status**: Needs verification  

### Description

During a subframe redirect in `url_request.cc:1084-1090`:

```cpp
site_for_cookies_ = redirect_info.new_site_for_cookies;  // URLRequest member updated
set_isolation_info(isolation_info_.CreateForRedirect(
                       url::Origin::Create(redirect_info.new_url)),
                   redirect_info.new_url);  // IsolationInfo preserves old site_for_cookies
```

The URLRequest's `site_for_cookies_` member is updated to `redirect_info.new_site_for_cookies`, but the partition key is computed from the IsolationInfo's `site_for_cookies()`, which for subframe redirects (`CreateForRedirect` at isolation_info.cc:308-311) preserves the ORIGINAL value.

In `IsolationInfo::CreateForRedirect` for `kSubFrame`:
```cpp
return IsolationInfo(
    request_type(), top_frame_origin(), new_origin, site_for_cookies(),  // OLD site_for_cookies
    nonce(), GetNetworkIsolationPartition(), frame_ancestor_relation());
```

This means the partition key's `ancestor_chain_bit` is computed using the old `site_for_cookies` compared against the new `request_site` (redirect destination). While this is likely intentional (the subframe's relationship to the top-level site doesn't change during redirects), it creates a state where:

- `url_request_->site_for_cookies()` returns the new value (used for SameSite cookie decisions in cookie access checks)
- The partition key's ancestor_chain_bit was computed from the old value

If a subframe navigation A(top)->B(iframe)->redirect to C, where B and C are different sites:
- The IsolationInfo's site_for_cookies stays as the original (A)
- The partition key computes: `!A.IsFirstParty(C)` - using old site_for_cookies vs new URL
- The URLRequest's site_for_cookies is updated to the redirect-computed value

This inconsistency is unlikely to cause a direct bypass since the IsolationInfo-based computation appears correct, but the dual state is a code clarity/maintenance concern.

### Files

- `/Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step1-chrome-logic/chromium-src/net/url_request/url_request.cc:1084-1090`
- `/Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step1-chrome-logic/chromium-src/net/base/isolation_info.cc:302-322`

---

## FINDING-244: ValidateAccessToCookiesAt Regression - DCHECK Downgraded to LOG(ERROR)

**Severity**: Low (regression tracking)  
**Type**: Validation weakening  
**Status**: Active regression per crbug.com/402207912  

### Description

In `restricted_cookie_manager.cc:1145-1161`, the validation of renderer-supplied `site_for_cookies` and `top_frame_origin` was downgraded from DCHECK (crash in debug builds) to LOG(ERROR):

```cpp
bool site_for_cookies_ok =
    BoundSiteForCookies().IsEquivalent(site_for_cookies);
// TODO(crbug.com/402207912): Switch back to a DCEHCK once this condition
// always holds again.
if (!site_for_cookies_ok) {
    LOG(ERROR) << "site_for_cookies from renderer='" ...
}
```

The mismatched values are logged but the function does NOT return false. The function only rejects when the URL doesn't match the bound origin. While the renderer-supplied `site_for_cookies` and `top_frame_origin` flow into `MakeOptionsForGet` (affecting SameSite cookie context) and `AnnotateAndMoveUserBlockedCookies` (affecting which cookies are blocked by settings), they do NOT affect the partition key collection (which is fixed at RestrictedCookieManager creation time).

Without a compromised renderer, the renderer should always send matching values. However, this represents a weakened validation that should be tracked.

### Files

- `/Users/migriane/Downloads/fuzzmind/corebreaker/experiments/step1-chrome-logic/chromium-src/services/network/restricted_cookie_manager.cc:1135-1183`

---

## Design Analysis (No Direct Vulnerability Found)

### 1. Partition Key Computation via FromNetworkIsolationKey

The core logic in `cookie_partition_key.cc:131-180` is sound:

- **Nonce case**: Forces `kCrossSite` and uses frame site (aligned with StorageKey). Correct.
- **Main frame navigation**: Forces `kSameSite` (no ancestor). Correct.
- **Null site_for_cookies**: Forces `kCrossSite` (opaque origin). Correct.
- **Normal case**: Compares `site_for_cookies` with `request_site`. Correct.

The partition key site always comes from `GetTopFrameSite()` (non-nonce case), which is the correct top-level site for CHIPS.

### 2. Popup / window.open Partition Key

Popups are main frames. `ComputeTopFrameOrigin` (render_frame_host_impl.cc:5461-5477) returns the popup's own origin for main frames. The partition key is `(popup_url_site, kSameSite)`.

- **with opener**: Same behavior - popup gets its own top-level partition key
- **with noopener**: Same behavior
- **about:blank popup**: Gets an opaque origin, resulting in an opaque SchemefulSite. CookiePartitionKey is not serializable (cookie_partition_key.cc:255-257), so no persistent partitioned cookies can be set. about:blank inherits the opener's origin for scripting but the partition key computation happens based on the actual committed URL origin.

Conclusion: Popups correctly get their own partition context. No bypass via opener relationships.

### 3. A embeds B embeds A (Nested Cross-Site Iframes)

The `ComputeIsolationInfoInternal` (render_frame_host_impl.cc:5516-5569) walks up the entire frame tree:

```cpp
for (const RenderFrameHostImpl* rfh = initial_rfh; rfh; rfh = rfh->parent_) {
    candidate_site_for_cookies.CompareWithFrameTreeSiteAndRevise(cur_site);
}
```

For A -> B -> A:
- Top frame: A
- Candidate site_for_cookies starts as A
- Walk: inner A checks B, which is cross-site with A, so site_for_cookies becomes null
- `ancestor_chain_bit` becomes `kCrossSite` (because site_for_cookies is null)

The inner A correctly gets `(A, kCrossSite)` partition key, distinct from the outer A's unpartitioned context. This is correct.

### 4. Storage Access API + CHIPS Interaction

When SAA grants access (`kAccessViaAPI`):
- `RestrictedCookieManager::GetCookieSettingOverrides` adds `kStorageAccessGrantEligible` to overrides
- The `cookie_partition_key_collection_` is NOT changed - it still contains only the partitioned key
- In `CookieMonster::GetCookieListWithOptions`, unpartitioned cookies ARE included in the initial result set (because `IncludeUnpartitionedCookies` returns true for non-nonced keys)
- The unpartitioned cookies then go through `AnnotateAndMoveUserBlockedCookies` which uses cookie settings to decide if they're accessible
- With SAA grant, the cookie settings check may allow the unpartitioned cookies through

This is working as designed: SAA grants access to unpartitioned cookies for the granted origin. The partition key is not modified - instead, the cookie settings layer allows the unpartitioned cookies through. This is the intended SAA+CHIPS interaction per spec.

**Key observation**: `ShouldAddInitialStorageAccessApiOverride` (cookie_util.cc:1192-1198) uses `IsSameOriginWith`, not same-site. This correctly prevents cross-origin subframes from piggybacking on a sibling's SAA grant. On cross-origin redirects (url_loader.cc:1034-1038), SAA overrides are cleared.

### 5. Service Worker Partition Keys

SW script requests use `StorageKey::ToPartialNetIsolationInfo()` (storage_key.cc:793-800) which creates `RequestType::kOther`. The cookie partition key for SW subresource requests inherits from the SW's storage key via `ToCookiePartitionKey()` (storage_key.cc:828-833).

For a SW registered in first-party context (e.g., on `https://example.com`):
- Storage key: `(example.com, example.com, kSameSite)`
- Partition key: `(example.com, kSameSite)`
- Fetch requests from this SW get this partition key

For a SW registered in third-party context (e.g., `https://third-party.com` in iframe on `https://example.com`):
- Storage key: `(third-party.com, example.com, kCrossSite)`
- Partition key: `(example.com, kCrossSite)`

The SW uses the partition key from its registration context for ALL fetch requests it makes. This is correct - a SW cannot escalate its cookie access by intercepting requests from different contexts.

### 6. `<meta http-equiv="set-cookie">` vs HTTP Header

`<meta http-equiv="set-cookie">` is completely blocked in Chromium (http_equiv.cc:158-166):

```cpp
void HttpEquiv::ProcessHttpEquivSetCookie(Document& document,
                                          const AtomicString& content,
                                          Element* element) {
  document.AddConsoleMessage(/* error: blocked */);
}
```

No cookie is set. No partition key mismatch is possible. This attack surface is eliminated.

### 7. Redirect Chain Partition Key (A -> B -> A)

For a request that redirects through sites A -> B -> A:
- Initial partition key: based on the initiating context
- After redirect to B: partition key recomputed with B as request_site
- After redirect back to A: partition key recomputed with A as request_site

The top_level_site in the partition key stays constant (from NetworkIsolationKey). Only the ancestor_chain_bit changes based on whether request_site matches site_for_cookies. For a subframe redirect chain, site_for_cookies is preserved from the original IsolationInfo, so the final A gets the same ancestor_chain_bit as if it had been loaded directly.

No partition key confusion via redirect chains.

---

## Summary of Findings

| ID | Title | Severity | Exploitable? |
|----|-------|----------|--------------|
| FINDING-242 | SW Navigation Forwarding Forces kSameSite AncestorChainBit | Medium | Needs PoC |
| FINDING-243 | site_for_cookies Divergence in Subframe Redirects | Low | Unlikely |
| FINDING-244 | ValidateAccessToCookiesAt DCHECK Downgraded | Low | Not without compromised renderer |

## Recommendations

1. **FINDING-242**: Investigate whether `force_main_frame_for_same_site_cookies` should ONLY affect SameSite cookie decisions and NOT partition key computation. Consider separating the `is_main_frame_navigation` flag for partition key from the SameSite cookie flag.

2. **FINDING-243**: Add a DCHECK or comment documenting the intentional divergence between URLRequest::site_for_cookies_ and IsolationInfo::site_for_cookies() during subframe redirects.

3. **FINDING-244**: Track crbug.com/402207912 for re-enabling the DCHECK. Ensure this doesn't persist as a permanent weakening.

# Finding 165: Isolated Cookie Copy Uses CookiePartitionKeyCollection::Todo() Skipping Partitioned Cookies (CHIPS)

## Summary
The prefetch isolated cookie copy flow in `PrefetchSingleRedirectHop::CopyIsolatedCookies()` and the cookie eligibility check in `PrefetchService::OnGotCookiesForEligibilityCheck()` both use `CookiePartitionKeyCollection::Todo()` when calling `GetCookieList()`. The `Todo()` method returns an empty key collection, which means **no partitioned cookies** (CHIPS) are returned. This creates two distinct issues: (1) the cookie eligibility check may falsely determine a user has no cookies for a cross-site target (because partitioned cookies are invisible to it), causing a prefetch to proceed that should be ineligible, and (2) when an isolated cookie copy is performed at serving time, partitioned cookies set by the prefetched response are silently lost.

## Affected Files
- `content/browser/preloading/prefetch/prefetch_service.cc` (lines 1044-1051) - Cookie eligibility check
- `content/browser/preloading/prefetch/prefetch_single_redirect_hop.cc` (lines 191-195) - Isolated cookie copy read
- `net/cookies/cookie_partition_key_collection.h` (lines 57-67) - Todo() returns empty collection

## Details
```cpp
// net/cookies/cookie_partition_key_collection.h:57-67
// Temporary method used to record where we need to decide how to build the
// CookiePartitionKeyCollection.
//
// Returns an empty key collection, so no partitioned cookies will be returned
// at callsites this is used.
//
// TODO(crbug.com/40188414): Remove this method and update callsites to use
// appropriate constructor.
static CookiePartitionKeyCollection Todo() {
  return CookiePartitionKeyCollection();
}
```

```cpp
// prefetch_service.cc:1044-1051 - Eligibility check
net::CookieOptions options = net::CookieOptions::MakeAllInclusive();
options.set_return_excluded_cookies();
const GURL url = params.url;
default_storage_partition->GetCookieManagerForBrowserProcess()->GetCookieList(
    url, options, net::CookiePartitionKeyCollection::Todo(),
    base::BindOnce(&PrefetchService::OnGotCookiesForEligibilityCheck,
                   weak_method_factory_.GetWeakPtr(), std::move(params)));
```

```cpp
// prefetch_single_redirect_hop.cc:191-195 - Cookie copy read
net::CookieOptions options = net::CookieOptions::MakeAllInclusive();
isolated_network_context->GetCookieManager()->GetCookieList(
    url_, options, net::CookiePartitionKeyCollection::Todo(),
    base::BindOnce(&PrefetchSingleRedirectHop::OnGotIsolatedCookiesForCopy,
                   weak_ptr_factory_.GetWeakPtr()));
```

The `Todo()` placeholder returns an empty `CookiePartitionKeyCollection`, which causes `CookieMonster` to skip the partitioned cookie map entirely. This means:
1. **Eligibility check**: A user who has partitioned cookies for a target site (via CHIPS `Partitioned` attribute) but no unpartitioned cookies will be treated as having no cookies at all. The prefetch will proceed as if the user never interacted with the target site.
2. **Cookie copy**: When copying cookies from the isolated network context to the default context, partitioned cookies are invisible and silently dropped.

## Attack Scenario
1. User visits `https://social-network.com` which sets a partitioned cookie via CHIPS: `Set-Cookie: __Host-session=abc; Partitioned; Secure; Path=/`
2. User then visits `https://referring-site.com` which has speculation rules to prefetch `https://social-network.com/profile`
3. The eligibility check at `PrefetchService::OnGotCookiesForEligibilityCheck` sees an empty cookie list (because `Todo()` skips partitioned cookies) and treats the user as having no cookies
4. The prefetch proceeds without the user's partitioned session cookie, fetching `social-network.com/profile` as a logged-out user
5. At serving time, the cookie copy from isolated context misses the partitioned cookies set during prefetch
6. The user navigates to `social-network.com/profile` and sees the logged-out version, potentially causing confusion or state inconsistency
7. More critically, the referring site can observe (via timing) whether the prefetch was eligible (no cookies) vs ineligible (has cookies), which now bypasses the CHIPS privacy model

## Impact
Medium - The use of `Todo()` in cookie eligibility and copy flows creates a systematic blind spot for CHIPS partitioned cookies. This affects both privacy (the eligibility decision leaks information about cookie state) and correctness (partitioned cookies are lost during copy). As CHIPS adoption grows, this gap becomes more impactful.

## VRP Value
Medium

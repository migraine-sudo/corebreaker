# Finding 144: Cookie Partitioning Uses Renderer-Supplied site_for_cookies Instead of Browser-Authoritative Value

## Summary

The network service's URL loader uses `url_request_->site_for_cookies()` (renderer-supplied) instead of `url_request_->isolation_info().site_for_cookies()` (browser-authoritative) when computing cookie partition keys. Combined with Finding 136's downgraded DCHECK validation for `site_for_cookies` in `RestrictedCookieManager`, a compromised renderer can manipulate cookie partitioning decisions.

## Affected Files

- `services/network/url_loader.cc:2246-2254` — Uses untrusted `site_for_cookies()`
- `services/network/restricted_cookie_manager.cc` (Finding 136) — DCHECK downgraded to LOG(ERROR)

## Details

```cpp
// url_loader.cc:2246-2254
// TODO when crbug.com/40093296 "Don't trust |site_for_cookies| provided by
// the renderer" is fixed. Update the FromNetworkIsolationKey method to use
// url_request_->isolation_info().site_for_cookies() instead of
// url_request_->site_for_cookies().
std::optional<net::CookiePartitionKey> partition_key =
    net::CookiePartitionKey::FromNetworkIsolationKey(
        url_request_->isolation_info().network_isolation_key(),
        url_request_->site_for_cookies(), request_site,  // ← RENDERER VALUE
        is_main_frame_navigation);
```

The `CookiePartitionKey` computation depends on `site_for_cookies` to determine which partition cookies belong to. A compromised renderer can supply a false `site_for_cookies`, causing:

1. Cookies to be placed in the wrong partition
2. Cross-site cookies to appear as same-site
3. Cookie partition isolation to be defeated

This is explicitly acknowledged in the TODO referencing crbug.com/40093296.

## Attack Scenario

1. Compromised renderer creates a request with a spoofed `site_for_cookies` matching the target site
2. The network service computes the cookie partition key using this spoofed value
3. Partitioned cookies that should be isolated to a different first-party context become accessible
4. The attacker reads or writes cookies in the wrong partition

## Impact

- **Requires compromised renderer**: Yes, for spoofing `site_for_cookies`
- **Cookie partition bypass**: Defeats third-party cookie partitioning (CHIPS)
- **Cross-site tracking**: Circumvents partitioned cookie isolation
- **Known issue**: crbug.com/40093296

## VRP Value

**Medium** — Requires compromised renderer, but the impact is significant: complete bypass of cookie partitioning (CHIPS). The explicit TODO confirms this is a known gap in the browser-renderer trust boundary.

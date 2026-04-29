# Finding 226: CookieManager Change Listeners Missing Partition Key - Cross-Partition Observation

## Summary

The `CookieManager::AddCookieChangeListener` method registers cookie change listeners with `std::nullopt` as the cookie partition key. This means the listener receives notifications for cookie changes across ALL partitions, not just the partition relevant to the listener's context. The TODO comment at line 255 explicitly notes: "Include the correct cookie partition key when attaching cookie change listeners to service workers."

This allows a CookieManager client (typically used by service workers or browser-level consumers) to observe cookie changes that occur in other partition contexts, potentially leaking cross-partition information.

## Affected Files

- `services/network/cookie_manager.cc` lines 254-265:
  ```cpp
  if (name) {
    // TODO(crbug.com/40188414): Include the correct cookie partition
    // key when attaching cookie change listeners to service workers.
    listener_registration->subscription =
        cookie_store_->GetChangeDispatcher().AddCallbackForCookie(
            url, *name, std::nullopt, std::move(cookie_change_callback));
            //          ^^^^^^^^^^^^ No partition key filtering!
  } else {
    // TODO(crbug.com/40188414): Include the correct cookie partition
    // key when attaching cookie change listeners to service workers.
    listener_registration->subscription =
        cookie_store_->GetChangeDispatcher().AddCallbackForUrl(
            url, std::nullopt, std::move(cookie_change_callback));
            //   ^^^^^^^^^^^^ No partition key filtering!
  }
  ```

Compare with `RestrictedCookieManager::Listener` (line ~297 of restricted_cookie_manager.cc) which correctly passes `cookie_partition_key` to `AddCallbackForUrl`.

## Code Snippet

```cpp
// CookieManager (INCORRECT - no partition key):
cookie_store_->GetChangeDispatcher().AddCallbackForUrl(
    url, std::nullopt, std::move(cookie_change_callback));

// RestrictedCookieManager (CORRECT - has partition key):
cookie_store_->GetChangeDispatcher().AddCallbackForUrl(
    url, cookie_partition_key,
    base::BindRepeating(&Listener::OnCookieChange, base::Unretained(this)));
```

## Attack Scenario

1. Service worker on `https://tracker.com` registers a cookie change listener via `CookieManager::AddCookieChangeListener` for cookies on `https://site.com`
2. User visits `https://site-a.com` which embeds `https://site.com` in a cross-site context
3. `site.com` sets a partitioned cookie `__Host-id=alice` with partition key `(site-a.com)`
4. User visits `https://site-b.com` which also embeds `https://site.com`
5. `site.com` sets a partitioned cookie `__Host-id=bob` with partition key `(site-b.com)`
6. The service worker's change listener receives notifications for BOTH cookie changes, even though partitioned cookies are designed to be isolated per partition
7. The service worker observes the cookie values and names across different partition contexts

Note: This primarily affects the `CookieManager` mojo interface (used by browser process and service workers), not the `RestrictedCookieManager` interface (used by page-level script). The severity depends on who has access to the `CookieManager` interface.

## Impact

- **Severity**: Low-Medium (cross-partition information leak via cookie change observation)
- **Requires compromised renderer**: No, but requires access to `CookieManager` mojo interface (typically browser-level or service worker)
- **Security principle violated**: Cookie partitioning should be enforced consistently across all access paths
- The TODO comment (crbug.com/40188414) confirms this is a known issue
- Partitioned cookies (CHIPS) are specifically designed to prevent cross-site tracking
- The CookieManager's lack of partition filtering undermines this isolation

## VRP Value Rating

Low-Medium - This is a known issue tracked at crbug.com/40188414. The CookieManager interface is typically available to browser-level consumers (not directly to web content), which limits the attack surface. However, if a service worker or extension has access to this interface, they can observe cross-partition cookie changes that should be isolated.

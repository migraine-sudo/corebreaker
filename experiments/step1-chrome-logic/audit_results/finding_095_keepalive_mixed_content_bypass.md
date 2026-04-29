# Finding 095: KeepAlive Fetch Mixed Content Check Bypassed When Renderer Dies

## Summary

When a `fetch({keepalive: true})` or `fetchLater()` request is redirected after the initiating renderer has died, the mixed content check is SKIPPED because `GetInitiator()` returns null. This allows HTTPS→HTTP redirects that would normally be blocked.

## Affected Files

- `content/browser/loader/keep_alive_url_loader.cc:1222-1230` — Mixed content check skipped when no initiator

## Details

```cpp
// keep_alive_url_loader.cc:1222-1230
// TODO(crbug.com/40941240): Figure out how to check without a frame.
if (auto* rfh = GetInitiator();
    rfh && MixedContentChecker::ShouldBlockFetchKeepAlive(
               rfh, redirect_info.new_url,
               /*for_redirect=*/true)) {
  return net::ERR_FAILED;
}
// When rfh is null (renderer died): mixed content check SKIPPED
```

This is exactly the scenario keepalive requests are designed for — surviving renderer death.

## Attack Scenario

1. Page on `https://attacker.com` issues `fetchLater("https://attacker.com/endpoint")` or `fetch(url, {keepalive: true})` in `beforeunload`
2. User navigates away, renderer dies
3. Server redirects the keepalive request to `http://victim-internal-server/sensitive-data`
4. Mixed content check is skipped because `GetInitiator()` returns null
5. The insecure request succeeds, potentially reaching internal HTTP servers

### Alternative: SSRF via Mixed Content Bypass

1. `fetchLater("https://attacker.com/redirect")` 
2. User navigates away
3. Attacker server responds with 302 to `http://192.168.1.1/admin/api`
4. Request reaches internal network over HTTP (mixed content would normally block this)

## Impact

- **No compromised renderer required**: Standard `fetchLater()` / `fetch({keepalive: true})` API
- **Mixed content bypass**: HTTPS→HTTP redirect succeeds
- **SSRF potential**: Can redirect to internal HTTP services after page unload
- **Known issue**: TODO with crbug.com/40941240

## VRP Value

**High** — No compromised renderer. Standard web API. Clear attack scenario with SSRF potential via mixed content bypass on keepalive redirects.

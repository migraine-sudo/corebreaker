# Finding 091: WebRequest Blocked Requests Map Shared Across Incognito/Regular Contexts

## Summary

The `WebRequestEventRouter::GetBlockedRequestMap()` stores blocked requests from incognito browsing in the regular profile's data map, leaking incognito request information across contexts.

## Affected Files

- `extensions/browser/api/web_request/extension_web_request_event_router.cc:2614-2621` — Blocked requests redirected to regular context

## Details

```cpp
// extension_web_request_event_router.cc:2614-2621
WebRequestEventRouter::BlockedRequestMap&
WebRequestEventRouter::GetBlockedRequestMap(
    content::BrowserContext* browser_context) {
  // TODO(crbug.com/40279375): Blocked requests should be isolated to
  // a particular BrowserContext and not shared between the main and
  // OTR contexts.
  if (browser_context->IsOffTheRecord()) {
    browser_context = GetCrossBrowserContext(browser_context);
  }
  return data_[GetBrowserContextID(browser_context)].blocked_requests;
}
```

## Attack Scenario

1. User browses in incognito with a webRequest-blocking extension active
2. Extension blocks requests in incognito (e.g., ad-blocker)
3. Blocked request IDs from incognito appear in the regular context's blocked-requests map
4. Extension observes these IDs from the regular context
5. Can infer incognito browsing patterns from blocked request timing

## Impact

- **No compromised renderer required**: Malicious extension with webRequestBlocking permission
- **Incognito leak**: Request blocking state leaks across contexts
- **Known issue**: crbug.com/40279375

## VRP Value

**Medium** — Incognito information leak via shared blocked-requests map. Known bug but unfixed.

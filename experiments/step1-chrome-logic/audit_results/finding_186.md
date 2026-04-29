# Finding 186: Extension WebRequest Listener Deactivation Silently Unblocks All Pending Requests Without Response

## Summary
When an extension's webRequest event listener is deactivated (e.g., because the service worker shuts down), all requests blocked by that listener are silently unblocked by calling `DecrementBlockCount` with a `nullptr` response. This means the requests proceed as if the extension had never intercepted them. The TODO (crbug.com/40107353) explicitly acknowledges "This likely won't be sufficient, since it means requests can leak through." This is a fundamental design gap in MV3 service worker-based extensions that silently defeats security/filtering extensions.

## Affected Files
- `extensions/browser/api/web_request/extension_web_request_event_router.cc` (lines 2185-2195)

## Details

```cpp
// Unblock any request that this event listener may have been blocking.
// Note that we do this even for deactivations, since if the service worker
// is shut down (which would happen if it reached the hard lifetime timeout),
// it won't be able to respond to the request.
// TODO(crbug.com/40107353): This likely won't be sufficient, since it
// means requests can leak through.
for (uint64_t blocked_request_id : listener.blocked_requests) {
    DecrementBlockCount(listener.id.browser_context, listener.id.extension_id,
                        event_name, blocked_request_id, nullptr,
                        0 /* extra_info_spec */);
}
```

The `nullptr` response means:
1. The request proceeds with no modifications (as if the extension approved it).
2. `cancel` is not set, so the request is not cancelled.
3. `redirect_url` is not set, so no redirect occurs.
4. All header modifications are lost.
5. Authentication credentials are not modified.

This affects ALL request types including:
- `onBeforeRequest` blocking (can block/redirect requests)
- `onBeforeSendHeaders` blocking (can modify request headers)
- `onHeadersReceived` blocking (can modify response headers)
- `onAuthRequired` blocking (can provide authentication credentials)

For security extensions, this means:
- Content blockers: Blocked requests silently load.
- Privacy extensions: Modified headers revert (referrer stripping lost).
- Parental controls: All restrictions silently lifted.
- Security scanners: All intercepted requests proceed unchecked.

## Attack Scenario
1. A web page that wants to bypass a content blocker (e.g., to load tracking scripts) identifies that the blocker is a MV3 extension.
2. The page creates many long-running requests that the extension must block.
3. The extension's service worker processes the `onBeforeRequest` events and blocks them.
4. The service worker hits the 5-minute hard lifetime timeout.
5. The browser deactivates the listener, triggering the code above.
6. ALL blocked requests are silently unblocked, including tracking scripts, ads, and malware.
7. The tracking scripts execute in the user's browser.
8. The user sees no indication that their blocker was bypassed.

Alternative timing attack:
1. The attacker's page opens many iframes simultaneously, each loading a different URL.
2. The content blocker's service worker processes the requests.
3. The service worker is kept busy processing events, approaching the idle timeout.
4. When the worker shuts down, all pending blocked requests are released.
5. Some of the attacker's requests succeed during this window.

## Impact
Medium-High. This is a fundamental security limitation of MV3's service worker model for webRequest-based security extensions. The TODO confirms this is a known, unresolved issue. Users relying on MV3 content blockers, parental controls, or security extensions have a silent bypass window whenever the service worker shuts down. The hardcoded extension IDs in `kDefaultSWExtendedLifetimeList` (Smart Card Connector, Citrix, VMware) show that Google is aware of the lifetime problem for specific use cases, but the general case remains unaddressed.

## VRP Value
Medium-High

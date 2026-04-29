# Finding 164: Payment App Icon Fetcher Same-Origin Check Uses DeprecatedGetOriginAsURL Comparison

## Summary
The `PaymentInstrumentIconFetcher` performs a same-origin check using `DeprecatedGetOriginAsURL().spec().compare()` string comparison, which is a deprecated API. The `DeprecatedGetOriginAsURL()` method returns a URL representation of the origin which may have subtly different semantics than proper origin comparison methods (like `url::IsSameOriginWith` or `url::Origin::IsSameOriginWith`).

## Affected Files
- `content/browser/payments/payment_instrument_icon_fetcher.cc:138-142` - Deprecated origin comparison

## Details
```cpp
// payment_instrument_icon_fetcher.cc
if (scope.DeprecatedGetOriginAsURL().spec().compare(
        manifest_icons[i]
            .src.DeprecatedGetOriginAsURL()
            .spec()) != 0) {
  // Not same origin, skip this icon
  continue;
}
```

Issues with this approach:
1. `DeprecatedGetOriginAsURL()` is explicitly marked as deprecated in the codebase
2. String comparison of URL specs may not handle all normalization cases correctly (e.g., trailing slashes, default port numbers, punycode)
3. The proper way to compare origins in Chromium is `url::IsSameOriginWith()` or `url::Origin::IsSameOriginWith()`, which handle edge cases like opaque origins, port normalization, etc.

This check determines whether a payment instrument icon URL is same-origin with the payment app's scope. If the check incorrectly passes for a cross-origin icon URL, the browser would download and display an icon from a different origin, which could be used for:
- UI spoofing (displaying a trusted provider's icon for a malicious handler)
- SSRF-like behavior (fetching URLs from the user's network context)

## Attack Scenario
1. A payment handler at `https://evil-pay.com:443/` registers with an icon URL that has a subtly different origin representation
2. The string comparison of `DeprecatedGetOriginAsURL().spec()` may normalize differently than expected
3. For example, if one URL normalizes to `https://evil-pay.com:443/` and the scope normalizes to `https://evil-pay.com/` (without port), the string comparison would fail (rejecting a same-origin icon), leading to a denial of service for the icon fetch
4. Conversely, edge cases in URL normalization could cause a cross-origin comparison to match

## Impact
The use of deprecated API creates a defense-in-depth concern. The primary risk is incorrect same-origin determination for icon fetching. In practice, `DeprecatedGetOriginAsURL()` is likely equivalent for most cases, but the deprecated status means it may not be maintained and could diverge from proper origin semantics in the future.

## VRP Value
Low

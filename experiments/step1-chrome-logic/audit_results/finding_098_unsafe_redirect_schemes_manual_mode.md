# Finding 098: kAllowUnsafeRedirectSchemesForManualMode Bypasses ALL Redirect Scheme Checks

## Summary

The `kAllowUnsafeRedirectSchemesForManualMode` feature flag (DISABLED by default) would allow `fetch(url, {redirect: "manual"})` to bypass ALL URL redirect scheme safety checks at the `URLRequestHttpJob` level when enabled. This would allow observing redirects to `data:`, `blob:`, `file:`, and internal schemes.

## Affected Files

- `services/network/url_loader_util.cc:585-593` — Sets `treat_all_redirects_as_safe`
- `services/network/public/cpp/features.cc:627-628` — DISABLED_BY_DEFAULT
- `net/url_request/url_request_http_job.cc:1569-1577` — `IsSafeRedirect` bypassed

## Details

```cpp
// url_loader_util.cc:585-593
if (base::FeatureList::IsEnabled(
        features::kAllowUnsafeRedirectSchemesForManualMode)) {
    url_request.set_treat_all_redirects_as_safe(
        request.redirect_mode == mojom::RedirectMode::kManual &&
        request.destination == mojom::RequestDestination::kEmpty);
}

// url_request_http_job.cc:1569-1577
bool URLRequestHttpJob::IsSafeRedirect(const GURL& location) {
  if (request_->treat_all_redirects_as_safe()) {
    return true;  // ALL scheme checks bypassed
  }
```

## Impact

- **Currently DISABLED**: No current risk
- **If enabled**: Web pages could learn about redirects to internal schemes
- **No compromised renderer**: Pure web API (`fetch()` with `redirect: "manual"`)

## VRP Value

**Low** — Currently disabled. Documenting for awareness in case it gets enabled.

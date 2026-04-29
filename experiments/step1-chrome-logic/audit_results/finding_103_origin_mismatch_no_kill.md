# Finding 103: Origin Header Mismatch Only DumpWithoutCrashing, Not Renderer Kill

## Summary

When a renderer provides an `Origin` header that doesn't match the browser-calculated origin, the browser only does a `DumpWithoutCrashing` but does NOT kill the renderer or reject the navigation. For HTTP methods that don't "need" an Origin header per the browser's determination, the renderer-supplied Origin value may persist.

## Affected Files

- `content/browser/renderer_host/navigation_request.cc:421-448` — Origin mismatch handling
- `content/browser/renderer_host/ipc_utils.cc:466-494` — Origin in allowlist

## Details

```cpp
// navigation_request.cc:421-448
if (existing_origin && existing_origin != serialized_origin &&
    !is_browser_initiated && !is_history &&
    base::FeatureList::IsEnabled(features::kDumpOnOriginHeaderMismatch)) {
  // TODO(https://crbug.com/487795397): this should
  // be a `bad_message::ReceivedBadMessage` and return `false` once
  // DumpWithoutCrashing data is evaluated.
  base::debug::DumpWithoutCrashing();
}
headers->SetHeader(net::HttpRequestHeaders::kOrigin, serialized_origin);
```

While the browser overwrites the Origin header for methods that "need" one, for methods where the browser determines Origin is NOT needed, it may not overwrite the renderer-supplied value. Combined with Finding 102 (VerifyNavigationHeaders allows all headers through), this creates a CSRF weakness.

## Attack Scenario

1. Compromised renderer sends navigation with forged Origin header
2. Browser detects mismatch but only logs a crash dump
3. Renderer is NOT killed, navigation proceeds
4. For certain HTTP methods where browser doesn't set its own Origin, the forged value reaches the server
5. Server-side CORS or Origin-based CSRF protection can be influenced

## Impact

- **Requires compromised renderer**: Yes
- **Weakened CSRF protection**: Renderer can probe Origin handling boundaries
- **Known issue**: crbug.com/487795397

## VRP Value

**Medium-High** — Directly weakens CSRF protection. The TODO explicitly says this should kill the renderer.

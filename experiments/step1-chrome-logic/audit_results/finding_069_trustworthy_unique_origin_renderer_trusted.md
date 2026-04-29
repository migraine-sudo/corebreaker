# Finding 069: has_potentially_trustworthy_unique_origin Trusted from Renderer at Commit

## Summary

When a navigation commits, the browser accepts `has_potentially_trustworthy_unique_origin` directly from the renderer's `DidCommitProvisionalLoadParams`. This boolean controls whether an opaque origin is considered "potentially trustworthy" (i.e., a secure context). A compromised renderer can claim any opaque origin is trustworthy, gaining access to secure-context-only APIs.

## Affected Files

- `content/browser/renderer_host/render_frame_host_impl.cc:5294-5295` — Renderer-supplied boolean accepted
- TODO at `render_frame_host_impl.cc:5774` acknowledges this should be derived browser-side

## Details

```cpp
// render_frame_host_impl.cc:5294-5295
SetLastCommittedOrigin(params.origin,
                       params.has_potentially_trustworthy_unique_origin);
```

The `params` struct comes from the renderer via DidCommitProvisionalLoad IPC. While `params.origin` is validated against `origin_to_commit`, the `has_potentially_trustworthy_unique_origin` boolean is not independently verified.

```cpp
// render_frame_host_impl.cc:5774
// TODO(https://crbug.com/40159049): Once we can always trust
// `network::IsOriginPotentiallyTrustworthy()` instead of passing around
// `has_potentially_trustworthy_unique_origin`, remove this.
```

## Attack Scenario

### Secure context upgrade for opaque origin (requires compromised renderer)

1. A page loads in an insecure context (HTTP) and creates a sandboxed iframe
2. The sandboxed iframe has an opaque origin (which is NOT potentially trustworthy because it was derived from HTTP)
3. A compromised renderer sends `has_potentially_trustworthy_unique_origin = true` in DidCommitParams
4. The browser marks the opaque origin as potentially trustworthy
5. The document gains secure context status
6. Secure-context-only APIs become available: `crypto.subtle`, ServiceWorker registration, Geolocation, etc.

## Impact

- **Requires compromised renderer**: Direct exploitation
- **Secure context upgrade**: Gains access to powerful APIs
- **Known issue**: crbug.com/40159049 tracks fixing this

## VRP Value

**Low-Medium** — Requires compromised renderer. The impact is access to secure-context APIs from an insecure context, which expands the attack surface after an initial compromise.

# Finding 208: Shared Storage No Bad Message for Insecure Context Requests

## Summary

When a renderer attempts to use Shared Storage from an insecure context, the browser-side code has a TODO acknowledging it should invoke `ReportBadMessage()` to kill the renderer, but doesn't. The code only returns an error message. This allows a compromised renderer to repeatedly probe Shared Storage from insecure contexts without being terminated.

## Affected Files

- `content/browser/shared_storage/shared_storage_document_service_impl.cc:178-180` — SharedStorageUpdate missing BadMessage
- `content/browser/shared_storage/shared_storage_document_service_impl.cc:216-218` — SharedStorageBatchUpdate missing BadMessage

## Details

```cpp
// shared_storage_document_service_impl.cc:174-181 (SharedStorageUpdate)
if (!CheckSecureContext(render_frame_host())) {
    std::move(callback).Run(
        /*error_message=*/kSharedStorageMethodFromInsecureContextMessage);
    // TODO(crbug.com/40068897): Invoke receiver_.ReportBadMessage here when
    // we can be sure honest renderers won't hit this path.
    return;
}

// shared_storage_document_service_impl.cc:212-219 (SharedStorageBatchUpdate)  
if (!CheckSecureContext(render_frame_host())) {
    std::move(callback).Run(
        /*error_message=*/kSharedStorageMethodFromInsecureContextMessage);
    // TODO(crbug.com/40068897): Invoke receiver_.ReportBadMessage here when
    // we can be sure honest renderers won't hit this path.
    return;
}
```

Contrast with the opaque origin check just above, which DOES call `receiver_.ReportBadMessage()`:
```cpp
if (render_frame_host().GetLastCommittedOrigin().opaque()) {
    receiver_.ReportBadMessage(
        "Attempted to call SharedStorageUpdate() from an opaque origin context.");
    return;
}
```

## Attack Scenario

1. Compromised renderer in an insecure (HTTP) context calls Shared Storage Mojo APIs
2. The browser rejects the request but does NOT kill the renderer
3. The renderer can continue making requests, probing for timing side-channels
4. The renderer can also continue other attack vectors since it wasn't terminated
5. An honest renderer should never call Shared Storage from an insecure context (the Blink-side check prevents it), so any such call indicates a compromised renderer

## Impact

- **Requires compromised renderer**: Normal renderers are blocked in Blink
- **Defense-in-depth failure**: Misbehaving renderer not terminated
- **Probing opportunity**: Repeated calls without termination enable timing analysis
- **Inconsistency**: Opaque origin check kills renderer; insecure context check doesn't

## VRP Value

**Low-Medium** — Defense-in-depth issue. The browser correctly rejects the request, but the renderer should be killed to prevent further abuse. The TODO explicitly acknowledges this should be fixed.

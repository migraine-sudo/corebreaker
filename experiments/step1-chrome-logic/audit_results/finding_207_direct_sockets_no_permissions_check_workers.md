# Finding 207: Direct Sockets Missing Permissions Policy Check in SharedWorker/ServiceWorker

## Summary

When creating Direct Sockets in SharedWorker or ServiceWorker contexts, the permissions policy check is explicitly skipped with TODO comments. In the RenderFrame context, Direct Sockets correctly checks `kMulticastInDirectSockets` permissions policy, but for SharedWorker and ServiceWorker, the lambda returns `true` unconditionally. This means a SharedWorker/ServiceWorker can use Direct Sockets without the embedding page having the permissions policy enabled.

## Affected Files

- `content/browser/direct_sockets/direct_sockets_service_impl.cc:171-184` — SharedWorker/ServiceWorker skip permissions policy
- `content/browser/direct_sockets/direct_sockets_service_impl.cc:452-456` — SharedWorker creation skips permission checks
- `content/browser/direct_sockets/direct_sockets_service_impl.cc:484-488` — ServiceWorker creation skips permission checks

## Details

```cpp
// direct_sockets_service_impl.cc:171-184
[](base::WeakPtr<SharedWorkerHost> shared_worker) {
    // No need to check flag DirectSocketsInSharedWorker,
    // since it was checked already
    // TODO(crbug.com/393539884): Add permissions policy check.
    return true;  // Always allows!
},
[](base::WeakPtr<ServiceWorkerVersion> service_worker) {
    // No need to check flag DirectSocketsInServiceWorker,
    // since it was checked already.
    // TODO(crbug.com/393539884): Add permissions policy check.
    return true;  // Always allows!
}

// direct_sockets_service_impl.cc:452-456
// SharedWorker - only checks isolation, NOT permissions
// TODO(crbug.com/393539884): Figure out the appropriate checks wrt permissions.
mojo::MakeSelfOwnedReceiver(
    base::WrapUnique(new DirectSocketsServiceImpl(shared_worker.AsWeakPtr())),
    std::move(receiver));

// direct_sockets_service_impl.cc:484-488
// ServiceWorker - only checks isolation, NOT permissions
// TODO(crbug.com/392843918): Figure out the appropriate checks wrt permissions.
mojo::MakeSelfOwnedReceiver(base::WrapUnique(new DirectSocketsServiceImpl(
                                service_worker.GetWeakPtr())),
                            std::move(receiver));
```

## Attack Scenario

1. Isolated Web App (IWA) has Direct Sockets permission for its main frame
2. IWA loads a SharedWorker or ServiceWorker
3. The worker gains full Direct Sockets access WITHOUT any permissions policy check
4. If the IWA's permissions policy is configured to restrict Direct Sockets to specific origins/features (e.g., only for the main frame, not workers), this restriction is bypassed
5. A compromised or malicious worker can open raw TCP/UDP sockets to any address, including local network devices

### Multicast attack variant
The RenderFrame path specifically checks `kMulticastInDirectSockets` permissions policy for multicast, but workers skip this entirely. A worker could use multicast Direct Sockets even when the page's permissions policy explicitly disables multicast.

## Impact

- **Requires Isolated Web App context**: Direct Sockets requires isolation
- **Permissions policy bypass**: Workers can use Direct Sockets without permissions policy checks
- **Multicast bypass**: Workers skip multicast-specific permissions check
- **Raw network access**: TCP/UDP sockets to arbitrary addresses including local network

## VRP Value

**Medium** — Permissions policy bypass in Direct Sockets for workers. While Direct Sockets already requires an Isolated Web App context (limiting exposure), the missing permissions policy check means workers get unrestricted access including multicast, bypassing per-feature policy controls.

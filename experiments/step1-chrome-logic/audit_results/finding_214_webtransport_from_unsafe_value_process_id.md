# Finding 214: WebTransport Uses FromUnsafeValue for Process ID Conversion

## Summary

`WebTransportConnectorImpl` stores the process ID as a raw `int` (`process_id_`) and later converts it using `ChildProcessId::FromUnsafeValue()` to create a `URLLoaderNetworkObserver` for ServiceWorker/SharedWorker contexts. The TODO comment at the call site (crbug.com/379869738) acknowledges this is unsafe. `FromUnsafeValue` bypasses the type-safety that `ChildProcessId` provides, and if the `process_id_` value were somehow corrupted or reused (process ID recycling after crash), it could result in the WebTransport connection getting an observer for a different process.

## Affected Files

- `content/browser/webtransport/web_transport_connector_impl.cc` lines 258-264:
  ```cpp
  // TODO(crbug.com/379869738): Remove FromUnsafeValue.
  url_loader_network_observer =
      static_cast<StoragePartitionImpl*>(storage_partition)
          ->CreateURLLoaderNetworkObserverForServiceOrSharedWorker(
              ToOriginatingProcessId(
                  ChildProcessId::FromUnsafeValue(process_id_)),
              origin_);
  ```
- `content/browser/webtransport/web_transport_connector_impl.h` line 75:
  ```cpp
  const int process_id_;
  ```

## Code Snippet

```cpp
// web_transport_connector_impl.cc:255-265
} else {
    content::StoragePartition* storage_partition =
        process->GetStoragePartition();
    // TODO(crbug.com/379869738): Remove FromUnsafeValue.
    url_loader_network_observer =
        static_cast<StoragePartitionImpl*>(storage_partition)
            ->CreateURLLoaderNetworkObserverForServiceOrSharedWorker(
                ToOriginatingProcessId(
                    ChildProcessId::FromUnsafeValue(process_id_)),
                origin_);
}
```

Compare with the WebSocket connector which uses `GlobalRenderFrameHostId` and `ToOriginatingProcessId(frame_id_.child_id)` which is type-safe.

## Attack Scenario

1. A ServiceWorker or SharedWorker creates a WebTransport connection
2. The `process_id_` is stored as a raw `int` in the connector
3. If the renderer process crashes and a new process is created with the same PID
4. The `FromUnsafeValue` conversion may associate the WebTransport observer with the wrong process
5. This could cause security-relevant network events (SSL errors, LNA checks) to be reported to the wrong observer
6. In the worst case, a malicious new process could influence the handling of an existing WebTransport connection's security decisions

This is primarily a type-safety issue that could become exploitable under process recycling conditions.

## Impact

- **Severity**: Low (type-safety issue, potential for process confusion)
- **Requires compromised renderer**: No, but requires specific timing
- **Security principle violated**: Type-safe process identification; the tracked bug confirms this is a known issue
- The process_id check at line 187 (`RenderProcessHost::FromID(process_id_)`) partially mitigates this

## VRP Value Rating

Low - The tracked bug (crbug.com/379869738) suggests this is a known type-safety debt. The security impact is limited because process ID reuse requires specific timing and the observer lifetime is typically short.

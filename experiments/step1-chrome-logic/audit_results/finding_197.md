# Finding 197: Extension Worker ID Set Does Not Enforce Single-Worker Invariant in Release

## Summary
The `WorkerIdSet::Insert()` method in `worker_id_set.cc` has a commented-out CHECK that would enforce at most one active service worker per extension. The current code allows multiple concurrent active workers for the same extension without any enforcement in release builds. The TODO (crbug.com/40936639) acknowledges that the CHECK has been disabled because multiple active workers is an unresolved condition. This means an extension could have two simultaneous active service workers, each with their own state, potentially leading to conflicting API operations, doubled event handling, and race conditions in extension state management.

## Affected Files
- `extensions/browser/service_worker/worker_id_set.cc` (lines 87-99)
- `extensions/browser/api/runtime/runtime_api.cc` (line 864)
- `extensions/browser/service_worker/service_worker_state.cc` (lines 108-122)

## Details

In `worker_id_set.cc`:
```cpp
workers_.insert(worker_id);
size_t new_size = previous_worker_ids.size() + 1;
base::UmaHistogramExactLinear(
    "Extensions.ServiceWorkerBackground.WorkerCountAfterAdd", new_size,
    kMaxWorkerCountToReport);

if (!g_allow_multiple_workers_per_extension) {
  // TODO(crbug.com/40936639): Enable this CHECK once multiple active workers
  // is resolved.
  // CHECK_LE(new_size, 1u) << "Extension with worker id "
  //                        << worker_id
  //                        << " added additional worker";
}
```

The CHECK is commented out, and the flag `g_allow_multiple_workers_per_extension` defaults to false -- but even when false, no enforcement occurs (the CHECK that would enforce it is commented out).

In `service_worker_state.cc` (lines 108-122), the same bug tracking reference shows the problem in `SetWorkerId()`:
```cpp
void ServiceWorkerState::SetWorkerId(const WorkerId& worker_id) {
  // ...
  // TODO(crbug.com/40936639): upgrade to CHECK and/or add
  // DumpWithoutCrashing here if the old_worker hasn't been reset.
}
```

In `runtime_api.cc` (line 864), the same issue is tracked:
```cpp
// TODO(crbug.com/40936639): Enable this CHECK once multiple active workers is
// resolved.
```

The consequences of multiple active workers:
1. **Doubled event handling**: Both workers receive the same events (webRequest, messaging, alarms), potentially causing duplicate actions.
2. **Conflicting state**: Each worker may hold different in-memory state, leading to inconsistent extension behavior.
3. **Resource exhaustion**: The extension effectively gets double the resource allocation (memory, CPU time).
4. **Keepalive confusion**: Each worker has independent keepalive tracking; one worker shutting down may not properly clean up if the other is still active.

## Attack Scenario
1. An extension's service worker is active and handling events.
2. Due to a race condition in the service worker lifecycle (e.g., during an update or restart), a second worker instance starts before the first is properly terminated.
3. Both workers are registered in the `WorkerIdSet` (the CHECK that would prevent this is commented out).
4. Both workers receive `webRequest.onBeforeRequest` events.
5. Both workers respond to a blocked request, potentially with conflicting decisions (one blocks, one allows).
6. The `DecrementBlockCount` receives two responses for the same request, potentially causing a use-after-free or double-free condition in the blocked request tracking.

Alternative scenario for messaging:
7. A web page sends a message to the extension via `runtime.sendMessage()`.
8. Both active workers receive the message and call `sendResponse()`.
9. The message port receives two responses, potentially causing the web page to process conflicting data.

## Impact
Medium. The disabled CHECK represents a known race condition (crbug.com/40936639) where multiple active workers can coexist. While Chrome tracks this via histogram metrics (suggesting it does happen in practice), the lack of enforcement means the system operates in an undefined state that could lead to security-relevant inconsistencies in webRequest handling, message routing, and permission enforcement.

## VRP Value
Low-Medium

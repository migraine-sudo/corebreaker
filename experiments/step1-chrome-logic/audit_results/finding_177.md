# Finding 177: Service Worker Multiple Worker Instance DCHECK-Only Check Allows State Confusion

## Summary
In `ServiceWorkerState::SetWorkerId`, the check that verifies the old service worker is gone before accepting a new one is only a `DCHECK`, which is stripped in release builds. Additionally, a global flag `g_allow_multiple_workers_per_extension` can disable this check entirely. The associated TODO (crbug.com/40936639) explicitly states this should be upgraded to a `CHECK` once the bug is fixed. In release builds, two concurrent service worker instances for the same extension could lead to state confusion, where security operations (keepalives, permissions, event routing) reference the wrong worker instance.

## Affected Files
- `extensions/browser/service_worker/service_worker_state.cc` (lines 108-122)
- `extensions/browser/service_worker/service_worker_state.cc` (line 23)

## Details

```cpp
void ServiceWorkerState::SetWorkerId(const WorkerId& worker_id) {
  if (worker_id_ && *worker_id_ != worker_id) {
    // Sanity check that the old worker is gone.
    // TODO(crbug.com/40936639): remove
    // `g_allow_multiple_workers_per_extension` once bug is fixed so that this
    // DCHECK() will be default behavior everywhere. Also upgrade to a CHECK
    // once the bug is completely fixed.
    DCHECK(!process_manager_->HasServiceWorker(*worker_id_) ||
           g_allow_multiple_workers_per_extension);

    // Clear stale renderer state if there's any.
    renderer_state_ = RendererState::kNotActive;
  }

  worker_id_ = worker_id;
  CHECK(worker_id_->start_token);
}
```

The `g_allow_multiple_workers_per_extension` flag (line 23):
```cpp
// Prevent check on multiple workers per extension for testing purposes.
bool g_allow_multiple_workers_per_extension = false;
```

In release builds, the `DCHECK` is stripped, meaning:
1. If two worker instances coexist (due to a race during restart), `SetWorkerId` silently accepts the new ID.
2. The old worker may still be running and processing events.
3. Keepalive counts may be tracked against the wrong worker ID.
4. Security-relevant operations (permission checks, message routing) could reference the stale worker.

## Attack Scenario
1. An extension's service worker is in the process of shutting down (e.g., hit the idle timeout).
2. Simultaneously, an event triggers the service worker to restart.
3. Due to the race condition described in crbug.com/452178846, two worker instances briefly coexist.
4. The old worker is still processing a security-sensitive operation (e.g., intercepting a web request, processing a message).
5. The new worker's ID is set via `SetWorkerId`, replacing the old ID in the state tracking.
6. Security keepalives for the old worker are now orphaned, as they reference a worker ID no longer tracked.
7. The old worker's security operations complete without proper keepalive tracking, potentially allowing the worker to be killed mid-operation.
8. Alternatively, the old worker continues processing with stale state while the new worker receives new events, leading to event duplication or lost events.

## Impact
Medium. The race condition between worker shutdown and restart is acknowledged in the code (crbug.com/452178846, crbug.com/40936639). While the practical exploitability is limited, the DCHECK-only nature of the check means the condition can silently occur in production, leading to unpredictable behavior in security-relevant extension operations.

## VRP Value
Medium

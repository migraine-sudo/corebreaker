# Finding 183: Extension Service Worker Stale Process DumpWithoutCrashing Allows Operation on Dead Process

## Summary
In `ServiceWorkerState::DidStartWorkerForScope`, when the service worker layer invokes the callback with a stale process ID (one where the `RenderProcessHost` has already terminated), the code only calls `DumpWithoutCrashing()` and returns early. It does not properly clean up the worker state or fail the pending tasks. The worker_starting_ flag remains true (since `DidStartWorkerFail` is not called), causing the worker to remain in a "starting" limbo state. Pending tasks queued for this worker will never be dispatched or failed, creating a permanent task leak.

## Affected Files
- `extensions/browser/service_worker/service_worker_state.cc` (lines 169-185)

## Details

```cpp
void ServiceWorkerState::DidStartWorkerForScope(
    const SequencedContextId& context_id,
    base::Time start_time,
    int64_t version_id,
    content::ChildProcessId process_id,
    int thread_id,
    const blink::ServiceWorkerToken& token) {
  // ...
  // HACK: The service worker layer might invoke this callback with an ID for a
  // RenderProcessHost that has already terminated. This isn't the right fix for
  // this, because it results in the internal state here stalling out - we'll
  // wait on the browser side to be ready, which will never happen. This should
  // be cleaned up on the next activation sequence, but this still isn't good.
  // The proper fix here is that the service worker layer shouldn't be invoking
  // this callback with stale processes.
  // https://crbug.com/1335821.
  if (!content::RenderProcessHost::FromID(worker_id.render_process_id)) {
    // The IsLiveServiceWorkerWithToken() check above *should* have caught
    // this instance.
    base::debug::DumpWithoutCrashing();
    // TODO(crbug.com/40913640): Investigate and fix.
    LOG(ERROR) << "Received bad DidStartWorkerForScope() message. "
                  "No corresponding RenderProcessHost.";
    return;
  }
```

When this early return occurs:
1. `worker_starting_` remains `true` (set in `StartWorker()`, line 130).
2. `NotifyObserversIfReady()` is never called, so `worker_starting_` is never cleared.
3. `DidStartWorkerFail()` is never called, so `worker_starting_` is never cleared via that path either.
4. All pending tasks in `ServiceWorkerTaskQueue` for this context remain stuck.
5. `MaybeStartWorker()` checks `worker_state->IsStarting()` and returns immediately, preventing retries.
6. The extension's service worker is permanently stuck in a "starting" state until the next activation (extension reload/update).

## Attack Scenario
1. An extension with security-relevant functionality (content blocker, password manager) has its service worker idle.
2. An event occurs that should wake the service worker (e.g., a web request to be blocked).
3. Due to a race condition, the service worker layer invokes `DidStartWorkerForScope` with a terminated process.
4. The `DumpWithoutCrashing()` fires silently and returns.
5. The extension's service worker is stuck in "starting" state.
6. All pending and future tasks (event handlers, message responses, web request blocking decisions) are silently dropped.
7. The content blocker stops blocking, the password manager stops filling, etc.
8. This persists until the extension is manually reloaded or Chrome is restarted.

## Impact
Medium. While this is a race condition that requires specific timing, when it occurs, the extension silently loses all functionality. For security extensions (ad blockers, content filters, password managers), this creates a silent security gap. The code explicitly acknowledges this is a known issue (HACK comment, crbug.com/1335821, crbug.com/40913640).

## VRP Value
Medium

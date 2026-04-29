# Finding 175: Extension Service Worker Incognito Context Handling Unimplemented in AddPendingTask

## Summary
The `ServiceWorkerTaskQueue::AddPendingTask` method contains an explicit TODO comment acknowledging that incognito context handling is unimplemented: `// TODO(lazyboy): Do we need to handle incognito context?`. This means that when a pending task is queued for a service worker-based extension in an incognito context, the task may be dispatched to the wrong service worker instance (the regular profile's worker instead of the incognito one, or vice versa), potentially causing cross-profile data leakage.

## Affected Files
- `extensions/browser/service_worker/service_worker_task_queue.cc` (line 281)
- `extensions/browser/process_manager.cc` (line 995)
- `extensions/browser/extension_registrar.cc` (line 1126)

## Details

In `service_worker_task_queue.cc:270-314`:
```cpp
void ServiceWorkerTaskQueue::AddPendingTask(
    const LazyContextId& lazy_context_id,
    PendingTask task) {
  DCHECK(lazy_context_id.IsForServiceWorker());
  // ...metrics...

  // TODO(lazyboy): Do we need to handle incognito context?

  auto activation_token =
      GetCurrentActivationToken(lazy_context_id.extension_id());
  // ...
}
```

This is compounded by a related TODO in `process_manager.cc:995`:
```cpp
// TODO(lazyboy): Revisit this once incognito is tested for extension SWs, as
// the cleanup below only works because regular and OTR ProcessManagers are
// separate.
```

And the incognito-unsafe DevTools reattach in `extension_registrar.cc:1126`:
```cpp
// TODO(yoz): this is not incognito-safe!
ProcessManager* manager = ProcessManager::Get(browser_context_);
```

For split-mode extensions, each profile (regular and incognito) should have its own service worker instance. The `AddPendingTask` function retrieves the activation token using `lazy_context_id.extension_id()` without considering whether the `lazy_context_id.browser_context()` is an incognito context. If the wrong activation token is used, the pending task could be dispatched to the regular profile's service worker, which has access to the regular profile's state.

## Attack Scenario
1. A user installs an extension running in split mode (separate incognito instance).
2. In incognito mode, a web page triggers an event that should be handled by the incognito service worker.
3. Due to the unimplemented incognito handling, `AddPendingTask` may queue the task using the regular profile's activation token.
4. The task is dispatched to the regular profile's service worker instead of the incognito one.
5. The regular profile's service worker handles an event that should have been handled in the incognito context.
6. Data from the incognito browsing session (e.g., URLs, page content) is processed by the regular profile's worker, where it can be persisted or exfiltrated.

## Impact
Medium. The code explicitly acknowledges incognito handling is unimplemented for service worker task queuing. For split-mode extensions, this could lead to cross-profile data leakage. The `SequencedContextId` includes `browser_context_->UniqueId()` which provides some isolation, but the TODO indicates this isn't fully verified.

## VRP Value
Medium

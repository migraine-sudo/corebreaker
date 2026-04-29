# Finding 176: Extension Function source_url Unvalidated for Service Worker Requests

## Summary
When an extension API function is dispatched from a service worker, the `source_url` is taken directly from the renderer-supplied `mojom::RequestParams::source_url` without validation. There is an explicit TODO (crbug.com/40056469) acknowledging this should be validated or removed. For frame-based requests, the browser uses the trusted `GetLastCommittedURL()`, but for service worker requests, the renderer-controlled value is used. The `source_url` is subsequently used in security-relevant contexts including activity logging and quota tracking.

## Affected Files
- `extensions/browser/extension_function_dispatcher.cc` (lines 568-575)

## Details

In `DispatchWithCallbackInternal()`:
```cpp
// Determine the source URL. When possible, prefer fetching this value from
// the RenderFrameHost, but fallback to the value in the `params` object if
// necessary.
// We can't use the frame URL in the case of a worker-based request (where
// there is no frame).
if (is_worker_request) {
    // TODO(crbug.com/40056469): Validate this URL further. Or, better,
    // remove it from `mojom::RequestParams`.
    function->set_source_url(params_without_args.source_url);
} else {
    DCHECK(render_frame_host_url);
    function->set_source_url(*render_frame_host_url);
}
```

The `source_url` is then used:
1. In `NotifyApiFunctionCalled()` for activity logging (could be used to poison logs).
2. The `ExtensionFunction::source_url()` getter exposes this to individual API implementations.
3. Any API that checks `source_url()` for security decisions will be using an untrusted value for SW-based calls.

The `source_url` validation for messaging (`IsValidSourceUrl` in `message_service_bindings.cc`) is more thorough. But for general extension function dispatch, there is no such validation for service worker requests.

## Attack Scenario
1. A compromised extension service worker renderer calls an extension API.
2. The renderer sets `params.source_url` to a spoofed URL (e.g., `chrome-extension://other-extension-id/background.js`).
3. The browser trusts this value and sets it as the function's `source_url`.
4. Activity logs show API calls as originating from a different URL than the actual source.
5. If any API implementation uses `source_url()` for authorization decisions, the spoofed value could grant unauthorized access.

## Impact
Low-Medium. The primary risk is activity log poisoning and defense-in-depth weakness. The `source_url` is not the primary security boundary (extension ID validation provides that), but it is an additional context that could be relied upon by specific API implementations.

## VRP Value
Low

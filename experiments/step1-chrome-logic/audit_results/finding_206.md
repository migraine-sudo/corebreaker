# Finding 206: Extension Function Mojo Response Callback Leak Detection is DCHECK-Only

## Summary
In `ExtensionFunction::~ExtensionFunction()`, the check that the extension function responded before destruction (and the fallback Mojo callback invocation) is entirely gated behind `DCHECK_IS_ON()`. In release builds, if an extension function is destroyed without calling `Respond()`, the Mojo reply callback is never invoked. This leads to a Mojo pipe leak where the renderer's pending request is never resolved. For service worker-based extensions, this can cause the service worker to stay alive indefinitely waiting for a response that will never arrive, or cause the pending request callback to be leaked.

## Affected Files
- `extensions/browser/extension_function.cc` (lines 389-429)

## Details

```cpp
// The extension function should always respond to avoid leaks in the
// renderer, dangling callbacks, etc. The exception is if the system is
// shutting down or if the extension has been unloaded.
#if DCHECK_IS_ON()
  auto can_be_destroyed_before_responding = [this]() {
    // ... checks for shutdown, testing, browser_context, etc ...
    return false;
  };

  DCHECK(did_respond() || can_be_destroyed_before_responding()) << name();

  // If ignore_did_respond_for_testing() has been called it could cause another
  // DCHECK about not calling Mojo callback.
  // Since the ExtensionFunction request on the frame is a Mojo message
  // which has a reply callback, it should be called before it's destroyed.
  if (!response_callback_.is_null()) {
    constexpr char kShouldCallMojoCallback[] = "Ignored did_respond()";
    std::move(response_callback_)
        .Run(ResponseType::kFailed, base::ListValue(), kShouldCallMojoCallback,
             nullptr);
  }
#endif  // DCHECK_IS_ON()
```

In release builds:
1. The DCHECK that the function responded is removed -- no crash/assertion.
2. The fallback `response_callback_` invocation is removed -- the Mojo callback is never called.
3. The Mojo pipe associated with the request is leaked when the `response_callback_` member is destroyed without being invoked.

This has several consequences:
- **Renderer-side leak**: The renderer's pending request promise/callback is never resolved or rejected.
- **Service worker keepalive**: If the request was from a service worker, the keepalive associated with the request may not be decremented, keeping the worker alive indefinitely.
- **Memory accumulation**: Each leaked Mojo pipe consumes memory. Over time, if extension functions repeatedly fail to respond (e.g., due to browser context destruction during API calls), memory accumulates.

The comment explicitly states: "The extension function should always respond to avoid leaks in the renderer, dangling callbacks, etc." But the enforcement of this invariant is debug-only.

## Attack Scenario
1. An extension makes rapid API calls (e.g., `storage.get()`, `tabs.query()`).
2. While the API calls are in flight, the extension's browser context is destroyed (e.g., incognito window closed).
3. The extension functions are destroyed without responding because the browser context check in `PreRunValidation` doesn't cover all cases.
4. In debug builds, the DCHECK fires and the fallback response is sent.
5. In release builds, the Mojo callbacks are silently dropped.
6. The renderer's pending callbacks are never resolved.
7. For service worker extensions, the keepalive count may not be properly decremented, causing the worker to remain alive.

This is primarily a resource leak / DoS vector rather than a direct security bypass, but the accumulation of leaked Mojo pipes and stuck service workers can degrade browser performance.

## Impact
Low. This is primarily a resource management issue. The DCHECK-only response checking means that invariant violations (extension functions destroyed without responding) are not caught in release builds, leading to Mojo pipe leaks and potentially stuck service workers.

## VRP Value
Low

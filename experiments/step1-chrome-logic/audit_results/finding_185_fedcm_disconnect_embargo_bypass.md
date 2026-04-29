# Finding 185: FedCM Disconnect Explicitly Bypasses Embargo

## Summary
The `DisconnectRequest::SetCallbackAndStart()` function explicitly allows FedCM disconnect requests even when the user is under embargo (i.e., the user has repeatedly dismissed FedCM prompts). The code handles `BLOCKED_EMBARGO` by falling through to the `GRANTED` case, allowing the disconnect to proceed. This means a credentialed request is sent to the IdP's disconnect endpoint even when the user has indicated they do not want FedCM interactions.

## Affected Files
- `content/browser/webid/disconnect_request.cc:77-99` -- Permission check with deliberate embargo bypass
- `content/browser/webid/disconnect_request.cc:206-210` -- Disconnect request sent to IdP with cookies

## Details
```cpp
FederatedApiPermissionStatus permission_status =
    api_permission_delegate->GetApiPermissionStatus(embedding_origin_);

std::optional<DisconnectStatus> error_disconnect_status;
switch (permission_status) {
    case FederatedApiPermissionStatus::BLOCKED_VARIATIONS:
      error_disconnect_status = DisconnectStatus::kDisabledInFlags;
      break;
    case FederatedApiPermissionStatus::BLOCKED_SETTINGS:
      error_disconnect_status = DisconnectStatus::kDisabledInSettings;
      break;
    // We do not block disconnect on FedCM cooldown.
    case FederatedApiPermissionStatus::BLOCKED_EMBARGO:
    case FederatedApiPermissionStatus::GRANTED:
      // Intentional fall-through.
      break;
}
```

The comment "We do not block disconnect on FedCM cooldown" confirms this is intentional. However, the disconnect request sends a credentialed fetch (with cookies) to the IdP's disconnect endpoint.

## Attack Scenario
1. User visits evil-rp.com and dismisses FedCM prompts multiple times, triggering embargo.
2. evil-rp.com calls `navigator.credentials.disconnect()` with the target IdP's config.
3. Despite the embargo, the disconnect request proceeds.
4. A credentialed fetch (with the user's cookies) is sent to the IdP's disconnect endpoint.
5. The IdP learns that the user has an active session, which can be used for tracking.
6. Additionally, the disconnect endpoint could be designed to not actually disconnect but merely log the user's visit.

## Impact
- Credentialed network requests to IdPs bypass embargo protection.
- IdPs can use disconnect as a tracking/detection mechanism.
- Users who have indicated they do not want FedCM interactions still have their cookies sent to IdPs.
- The sharing permission check (line 102-108) mitigates this somewhat by requiring prior FedCM usage, but if the user has ever used FedCM with this IdP/RP pair, disconnects remain possible.

## VRP Value
**Low-Medium** -- The embargo bypass for disconnect is intentional (to allow users to disconnect from IdPs), but the credentialed fetch during embargo creates a tracking vector. The practical impact is limited to users who have previously used FedCM with the specific IdP/RP pair.

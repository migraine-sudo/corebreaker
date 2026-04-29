# Finding 191: FedCM Third-Party Cookie Access Bypasses Sharing Permission Requirement

## Summary
The `HasSharingPermissionOrIdpHasThirdPartyCookiesAccess()` function in `webid_utils.cc` returns `true` if the IdP has third-party cookie access on the RP's site, completely bypassing the sharing permission check. This means any IdP that has been granted third-party cookie access (e.g., via the Storage Access API or enterprise policy) can use FedCM's `getUserInfo()` and `disconnect()` APIs without the user ever having granted FedCM-specific sharing permission. This conflates cookie access with identity sharing consent.

## Affected Files
- `content/browser/webid/webid_utils.cc:419-439` -- `HasSharingPermissionOrIdpHasThirdPartyCookiesAccess()` with early return on cookie access
- `content/browser/webid/user_info_request.cc:152-156` -- Used to gate `getUserInfo()` access
- `content/browser/webid/disconnect_request.cc:102-108` -- Used to gate `disconnect()` access
- `content/browser/webid/request_service.cc:2717-2721` -- Used in `ShouldFailBeforeFetchingAccounts()`

## Details
```cpp
bool HasSharingPermissionOrIdpHasThirdPartyCookiesAccess(
    RenderFrameHost& host,
    const GURL& provider_url,
    const url::Origin& embedder_origin,
    const url::Origin& requester_origin,
    const std::optional<std::string>& account_id,
    FederatedIdentityPermissionContextDelegate* sharing_permission_delegate,
    FederatedIdentityApiPermissionContextDelegate* api_permission_delegate) {
  if (api_permission_delegate->HasThirdPartyCookiesAccess(host, provider_url,
                                                          embedder_origin)) {
    return true;  // Bypass sharing permission check entirely
  }
  // ... actual sharing permission check below ...
}
```

## Attack Scenario
1. An IdP (tracker-idp.com) obtains third-party cookie access on rp.com via the Storage Access API or an enterprise policy.
2. rp.com calls `getUserInfo()` for tracker-idp.com.
3. The browser checks `HasSharingPermissionOrIdpHasThirdPartyCookiesAccess()`.
4. Since tracker-idp.com has third-party cookie access, the function returns `true` immediately.
5. The sharing permission check is skipped -- the user never consented to FedCM identity sharing.
6. rp.com receives the user's account information from tracker-idp.com.
7. This enables cross-site tracking: the RP learns the user's identity at the IdP without FedCM-specific consent.

## Impact
- Third-party cookie access (a different, broader permission) is treated as equivalent to FedCM sharing consent.
- Users who granted Storage Access for cookie-related purposes have their identity silently shared via FedCM.
- This creates a cross-site tracking vector that bypasses FedCM's consent model.
- Affects `getUserInfo()`, `disconnect()`, and `ShouldFailBeforeFetchingAccounts()`.

## VRP Value
**Medium** -- This is a design-level privacy issue that conflates two different permission models. It does not require a compromised renderer and affects all users who have granted third-party cookie access to any IdP. The Chrome VRP explicitly covers privacy bypasses in FedCM.

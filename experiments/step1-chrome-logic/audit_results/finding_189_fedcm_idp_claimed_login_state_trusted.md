# Finding 189: FedCM IdP-Claimed Login State Can Override Browser-Trusted State

## Summary
The FedCM flow uses `idp_claimed_login_state` (provided by the IdP in its accounts response via the `approved_clients` field) which can override the browser's own `browser_trusted_login_state` when determining auto-reauthentication eligibility and account sorting. The pattern `account.idp_claimed_login_state.value_or(account.browser_trusted_login_state)` is used throughout the codebase, meaning the IdP's claim takes precedence over the browser's own records when the IdP provides a value.

## Affected Files
- `content/browser/webid/request_service.cc:1089-1095` -- Account sorting uses IdP claim over browser state
- `content/browser/webid/user_info_request.cc:294-306` -- `IsReturningAccount()` uses IdP claim over browser state
- `content/browser/webid/identity_credential_source_impl.cc:66-68` -- Account filtering uses IdP claim

## Details
In account sorting:
```cpp
if (account1->idp_claimed_login_state.value_or(
        account1->browser_trusted_login_state) == LoginState::kSignUp ||
    account2->idp_claimed_login_state.value_or(
        account2->browser_trusted_login_state) == LoginState::kSignUp) {
```

In `IsReturningAccount()`:
```cpp
// The |idp_claimed_login_state| will be |kSignUp| if IDP provides an
// |approved_clients| AND the client id is NOT on the |approved_clients|
// list, in which case we trust the IDP that we should treat the user as a
// new user and shouldn't return the user info.
if (account.idp_claimed_login_state.value_or(
        account.browser_trusted_login_state) == LoginState::kSignUp) {
    return false;
}
```

This means an IdP can claim `kSignIn` for an account that the browser has never seen before, causing:
1. The account to be treated as a returning account.
2. The account to be prioritized in the UI.
3. Auto-reauthentication to potentially be triggered.

## Attack Scenario
1. A user visits a new RP for the first time.
2. The IdP includes the RP's client_id in the `approved_clients` list for an account, claiming `kSignIn`.
3. The browser trusts this claim and treats the account as a returning account.
4. If other conditions for auto-reauthn are met (single returning account, no embargo), the browser may auto-select this account without showing a full chooser.
5. The IdP can influence which account gets auto-selected by manipulating `approved_clients`.
6. Conversely, the IdP can set `kSignUp` to prevent the user from being treated as a returning user, even when the browser has records of prior sign-ins, blocking `getUserInfo()` from returning account data.

## Impact
- IdP can influence auto-reauthentication behavior by claiming accounts are returning.
- IdP can suppress `getUserInfo()` results by claiming accounts are new.
- The browser's own permission records can be overridden by the IdP's claim.
- This gives the IdP more control over the authentication flow than the user or RP.

## VRP Value
**Low-Medium** -- The `idp_claimed_login_state` is a documented part of the FedCM specification and the comment acknowledges that the IdP's claim can "override browser local stored permission." However, the ability for the IdP to influence auto-reauthentication and account filtering has privacy implications that may not be obvious to users.

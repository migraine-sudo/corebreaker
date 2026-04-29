# Finding 176: FLEDGE Auction URL Loader Leaks URL and NIK to Third Parties

## Summary

In the FLEDGE/Protected Audience API, the auction URL loader factory proxy treats certain requests as subresource requests from the interest group owner's origin. This uses the owner's `IsolationInfo` (Network Isolation Key) and attaches the owner's `ClientSecurityState`, which the TODO explicitly acknowledges leaks information to the third party that made the request.

## Affected Files

- `content/browser/interest_group/auction_url_loader_factory_proxy.cc:339-347` — Information leak via NIK and URL

## Details

```cpp
// auction_url_loader_factory_proxy.cc:339-347
// TODO(mmenke): This leaks information to the third party that made the
// request (both the URL itself leaks information, and using the origin's
// NIK leaks information). These leaks need to be fixed.
new_request.trusted_params = network::ResourceRequest::TrustedParams();
new_request.trusted_params->isolation_info = isolation_info_;
new_request.trusted_params->client_security_state =
    client_security_state_.Clone();
```

The auction process makes network requests on behalf of interest group owners. By using the owner's `IsolationInfo`:
1. The Network Isolation Key reveals which first-party context the user is in
2. The URL of the request reveals what the auction is bidding on
3. The `ClientSecurityState` leaks the owner's security context

This information is visible to the network intermediary (the server receiving the request) and could be used for cross-site tracking.

## Attack Scenario

1. Ad tech company A registers an interest group for user on site-1.com
2. User visits site-2.com which runs a Protected Audience auction
3. The auction worklet fetches A's bidding signals from A's server
4. The request uses site-1.com's NIK, revealing to A's server that the user is on site-2.com while being associated with site-1.com
5. A correlates the user's browsing across sites via the NIK

## Impact

- **No compromised renderer required**: Standard Protected Audience API usage
- **Cross-site tracking**: NIK leaks first-party context to third-party ad tech servers
- **Privacy violation**: Defeats the Privacy Sandbox's goal of preventing cross-site tracking
- **Known issue**: TODO explicitly acknowledges the leak

## VRP Value

**Medium** — Information leak in the Privacy Sandbox. The purpose of FLEDGE is to prevent cross-site tracking, but this implementation leaks the very information it's supposed to protect. Chrome team is aware per the TODO.

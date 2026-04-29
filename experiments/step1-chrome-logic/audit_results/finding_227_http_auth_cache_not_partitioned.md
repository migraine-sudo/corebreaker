# Finding 227: HTTP Auth Cache Not Partitioned by Network Isolation Key (Disabled by Default)

## Summary

The `kSplitAuthCacheByNetworkIsolationKey` feature flag is `FEATURE_DISABLED_BY_DEFAULT`. When disabled, the HTTP authentication cache is shared across all network isolation contexts. This means HTTP authentication credentials (Basic, Digest, NTLM, Negotiate) entered in one site context can be automatically used by requests from a different site context, creating a cross-site information channel.

## Affected Files

- `services/network/public/cpp/features.cc` lines 90-93:
  ```cpp
  // Enables or defaults splittup up server (not proxy) entries in the
  // HttpAuthCache.
  BASE_FEATURE(kSplitAuthCacheByNetworkIsolationKey,
               base::FEATURE_DISABLED_BY_DEFAULT);
  ```

## Attack Scenario

1. User visits `https://attacker.com` which embeds a cross-origin subresource from `https://internal-corp.com/api`
2. The subresource request triggers HTTP authentication (e.g., Negotiate/NTLM for the user's corporate account)
3. The browser prompts the user or silently sends cached credentials (if the user previously authenticated to `internal-corp.com` from any context)
4. Because the auth cache is not partitioned, the credentials entered in the context of `https://hr-portal.corp.com` (a first-party visit to internal-corp.com) are reused for the cross-site request from `attacker.com`
5. `attacker.com` can detect whether the user has authenticated to `internal-corp.com` (via timing or response behavior), and the automatic credential reuse enables CSRF-like attacks on HTTP-auth-protected resources

More concretely:
- User authenticates to `https://internal.example.com` via NTLM while visiting `https://internal.example.com/dashboard`
- User later visits `https://evil.com`
- `evil.com` embeds `<img src="https://internal.example.com/admin/api?action=delete_user&id=123">`
- The browser automatically sends the cached NTLM credentials with this request because the auth cache is not partitioned
- The action is performed with the user's credentials

## Impact

- **Severity**: Medium (cross-site credential reuse, no compromised renderer needed)
- **Requires compromised renderer**: No -- standard web content can trigger cross-site requests that reuse cached auth credentials
- **Security principle violated**: Network state partitioning; HTTP auth cache should be partitioned to prevent cross-site credential leakage
- This is a known architectural gap in Chrome's network state partitioning efforts
- HTTP auth is becoming less common but is still used in enterprise environments (NTLM, Negotiate)
- SameSite cookies provide some protection, but HTTP auth operates at a different layer

## VRP Value Rating

Low - This is a known architectural decision with the feature flag deliberately disabled by default. Chrome's network state partitioning effort is ongoing, and auth cache partitioning has known compatibility concerns (SSO flows would break). However, the unpartitioned auth cache enables cross-site credential reuse that can be exploited for CSRF-like attacks on HTTP-auth-protected services, particularly in enterprise environments.

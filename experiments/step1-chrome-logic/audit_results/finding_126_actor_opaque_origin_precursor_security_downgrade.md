# Finding 126: Actor Uses Opaque Origin Precursor for Security Decisions, Enabling Sandbox Escape

## Severity: MEDIUM

## Summary

The Actor's `OriginOrPrecursorIfOpaque()` function intentionally uses the precursor origin of an opaque origin for user confirmation decisions. This means that when a user approves navigation to an opaque origin (e.g., from a sandboxed iframe or data: URL), the PRECURSOR origin is what gets added to the allowlist. This can allow sandboxed content to gain the Actor permissions of its embedding origin.

## Affected Files

- `chrome/browser/actor/execution_engine.cc:112-126` -- OriginOrPrecursorIfOpaque()
- `chrome/browser/actor/execution_engine.cc:589` -- Used in user confirmation

## Details

```cpp
// execution_engine.cc:112-126
// When operating on an opaque site, we choose to use the precursor's origin
// when judging whether a user confirmation should be triggered or not. We are
// effectively, using `rfh.GetLastCommittedUrl()` vs
// `rfh.GetLastCommittedOrigin()` for this "security" purpose contrary to the
// guidance here (docs/security/origin-vs-url.md).
//
// This is an intentional decision since it relates to user confirmations and it
// would be confusing to ask the user to distinguish between opaque domains.
url::Origin OriginOrPrecursorIfOpaque(const url::Origin& origin) {
  if (!origin.opaque()) {
    return origin;
  }
  return url::Origin::Create(
      origin.GetTupleOrPrecursorTupleIfOpaque().GetURL());
}
```

```cpp
// execution_engine.cc:587-590 (in OnPromptUserToConfirmNavigationDecision)
if (permission_granted) {
    origin_checker_.AllowNavigationTo(OriginOrPrecursorIfOpaque(destination),
                                      /*is_user_confirmed=*/true);
}
```

The comment explicitly acknowledges this goes against Chromium's security guidance (docs/security/origin-vs-url.md). When a user confirms an opaque origin, the non-opaque precursor is added to the allowlist with `is_user_confirmed=true`, which grants the highest level of trust.

## Attack Scenario

1. Attacker's site `evil.com` uses a sandboxed iframe: `<iframe sandbox="allow-scripts" src="...">`
2. The sandboxed content has an opaque origin with `evil.com` as the precursor
3. Actor navigates to the sandboxed content and asks user to confirm
4. User sees a confirmation prompt -- the opaque origin may be confusing
5. Upon confirmation, `evil.com` (the precursor) is added to the allowlist as user-confirmed
6. Now ALL future navigations to `evil.com` (including non-sandboxed) bypass all checks because `IsNavigationConfirmedByUser()` returns true
7. The sandboxed iframe has effectively upgraded its own embedding origin's Actor permissions

## Impact

- Sandboxed content can influence Actor permissions for its embedding origin
- User confirmation for opaque origins translates to permanent trust for the precursor
- Goes against Chromium's own security guidelines for origin vs URL usage
- Can be exploited through data: URLs, blob: URLs, or sandboxed iframes

## Remediation

For opaque origins, the Actor should either:
1. Refuse to act (since the origin is intentionally isolated)
2. Track opaque origins separately without promoting to precursor
3. At minimum, not set `is_user_confirmed=true` for the precursor when the actual interaction was with an opaque origin

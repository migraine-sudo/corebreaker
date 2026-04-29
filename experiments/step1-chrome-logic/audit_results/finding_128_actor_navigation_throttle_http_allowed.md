# Finding 128: Actor Navigation Throttle Allows HTTP for Cross-Origin Redirects

## Severity: MEDIUM

## Summary

The `ActorNavigationThrottle::WillStartOrRedirectRequest()` calls `MayActOnUrl()` with `allow_insecure_http=true` for BOTH initial navigations and redirects. This means if a navigation starts on HTTPS but is redirected to HTTP (a downgrade attack), the throttle will still allow it. Combined with the AI agent's ability to enter credentials, this creates a man-in-the-middle credential theft vector.

## Affected Files

- `chrome/browser/actor/actor_navigation_throttle.cc:232-233` -- allow_insecure_http=true
- `chrome/browser/actor/execution_engine.cc:1090` -- Same in IsAcceptableNavigationDestination

## Details

```cpp
// actor_navigation_throttle.cc:232-233
::actor::MayActOnUrl(
    navigation_url, /*allow_insecure_http=*/true, GetProfile(), journal,
    task_id_, task->policy_checker(), ...);
```

The navigation throttle handles redirect chains:
1. `WillStartRequest()` is called for the initial request
2. `WillRedirectRequest()` is called for each redirect

Both call `WillStartOrRedirectRequest()` which uses `allow_insecure_http=true`. This means:
- Initial HTTPS navigation to `https://legitimate.com` passes
- Server redirect to `http://legitimate.com` (downgrade) also passes
- The agent continues operating on the HTTP page

Note that `MayActOnTab()` at line 340-341 uses `allow_insecure_http=false`, but this only checks the CURRENT tab URL. The throttle checks are for new navigations, and those allow HTTP.

## Attack Scenario

1. User asks Actor to interact with `https://bank.com`
2. Attacker (MITM on the network) intercepts a redirect
3. The redirect takes the agent to `http://bank.com` or `http://attacker.com`
4. The navigation throttle allows this because `allow_insecure_http=true`
5. The AI agent operates on the HTTP page, entering credentials in plaintext
6. MITM attacker captures the credentials

## Impact

- HTTPS-to-HTTP downgrade attacks succeed against AI agent navigation
- Credential entry on HTTP pages enables plaintext credential capture
- The `MayActOnTab` check (which blocks HTTP) only applies at task start, not during navigation

## Remediation

Navigation redirects to HTTP should be blocked, or at least trigger a user warning. The `allow_insecure_http` parameter should be `false` for redirect handling, even if it remains `true` for initial requests (to handle HTTP-to-HTTPS upgrade scenarios).

# Finding 100: Actor AI Agent Allows Insecure HTTP Navigation by Default

## Summary

The Actor (AI agent) feature's `IsAcceptableNavigationDestination()` passes `allow_insecure_http=true` to `MayActOnUrl()`. This means the AI agent can be directed to navigate to HTTP (insecure) sites, even though the safety policy has scheme validation. The HTTP exception is intentional but creates a downgrade attack surface.

## Affected Files

- `chrome/browser/actor/execution_engine.cc:1090` — allow_insecure_http=true
- `chrome/browser/actor/site_policy.cc:149-150` — HTTP allowed when flag is true

## Details

```cpp
// execution_engine.cc:1087-1091
void ExecutionEngine::IsAcceptableNavigationDestination(
    const GURL& url,
    DecisionCallbackWithReason callback) {
  MayActOnUrl(url, /*allow_insecure_http=*/true, ...);
}

// site_policy.cc:149-150
if (!(url.SchemeIs(url::kHttpsScheme) ||
      (allow_insecure_http && url.SchemeIs(url::kHttpScheme)))) {
```

## Attack Scenario

1. User asks Actor to perform a task on a website
2. Malicious page contains a link/redirect to an HTTP version of a legitimate site
3. Actor navigates to the HTTP site
4. MITM attacker intercepts the HTTP traffic
5. Actor interacts with attacker-controlled content, potentially entering credentials or sensitive data

## Impact

- **No compromised renderer required**: Actor follows HTTP links by design
- **MITM exposure**: AI agent traffic on insecure connections
- **Credential risk**: Actor may enter credentials on HTTP pages

## VRP Value

**Low-Medium** — By design, but creates MITM exposure for AI agent interactions.

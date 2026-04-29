# Finding 131: Actor Allows Actions on localhost and about:blank Without Safety Checks

## Severity: MEDIUM

## Summary

The Actor's site policy check unconditionally allows actions on `localhost` URLs (if HTTP/HTTPS) and `about:blank` pages, bypassing ALL safety checks including SafeBrowsing, optimization guide, lookalike detection, and enterprise policy. This creates attack vectors where sensitive local services or dynamically-generated content can be accessed by the AI agent.

## Affected Files

- `chrome/browser/actor/site_policy.cc:143-147` -- Unconditional allow for localhost and about:blank

## Details

```cpp
// site_policy.cc:143-147
if ((net::IsLocalhost(url) && url.SchemeIsHTTPOrHTTPS()) ||
    url.IsAboutBlank()) {
  decision_wrapper->Accept();
  return;
}
```

This check runs BEFORE all other safety checks. When it matches:
- SafeBrowsing check is skipped
- Optimization guide check is skipped
- Lookalike domain check is skipped
- Enterprise policy check is skipped
- Allowlist/blocklist check is skipped

For localhost:
- Local development servers are accessible
- Internal services running on localhost (databases, admin panels, etc.) can be interacted with
- Port scanning via navigation is possible (navigate to localhost:PORT, check if it succeeds)

For about:blank:
- `about:blank` pages inherit the origin of their opener
- Content injected into `about:blank` iframes can be interacted with
- This provides a way to create content that bypasses all URL-based safety checks

## Attack Scenario

### Localhost Attack:
1. Attacker's page uses prompt injection to cause the AI to navigate to `http://localhost:8080/admin`
2. The localhost check passes immediately, no safety checks applied
3. Actor interacts with the local admin panel
4. Credentials or configuration data could be exfiltrated via subsequent actions

### about:blank Attack:
1. Attacker creates an `about:blank` page with injected content (via window.open or iframe)
2. The `about:blank` page contains a fake login form
3. AI agent is directed to interact with this page
4. Safety checks are bypassed because `url.IsAboutBlank()` returns true
5. Credentials could be entered into the attacker's injected form

## Impact

- Local services accessible without any safety checks
- Port scanning of localhost services possible via navigation
- `about:blank` provides a way to create unchecked pages for interaction
- No enterprise policy enforcement for localhost

## Remediation

Localhost access should be gated behind additional checks, or at least be subject to user confirmation. The `about:blank` exception should be narrowed -- consider checking the opener's origin and applying safety checks based on that origin instead.

# Finding 120: Actor New-Origin Navigation Confirmation Disabled by Default

## Severity: HIGH

## Summary

The `kGlicConfirmNavigationToNewOrigins` feature parameter defaults to `false`, meaning the Actor agent can navigate to ANY new (never-before-seen) origin without any confirmation from the server or user. This is the primary defense against the AI agent being directed to unknown/malicious sites, and it is OFF by default.

## Affected Files

- `chrome/browser/actor/execution_engine.cc:460-462` -- Early return when disabled
- `components/actor/core/actor_features.cc:59-62` -- Default: false

## Details

```cpp
// execution_engine.cc:455-462
void ExecutionEngine::HandleNavigationToNewOrigin(
    const url::Origin& destination,
    ukm::SourceId ukm_source_id,
    base::ScopedUmaHistogramTimer timer,
    ExecutionEngine::NavigationDecisionCallback callback) {
  if (!kGlicConfirmNavigationToNewOrigins.Get()) {
    std::move(callback).Run(/*may_continue=*/true);  // ALWAYS ALLOWS
    return;
  }
  // ... confirmation logic ...
}
```

The flow is:
1. Navigation to a new origin detected
2. `OnNavigationSensitiveUrlListChecked` is called with `not_sensitive=true` (not on the sensitive list)
3. `origin_checker_.IsNavigationAllowed()` returns false (novel origin)
4. `HandleNavigationToNewOrigin()` is called
5. Since `kGlicConfirmNavigationToNewOrigins` is false, navigation is ALWAYS allowed

This means the only checks that apply to novel origins are:
- Same-origin check (bypassed for any cross-origin navigation)
- Static blocklist/allowlist (only covers known-bad sites)
- Optimization guide "sensitive" check (only for sites the OG explicitly flags)

Any site NOT on the optimization guide sensitive list AND not on the static blocklist will be navigated to freely.

## Attack Scenario

1. Attacker creates a new phishing domain not yet known to optimization guide
2. Via prompt injection in page content, attacker causes AI model to navigate to this domain
3. Since the domain is novel and not on any list, the "new origin" handler fires
4. With `kGlicConfirmNavigationToNewOrigins=false`, navigation proceeds immediately
5. No server confirmation, no user prompt
6. Actor interacts with attacker-controlled content

## Impact

- The AI agent can navigate to ANY arbitrary domain with no confirmation
- Only defense is the optimization guide blocklist, which cannot cover zero-day phishing domains
- This is the intended deployment state (not a bug per se), but combined with prompt injection possibilities, it represents a significant attack surface
- The "sensitive navigation" prompt (for optimization guide blocked sites) is the ONLY user-facing check

## Remediation

Consider defaulting `kGlicConfirmNavigationToNewOrigins` to true, at least for the initial launch. Unknown origins should require some form of confirmation before the AI agent can interact with them.

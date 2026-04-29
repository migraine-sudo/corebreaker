# Finding 127: Server/Model Can Inject Writable Mainframe Origins Into Actor Allowlist

## Severity: HIGH

## Summary

The `ExecutionEngine::AddWritableMainframeOrigins()` method accepts a set of origins from the server/AI model and adds them directly to the navigation allowlist without any user confirmation. This provides a direct path for the AI model (which processes potentially adversarial web content) to pre-approve arbitrary origins for navigation.

## Affected Files

- `chrome/browser/actor/execution_engine.cc:1283-1289` -- AddWritableMainframeOrigins()
- `chrome/browser/actor/execution_engine.h:222-223` -- Public method declaration

## Details

```cpp
// execution_engine.cc:1283-1289
void ExecutionEngine::AddWritableMainframeOrigins(
    const absl::flat_hash_set<url::Origin>& added_writable_mainframe_origins) {
  if (!IsNavigationGatingEnabled()) {
    return;
  }
  origin_checker_.AllowNavigationTo(added_writable_mainframe_origins);
}
```

```cpp
// origin_checker.cc:65-74
void OriginChecker::AllowNavigationTo(
    const absl::flat_hash_set<url::Origin>& origins) {
  std::ranges::transform(
      origins,
      std::inserter(allowed_navigation_origins_,
                    allowed_navigation_origins_.end()),
      [](const auto& origin) {
        return std::make_pair(origin, OriginState{/*is_user_confirmed=*/false});
      });
}
```

This is a public method on `ExecutionEngine` that bulk-adds origins to the allowlist. The origins are added with `is_user_confirmed=false`, but they still pass the `IsNavigationAllowed()` check, which means:
1. Cross-origin navigation gating is bypassed for these origins
2. The optimization guide sensitive-URL check is bypassed for these origins (via the `not_sensitive` path)
3. No user prompt is shown

The origins come from the AI model's processing of page content. If the model processes adversarial content (prompt injection), it could be influenced to include attacker-controlled origins in the writable mainframe set.

## Attack Scenario

1. Attacker's page contains crafted content designed to manipulate the AI model
2. The AI model processes this content and generates a response including writable mainframe origins
3. The response includes `attacker.com` in the writable mainframe origins set
4. `AddWritableMainframeOrigins()` adds `attacker.com` to the allowlist
5. Any subsequent navigation to `attacker.com` bypasses all origin gating checks
6. The attacker's origin is now treated as a trusted destination for the remainder of the task

## Impact

- AI model output (which processes untrusted web content) directly controls security-critical allowlist
- No user confirmation required
- Bulk addition of arbitrary origins
- Prompt injection in web content can influence which origins are added
- Combined with credential tools, this enables credential phishing attacks

## Remediation

Origins added via `AddWritableMainframeOrigins()` should still be subject to the optimization guide check and, ideally, user confirmation. The method should validate origins against the blocklist before adding them. Consider treating model-provided origins as "suggested" rather than "approved."

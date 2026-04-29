# Finding 119: AI Agent Server Can Pre-Approve Arbitrary Origins via Implicit Tool Origin Grants

## Severity: HIGH

## Summary

When `kGlicAllowImplicitToolOriginGrants` is enabled (default: true), every tool request's `AssociatedOriginGrant()` is automatically added to the navigation allowlist WITHOUT user confirmation. For `NavigateToolRequest`, this means the server/AI model can pre-approve arbitrary navigation destinations by simply including them as navigate actions, bypassing the entire cross-origin navigation gating system.

## Affected Files

- `chrome/browser/actor/execution_engine.cc:706-717` -- Implicit origin grant loop
- `chrome/browser/actor/tools/navigate_tool_request.cc:52-54` -- AssociatedOriginGrant returns url::Origin::Create(url_)
- `components/actor/core/actor_features.cc:84-87` -- Default: true

## Details

```cpp
// execution_engine.cc:706-717  (inside Act())
for (const std::unique_ptr<ToolRequest>& action : action_sequence_) {
    CHECK(action);
    // ...
    if (IsNavigationGatingEnabled() &&
        kGlicAllowImplicitToolOriginGrants.Get()) {
      if (std::optional<url::Origin> maybe_origin =
              action->AssociatedOriginGrant();
          maybe_origin) {
        origin_checker_.AllowNavigationTo(maybe_origin.value(),
                                          /*is_user_confirmed=*/false);
      }
    }
}
```

```cpp
// navigate_tool_request.cc:52-54
std::optional<url::Origin> NavigateToolRequest::AssociatedOriginGrant() const {
  return url::Origin::Create(url_);
}
```

The AI model provides a batch of actions. BEFORE any safety check runs, the execution engine loops through ALL actions and adds their associated origins to the allowlist. When a NavigateToolRequest is in the batch, its target URL's origin is pre-approved.

This means:
1. Origin is added to `allowed_navigation_origins_` with `is_user_confirmed=false`
2. `IsNavigationAllowed()` will return true for this origin
3. The `MayActOnTab` check in `SafetyChecksForNextAction()` will short-circuit at site_policy.cc:264 because `origin_checker.IsNavigationConfirmedByUser()` is checked but `IsNavigationAllowed()` is what matters for the optimization guide check bypass
4. The navigation throttle's `WillProcessResponse` check uses `ShouldDeferNavigation` which also checks `origin_checker_.IsNavigationAllowed()` in `OnNavigationSensitiveUrlListChecked`

## Attack Scenario

1. Attacker crafts a page that, via prompt injection in page content, causes the AI model to generate a batch of actions including `NavigateToolRequest("https://evil-phishing.com/login")`
2. Before ANY safety check or user prompt runs, `evil-phishing.com`'s origin is added to the allowlist
3. When the navigation gating check runs, `evil-phishing.com` is already pre-approved
4. The sensitive URL check is skipped because the origin is in the allowlist
5. Actor navigates to the phishing page without user confirmation
6. Actor may then attempt to fill in credentials on the phishing page

## Impact

- Prompt injection in web page content can influence what origins the AI model includes in action batches
- Pre-approval happens before validation, creating a TOCTOU-like issue in the security design
- Completely bypasses the optimization guide blocklist check for navigation
- Combined with the `AttemptLoginTool`, credentials could be entered on attacker-controlled sites

## Remediation

Origin grants should not be applied before the tool's own validation passes. Move the implicit grant to AFTER the tool's `Validate()` succeeds, or remove implicit grants entirely and rely on explicit user confirmation.

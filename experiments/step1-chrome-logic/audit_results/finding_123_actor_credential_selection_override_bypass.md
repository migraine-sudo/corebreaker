# Finding 123: Actor Credential Selection Override Bypasses User Consent for Password Entry

## Severity: HIGH

## Summary

The `ExecutionEngine` has a `credential_selection_override_callback_` mechanism that, when set, completely bypasses the user-facing credential selection dialog. When enabled (gated behind `kPasswordCheckupPrototype`), it allows programmatic credential selection without user interaction, which could be exploited during automated password change flows to redirect credentials to attacker-controlled sites.

## Affected Files

- `chrome/browser/actor/execution_engine.cc:1118-1124` -- Override bypasses UI
- `chrome/browser/actor/execution_engine.cc:1291-1293` -- Override setup
- `chrome/browser/actor/execution_engine.h:450-452` -- Override callback field

## Details

```cpp
// execution_engine.cc:1111-1124
void ExecutionEngine::PromptToSelectCredential(
    const std::vector<actor_login::Credential>& credentials,
    const base::flat_map<std::string, gfx::Image>& icons,
    ToolDelegate::CredentialSelectedCallback callback) {
  CHECK(!credentials.empty());

  if (credential_selection_override_callback_ &&
      base::FeatureList::IsEnabled(
          password_manager::features::kPasswordCheckupPrototype)) {
    std::move(credential_selection_override_callback_)
        .Run(credentials, std::move(callback));
    return;  // <-- User prompt completely skipped
  }
  // ... normal credential selection dialog ...
}
```

The `PreHandleCredentialSelectionDialog()` method at line 1291-1293 allows external code to inject this override callback. When the `kPasswordCheckupPrototype` feature is enabled, this override takes priority over the user-facing credential picker.

Additionally, once a credential is selected (whether by user or override), it is cached in `user_selected_credentials_` keyed by origin. The `GetUserSelectedCredential()` method then looks up credentials by the request origin, and also checks `affiliated_origin_map_` for affiliated domains. This means a credential approved for `example.com` may be automatically reused on `affiliated-example.com` without additional user consent.

## Attack Scenario

1. `kPasswordCheckupPrototype` is enabled (prototype feature, but could reach broader audiences)
2. The automated password change flow is initiated
3. The credential selection override auto-selects a credential without user interaction
4. If the AI agent is directed (via prompt injection) to a lookalike domain that triggers the affiliated origin lookup
5. The credential is silently submitted to the attacker's site
6. Alternatively, a cross-origin navigation during the multi-step login flow could cause credentials to be used on the wrong origin

## Impact

- User credentials can be selected without the user seeing a prompt
- Affiliated origin matching could allow credential reuse across related domains
- In combination with navigation to a phishing page, this is a credential theft vector
- The prototype feature gate means this is currently limited, but the mechanism exists

## Remediation

Even when `kPasswordCheckupPrototype` is enabled, the override should still require some form of user acknowledgment before credentials are used. The affiliated origin matching should verify the affiliation chain is legitimate and not include attacker-controlled origins.

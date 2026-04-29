# Finding 129: Actor Can Skip BeforeUnload Dialog, Enabling Silent Data Loss and Navigation Manipulation

## Severity: MEDIUM

## Summary

The `kGlicSkipBeforeUnloadDialogAndNavigate` feature flag (default: disabled) allows the Actor to skip `beforeunload` confirmation dialogs. The Chromium source code includes an explicit warning: "Enabling this feature can lead to data loss when navigating." Additionally, the navigation proceeds without informing the user that their unsaved work is being abandoned.

## Affected Files

- `components/actor/core/actor_features.cc:119-120` -- Feature definition
- `components/actor/core/actor_features.h:63-66` -- Warning comment

## Details

```cpp
// actor_features.h:63-66
// When enabled, `beforeunload` dialog will not be displayed and the callback
// indicating the dialog outcome will be called with `true`.
// Warning: Enabling this feature can lead to data loss when navigating.
BASE_DECLARE_FEATURE(kGlicSkipBeforeUnloadDialogAndNavigate);
```

While this is currently `FEATURE_DISABLED_BY_DEFAULT`, it is a Finch-controllable flag that could be enabled for experiments. When enabled:
1. The `beforeunload` dialog is suppressed
2. The callback is invoked with `true` (proceed with navigation)
3. Any unsaved form data, ongoing uploads, or draft content is silently lost
4. The user has no opportunity to prevent the navigation

This is particularly concerning for the Actor because:
- The AI agent may be navigating away from a page where the user has unsaved work
- The `beforeunload` dialog is a critical user consent mechanism
- Skipping it means the user cannot override the AI agent's navigation decision

## Attack Scenario

1. `kGlicSkipBeforeUnloadDialogAndNavigate` is enabled via Finch
2. User is editing a document/form on a website
3. Attacker's prompt injection causes the AI to navigate away from the page
4. Normally, the `beforeunload` dialog would alert the user and let them cancel
5. With the flag enabled, navigation proceeds silently
6. User's unsaved work is lost
7. Actor navigates to attacker's page where further exploitation can occur

## Impact

- Silent data loss when AI agent navigates away from pages with unsaved data
- Removal of user consent mechanism for navigation
- Can be combined with prompt injection to force navigation to malicious sites
- The explicit warning in the code comments confirms this is a known risk

## Remediation

This feature flag should be removed entirely or gated behind an enterprise policy rather than a Finch experiment. The `beforeunload` dialog serves as a critical user consent mechanism that should never be bypassed by an automated agent.

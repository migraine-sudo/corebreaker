# Finding 200: Debugger API Not Restricted to Developer Mode by Default

## Summary
The feature flag `kDebuggerAPIRestrictedToDevMode` is `FEATURE_DISABLED_BY_DEFAULT`. This means any extension with the `debugger` permission can use the Chrome DevTools Protocol (CDP) to attach to targets regardless of whether the user has developer mode enabled. The code in `SimpleFeature::IsAvailableToContext` explicitly bypasses the developer mode restriction when this flag is disabled -- extensions marked as `developer_mode_only` in the features file would normally be restricted, but for the debugger API specifically, the restriction is lifted when the flag is off. This effectively gives all extensions with the `debugger` permission full CDP access without requiring the additional trust signal of developer mode being enabled.

## Affected Files
- `extensions/common/extension_features.cc` (lines 209-210)
- `extensions/common/features/simple_feature.cc` (lines 660-681)

## Details

In `extension_features.cc`:
```cpp
BASE_FEATURE(kDebuggerAPIRestrictedToDevMode,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

In `simple_feature.cc`:
```cpp
bool debugger_api_restricted = base::FeatureList::IsEnabled(
    extensions_features::kDebuggerAPIRestrictedToDevMode);

if (check_developer_mode && developer_mode_only_ &&
    !GetCurrentDeveloperMode(context_id)) {
  // TODO(crbug.com/390138269): Once the kUserScriptUserExtensionToggle
  // feature is default enabled, we should make the
  // kDebuggerAPIRestrictedToDevMode feature control dev mode restriction
  // entirely and no longer be specific to the debugger API (while also
  // setting the debugger API to use dev mode in the features file so the dev
  // mode restriction is continued to be tested).

  // Restrict the debugger feature to dev mode if the extension feature is
  // enabled. But if the feature is disabled, then we treat it like any other
  // API.
  if (name() == "debugger" && !debugger_api_restricted) {
    return CreateAvailability(AvailabilityResult::kIsAvailable);
  }

  return CreateAvailability(AvailabilityResult::kRequiresDeveloperMode);
}
```

The logic specifically exempts the "debugger" feature from the developer mode restriction when `kDebuggerAPIRestrictedToDevMode` is disabled (which is the default). This means:

1. When `kDebuggerAPIRestrictedToDevMode` is disabled (default):
   - The debugger API is available to extensions regardless of developer mode setting
   - Other `developer_mode_only` APIs still require developer mode
   - The debugger API gets special-case treatment to bypass the restriction

2. When `kDebuggerAPIRestrictedToDevMode` is enabled:
   - The debugger API requires developer mode, like other restricted APIs
   - This would provide an additional layer of user consent before CDP access is possible

The Chrome DevTools Protocol is the most powerful API available to extensions. It allows:
- Complete page content access (DOM, cookies, storage)
- Network interception and modification
- JavaScript execution in page context
- Browser-level control (for trusted extensions)
- Screenshot/screencast capture

## Attack Scenario
1. A user installs an extension from the Chrome Web Store that requests the `debugger` permission.
2. The user does NOT have developer mode enabled (indicating they are not a developer and may not understand the full implications of the permission).
3. Despite developer mode being off, the extension can use `chrome.debugger.attach()` to attach to any tab.
4. The extension uses CDP commands to read page content, intercept network traffic, or execute JavaScript.
5. The user is shown the standard debugging infobar (unless the extension is policy-installed per Finding 196), but the absence of a developer mode requirement means the attack surface is available to all users.

If `kDebuggerAPIRestrictedToDevMode` were enabled:
6. The extension's debugger API calls would fail because developer mode is not enabled.
7. Only users who explicitly enable developer mode (a stronger trust signal) would be vulnerable.
8. This would significantly reduce the attack surface from all Chrome users to only those with developer mode enabled.

## Impact
Medium. The debugger permission is the most powerful extension capability, equivalent to full page and network control. Not gating it behind developer mode means the full CDP attack surface is available to all Chrome extension users, not just developers. The TODO and feature flag suggest this restriction is planned but not yet deployed.

## VRP Value
Low-Medium

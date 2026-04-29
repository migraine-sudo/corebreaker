# Finding 125: Actor Safety List Block Enforcement Can Be Disabled via Feature Flag

## Severity: MEDIUM

## Summary

The `SafetyListManager::Find()` method contains a feature flag `kGlicEnforceComponentUpdaterBlockListEntries` that, when disabled, causes blocked entries in the component updater-provided safety list to be IGNORED (treated as `kNone` instead of `kBlock`). This means known-dangerous site pairs can be navigated to freely.

## Affected Files

- `components/actor/core/safety_list_manager.cc:131-133` -- Block enforcement toggle
- `components/actor/core/actor_features.cc:79-82` -- Default: true

## Details

```cpp
// safety_list_manager.cc:128-133
case CONTENT_SETTING_BLOCK:
    return kGlicEnforceComponentUpdaterBlockListEntries.Get()
               ? Decision::kBlock
               : Decision::kNone;  // <-- Blocked sites silently allowed
```

When `enforce_component_updater_block_list_entries=false`:
1. A site pair explicitly marked as BLOCKED in the safety list is treated as if there is no entry
2. The `Decision::kNone` result means the navigation falls through to the default handling
3. For same-origin navigations, this means `kAllowSameOrigin`
4. For cross-origin navigations, this means `kNeedsAsyncCheck` (which may still fail-open as described in Finding 121)

The safety list is the ONLY mechanism that can block specific source->destination navigation pairs (e.g., "from banking site to known phishing domain"). Disabling its enforcement removes this protection entirely.

## Attack Scenario

1. Finch experiment disables `enforce_component_updater_block_list_entries` for testing/rollback
2. Safety list has entries blocking navigation from `bank.com` to `phishing-bank.com`
3. AI agent operating on `bank.com` is tricked via prompt injection to navigate to `phishing-bank.com`
4. Safety list block entry is IGNORED
5. Navigation proceeds through the async check path, which may also fail open

## Impact

- Known-dangerous navigation pairs silently allowed
- No user-visible indication that enforcement is disabled
- Controllable via Finch server-side
- Defense-in-depth layer removed with a single parameter change

## Remediation

Block enforcement should not be togglable. If the safety list says "block," that decision should be final. The feature flag should be removed, or at minimum, block enforcement should be a separate kill switch with much stricter controls than a Finch parameter.

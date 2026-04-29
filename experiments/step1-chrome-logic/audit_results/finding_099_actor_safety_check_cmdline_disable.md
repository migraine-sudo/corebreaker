# Finding 099: Actor AI Agent Safety Checks Bypassable via Command-Line Switch

## Summary

Chrome's Actor (AI agent) feature has a command-line switch `--disable-actor-safety-checks` that completely disables ALL safety checks, including SafeBrowsing verification, URL scheme restrictions, IP address blocking, and navigation gating. This switch exists in release builds.

## Affected Files

- `components/actor/core/actor_util.cc:14-17` — IsActorSafetyCheckDisabled()
- `components/actor/core/actor_switches.cc:12` — "disable-actor-safety-checks"
- `chrome/browser/actor/site_policy.cc:163-166` — Safety check bypass

## Details

```cpp
// actor_util.cc:14-17
bool IsActorSafetyCheckDisabled() {
  return base::CommandLine::ForCurrentProcess()->HasSwitch(
      switches::kDisableActorSafetyChecks);
}

// site_policy.cc:163-166
if (IsActorSafetyCheckDisabled()) {
    decision_wrapper->Accept();  // ALL safety checks bypassed
    return;
}
```

When the switch is present, `MayActOnUrlInternal()` accepts ANY URL:
- Bypasses SafeBrowsing check
- Allows IP addresses
- Allows non-HTTPS schemes
- Bypasses optimization guide blocks
- Bypasses enterprise policy checks

Additionally, `IsNavigationGatingEnabled()` returns false, disabling cross-origin navigation gating.

## Attack Scenario

1. Attacker modifies Chrome shortcut/launch command to include `--disable-actor-safety-checks`
2. User uses Actor AI agent feature
3. AI agent can navigate to malicious HTTP sites, IP addresses, and SafeBrowsing-blocked sites
4. No safety warnings or blocks are shown
5. Agent could be tricked (via prompt injection on a malicious page) into navigating to dangerous sites

## Impact

- **No compromised renderer required**: Command-line flag modification
- **Complete safety bypass**: ALL Actor safety checks disabled
- **Available in release builds**: Not gated behind DCHECK or CHECK_IS_TEST

## VRP Value

**Medium** — Requires command-line modification. But since Actor is a powerful AI agent that can interact with web pages, disabling its safety is a significant risk.

# Finding 118: Actor Dark Launch Flag Bypasses Server-Side Navigation Rejection

## Severity: HIGH

## Summary

The `kGlicConfirmNavigationToNewOriginsDarkLaunch` feature parameter causes the Actor to PROCEED with navigation even when the server explicitly rejects it. When enabled, a server "rejected" response is overridden to "granted," effectively disabling server-side navigation control.

## Affected Files

- `chrome/browser/actor/execution_engine.cc:546-548` -- Dark launch override
- `components/actor/core/actor_features.cc:69-72` -- Feature parameter definition (default: false)

## Details

```cpp
// execution_engine.cc:546-548
permission_granted = permission_granted ||
                     kGlicConfirmNavigationToNewOriginsDarkLaunch.Get();
if (permission_granted) {
    origin_checker_.AllowNavigationTo(destination,
                                      /*is_user_confirmed=*/false);
}
std::move(callback).Run(permission_granted);
```

When `kGlicConfirmNavigationToNewOriginsDarkLaunch` is true, the server's rejection is logged via UMA but then OVERRIDDEN. The navigation proceeds as if the server approved it, AND the destination origin is permanently added to the allowed origins list via `AllowNavigationTo()`.

This is a Finch-controlled parameter under `kGlicCrossOriginNavigationGating`, meaning it can be toggled server-side for any Chrome population. The default is `false`, but any Finch experiment enabling it silently disables server-side navigation safety for Actor.

## Attack Scenario

1. During a Finch experiment rollout (or if an attacker can influence Finch configs, e.g., via variations service manipulation), `confirm_navigation_to_new_origins_dark_launch` is set to true
2. User asks Actor to perform a task
3. Actor attempts to navigate to a phishing/malicious site
4. Server-side check correctly identifies the site as dangerous and returns "rejected"
5. The rejection is IGNORED due to dark launch mode
6. Actor navigates to the malicious site and the origin is permanently allowlisted for the task session
7. All future navigations to that origin skip safety checks entirely

## Impact

- Server-side safety controls rendered ineffective when dark launch is enabled
- Origin permanently allowlisted after first bypass
- Combined with `kGlicAllowImplicitToolOriginGrants`, attacker-controlled origins can be pre-approved
- No user prompt shown since the "confirmation" path is what is being bypassed

## Remediation

The dark launch path should never override a rejection to an approval. Instead, it should log the hypothetical result while still enforcing the rejection:
```cpp
base::UmaHistogramBoolean(kPermissionGrantedHistogram, permission_granted);
if (kGlicConfirmNavigationToNewOriginsDarkLaunch.Get()) {
    // Dark launch: log but DO NOT override rejection
    std::move(callback).Run(/*may_continue=*/true);  // BUG: should use permission_granted
}
```

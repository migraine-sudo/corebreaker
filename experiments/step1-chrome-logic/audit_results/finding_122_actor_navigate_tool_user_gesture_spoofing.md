# Finding 122: Actor NavigateTool Injects User Gesture on Browser-Initiated Navigation

## Severity: MEDIUM

## Summary

The `NavigateTool` sets `params.has_user_gesture = true` on its browser-initiated `LoadURLWithParams` call (the default code path). This means every navigation performed by the AI agent appears to have a user gesture, which can bypass popup blockers, permission prompts, autoplay restrictions, and other user-gesture-gated security features on the destination page.

## Affected Files

- `chrome/browser/actor/tools/navigate_tool.cc:55-75` -- LoadURLWithParams with has_user_gesture=true
- `components/actor/core/actor_features.cc:110` -- kGlicNavigateWithoutUserGesture (legacy path fix)

## Details

```cpp
// navigate_tool.cc:55-75 (default code path, kGlicNavigateUsingLoadURL enabled)
if (base::FeatureList::IsEnabled(kGlicNavigateUsingLoadURL)) {
    content::NavigationController::LoadURLParams params(url_);
    // ...
    params.transition_type = ::ui::PAGE_TRANSITION_AUTO_TOPLEVEL;
    params.is_renderer_initiated = false;
    params.has_user_gesture = true;  // <-- SPOOFED USER GESTURE
    base::WeakPtr<content::NavigationHandle> handle =
        web_contents()->GetController().LoadURLWithParams(params);
```

The navigation is `is_renderer_initiated = false` (browser-initiated) but carries `has_user_gesture = true`. This is a contradictory signal: the browser is initiating the navigation (not the user), but it claims user intent.

The legacy code path (when `kGlicNavigateUsingLoadURL` is disabled) has a separate fix via `kGlicNavigateWithoutUserGesture` that sets `params.user_gesture = false`, but this is not the default path.

## Attack Scenario

1. Attacker's page contains prompt injection causing the AI to navigate to attacker's site
2. The navigation carries a user gesture
3. Destination page can immediately:
   - Open popups without being blocked
   - Trigger autoplay of media
   - Access APIs that require user activation (e.g., clipboard write)
   - Bypass certain permission prompt cooldown restrictions
4. Attacker's page leverages the gesture to perform actions that would normally require real user interaction

## Impact

- AI agent navigation grants user gesture to destination pages
- Bypasses browser security features that depend on genuine user interaction
- Attacker-controlled pages gain capabilities they would not normally have
- Can be chained with other attacks for greater impact

## Remediation

The `has_user_gesture` field should be `false` for AI agent navigations since there is no actual user click or interaction driving the navigation. The existing `kGlicNavigateWithoutUserGesture` fix should be applied to the primary code path as well.

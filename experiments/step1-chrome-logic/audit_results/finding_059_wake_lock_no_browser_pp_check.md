# Finding 059: Wake Lock Has No Browser-Side Permissions Policy Check

## Summary

The Wake Lock API (`navigator.wakeLock.request()`) checks the `kScreenWakeLock` Permissions Policy only in the Blink renderer. The browser-side `WakeLockServiceImpl` has no Permissions Policy check. A compromised renderer can acquire a screen wake lock even when Permissions Policy explicitly disallows it, keeping the device screen on indefinitely.

## Affected Files

- `third_party/blink/renderer/modules/wake_lock/wake_lock.cc:90-93` — Renderer-only PP check
- `content/browser/wake_lock/wake_lock_service_impl.cc` — No PP check at browser binding or request time
- `content/browser/browser_interface_binders.cc:1207` — Direct binding without PP gate

## Details

### Renderer check (only enforcement)

```cpp
// wake_lock.cc:90-93
if (!execution_context->IsFeatureEnabled(
        mojom::blink::PermissionsPolicyFeature::kScreenWakeLock)) {
  // ... reject promise
}
```

### Browser side (no check)

The `WakeLockServiceImpl` is bound via `browser_interface_binders.cc:1207` without any Permissions Policy gate. The service itself doesn't check Permissions Policy at request time either.

## Attack Scenario

### Battery drain / denial of service from cross-origin iframe

1. A page at `https://news.example` embeds an ad iframe from `https://ads.example`
2. The parent sets `<iframe allow="">` (empty) or `allow="wake-lock 'none'"` — explicitly blocking wake lock
3. A compromised renderer in the ad iframe ignores the renderer-side PP check
4. It directly calls the Mojo WakeLock service to acquire a screen wake lock
5. The user's screen stays on indefinitely, draining battery
6. The parent page has no way to prevent this despite setting Permissions Policy

### Alternative: No compromised renderer needed for some scenarios

In certain embedder configurations, the Permissions Policy may not propagate correctly for inherited policies, allowing a legitimate iframe to acquire wake locks it shouldn't have.

## Impact

- **Requires compromised renderer for direct bypass**: But this is a defense-in-depth gap
- **Battery drain**: Screen wake lock keeps display on indefinitely
- **User annoyance**: Device won't auto-sleep
- **Policy violation**: Site operators cannot enforce wake lock restrictions on embedded content

## VRP Value

**Medium** — Requires compromised renderer for the direct PP bypass. However, many other APIs (Fullscreen, Geolocation, USB, Serial) DO have browser-side PP checks, making this inconsistency notable. The impact is limited to battery drain (not data exfiltration), which reduces severity.

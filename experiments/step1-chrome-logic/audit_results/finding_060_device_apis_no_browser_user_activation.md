# Finding 060: Device APIs (Bluetooth, USB, Serial, Contacts) Have No Browser-Side User Activation Check

## Summary

Multiple device-access APIs check `HasTransientUserActivation` only in the Blink renderer. The browser-side service implementations go directly to the device chooser dialog without verifying user activation. A compromised renderer can trigger device enumeration dialogs without any user interaction.

## Affected APIs and Files

### Web Bluetooth
- Renderer: `third_party/blink/renderer/modules/bluetooth/bluetooth.cc:426` — checks user activation
- Browser: `content/browser/bluetooth/web_bluetooth_service_impl.cc:788-811` — NO user activation check, goes straight to chooser

### WebUSB
- Renderer: `third_party/blink/renderer/modules/webusb/usb.cc:229` — checks user activation
- Browser: `content/browser/usb/web_usb_service_impl.cc:332-344` — NO user activation check

### Web Serial
- Renderer: `third_party/blink/renderer/modules/serial/serial.cc:217` — checks user activation
- Browser: `content/browser/serial/serial_service.cc` — NO user activation check

### Contacts Picker (Android)
- Renderer: `third_party/blink/renderer/modules/contacts_picker/contacts_manager.cc:162` — checks user activation
- Browser: `content/browser/contacts/contacts_manager_impl.cc:69-85` — NO user activation check

### Presentation API
- Renderer: `third_party/blink/renderer/modules/presentation/presentation_request.cc:139` — checks user activation
- Browser: `content/browser/presentation/presentation_service_impl.cc:219-253` — NO user activation check

## Contrast with Properly Enforced APIs

These APIs DO have browser-side user activation checks:
- **window.open**: `render_frame_host_impl.cc:10244` — independent browser check
- **Fullscreen**: `render_frame_host_impl.cc:9234` — independent browser check
- **File System Access (write)**: `file_system_access_manager_impl.cc:1338` — independent browser check
- **SelectAudioOutput**: `media_devices_dispatcher_host.cc:563` — independent browser check
- **Sensor API**: `frame_sensor_provider_proxy.cc:87` — validates against browser-side state

## Attack Scenario

### Device enumeration/access without user interaction (requires compromised renderer)

1. User visits `https://evil.example` which exploits a renderer bug
2. Compromised renderer bypasses Blink's user activation check
3. Directly calls `WebBluetoothService::RequestDevice()` via Mojo
4. Browser opens Bluetooth device chooser dialog without any user click
5. If the user interacts with the unexpected dialog (e.g., clicks "Cancel" or accidentally selects a device), the attacker may gain device access
6. Even without user interaction, the dialog enumeration itself reveals nearby devices

### Multi-API chaining

A compromised renderer could simultaneously trigger:
- Bluetooth device chooser
- USB device chooser
- Serial port chooser
- Contacts picker (Android)
- Presentation device picker

This creates a confusing UX with multiple dialogs appearing simultaneously.

## Impact

- **Requires compromised renderer**: Direct exploitation needs Mojo IPC access
- **Device access**: Could gain access to Bluetooth, USB, Serial devices
- **Privacy**: Dialog enumeration reveals nearby devices
- **Inconsistent enforcement**: Some APIs (Fullscreen, File Access) DO check browser-side, making this a systematic gap

## VRP Value

**Medium** — Requires compromised renderer. However, the inconsistency across APIs suggests some were missed during the browser-side hardening effort. The Bluetooth/USB/Serial APIs in particular are high-impact targets because they grant access to physical devices.

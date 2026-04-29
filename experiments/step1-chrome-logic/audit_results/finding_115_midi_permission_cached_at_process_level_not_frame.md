# Finding 115: MIDI Permission Cached at Process Level, Not Frame Level

## Severity: MEDIUM

## Location
- `content/browser/media/midi_host.cc`, lines 134-163 (ReceiveData) and 234-258 (SendData)

## Description

The `MidiHost` class caches MIDI and MIDI SysEx permissions using boolean flags (`has_midi_permission_` and `has_midi_sysex_permission_`). These flags are checked against the renderer process ID, not the specific frame that initiated the MIDI session:

```cpp
// ReceiveData path (incoming MIDI messages):
if (!has_midi_permission_) {
    // TODO(crbug.com/40637524): This should check permission with the Frame
    // and not the Process.
    has_midi_permission_ =
        ChildProcessSecurityPolicyImpl::GetInstance()->CanSendMidiMessage(
            renderer_process_id_);
    if (!has_midi_permission_) {
        continue;  // Silently drops the message
    }
}

// SendData path (outgoing MIDI messages):
if (!has_midi_permission_ && !std::ranges::contains(data, kSysExByte)) {
    has_midi_permission_ =
        ChildProcessSecurityPolicyImpl::GetInstance()->CanSendMidiMessage(
            renderer_process_id_);
    if (!has_midi_permission_) {
        bad_message::ReceivedBadMessage(renderer_process_id_,
                                        bad_message::MH_MIDI_PERMISSION);
        return;
    }
}
```

The TODO at line 138-139 and line 154-155 explicitly acknowledges this is a known security gap:
```
// TODO(crbug.com/40637524): This should check permission with the Frame
// and not the Process.
```

## Security Issues

1. **Cross-frame permission leakage**: If Frame A in a renderer process has MIDI permission and Frame B does not, Frame B can still send/receive MIDI messages because the permission is checked at the process level. Once `has_midi_permission_` is set to true by Frame A's check, Frame B inherits that permission.

2. **Asymmetric security enforcement**: The ReceiveData path silently drops unauthorized messages (`continue`), while the SendData path kills the renderer process (`ReceivedBadMessage`). This asymmetry means:
   - A compromised renderer's incoming MIDI data is quietly discarded (no penalty)
   - A compromised renderer's outgoing MIDI data triggers process termination
   
3. **Permission caching**: Once `has_midi_permission_` is set to true, it is never reset. If a frame's MIDI permission is revoked after the initial check, the cached value will continue to allow access.

4. **Feature flag dependency**: The base MIDI permission check (non-SysEx) is behind `blink::features::kBlockMidiByDefault`. When this feature is disabled, basic MIDI messages have no browser-side permission enforcement at all -- only SysEx messages are checked.

## Impact

In a site-isolated world, this is mitigated because different origins are in different processes. However, same-site iframes or frames in the same process could inherit MIDI permissions they were not individually granted. Combined with the caching behavior, this creates a permission persistence issue.

## Exploitability

MEDIUM -- Requires same-process frames with different permission states, which can happen with same-site iframes. A malicious same-site iframe could leverage a parent frame's MIDI permission to interact with MIDI devices without its own permission grant.

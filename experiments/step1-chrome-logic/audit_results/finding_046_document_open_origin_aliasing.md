# Finding 046: document.open() Origin Aliasing — Shared Mutable SecurityOrigin Between Windows

## Summary

When `document.open()` is called, the opened document's SecurityOrigin is replaced with a **shared pointer** to the calling window's SecurityOrigin object. This means two windows share the same mutable SecurityOrigin. Mutations via `document.domain` on either window propagate to both. The feature flag `DocumentOpenOriginAliasRemoval` that would fix this is still "experimental" (not enabled by default).

Additionally, sandbox flags are merged during `document.open()` without notifying the browser process, creating a renderer/browser security state desynchronization.

## Affected Files

- `third_party/blink/renderer/core/dom/document.cc:3840-3847` — Shared origin assignment
- `third_party/blink/renderer/core/dom/document.cc:3800-3827` — Sandbox flag merge without browser notification
- `third_party/blink/renderer/platform/weborigin/security_origin.cc:625-645` — IsSameOriginDomainWith() port ignoring

## Details

### Shared mutable origin

```cpp
// document.cc:3840-3847
dom_window_->GetSecurityContext().SetSecurityOrigin(
    entered_window->GetMutableSecurityOrigin());
entered_window->GetMutableSecurityOrigin()
    ->set_aliased_by_document_open();
```

When `DocumentOpenOriginAliasRemovalEnabled()` is false (default), two windows end up pointing to the **same** SecurityOrigin object. Any call to `SetDomainFromDOM()` on either window's origin mutates both.

### Port-ignoring domain matching

```cpp
// security_origin.cc:625-645
// IsSameOriginDomainWith() grants cross-origin access when both documents
// have set document.domain to the same value, IGNORING PORT DIFFERENCES.
```

Two sites on different ports (e.g., `evil.example.com:8080` and `victim.example.com:443`) can gain DOM access by both setting `document.domain = "example.com"`.

### Sandbox flag desynchronization

```cpp
// document.cc:3807-3821
// TODO: The browser process won't be notified of the update.
// The origin won't be made opaque, despite the new flags.
```

## Attack Scenario

### Cross-subdomain DOM access via document.open + document.domain chain

1. Attacker controls `evil.sub.example.com`
2. Attacker creates an iframe to `victim.sub.example.com`
3. Attacker calls `document.open()` on the iframe, creating a shared SecurityOrigin
4. Attacker sets `document.domain = "example.com"` — this mutates the shared origin
5. Both windows now have `domain_was_set_in_dom = true` with domain `example.com`
6. `IsSameOriginDomainWith()` returns true — cross-origin DOM access granted
7. Attacker reads DOM of `victim.sub.example.com`

### Sandbox bypass via browser desync

1. A sandboxed iframe calls `document.open()` on another frame
2. Sandbox flags are merged via bitwise OR in the renderer
3. Browser process is not notified of the new sandbox flags
4. Renderer claims reduced sandbox; browser believes original sandbox applies
5. Security decisions diverge between renderer and browser

## Impact

- **No compromised renderer required**: Standard JavaScript APIs
- **Cross-subdomain DOM access**: Via origin aliasing + document.domain mutation
- **Non-standard behavior**: Comment explicitly notes "not specified, only Webkit/Blink implement it"
- **Browser/renderer desync**: Sandbox flags modified without browser knowledge

## VRP Value

**Medium** — Requires same-site subdomain control for practical exploitation. The shared mutable origin is a well-known anti-pattern being removed, but the removal flag is still experimental. The sandbox desynchronization is a more novel attack vector.

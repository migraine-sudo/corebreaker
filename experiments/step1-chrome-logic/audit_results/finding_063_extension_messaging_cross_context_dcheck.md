# Finding 063: Extension Messaging Cross-BrowserContext Check is DCHECK-Only

## Summary

The `MessageService` validates that messages stay within their intended BrowserContext using `DCHECK(IsSameContext(context, context_))`. In release builds, this check is stripped, potentially allowing messages to cross BrowserContext boundaries (e.g., incognito to regular profile).

## Affected Files

- `extensions/browser/api/messaging/message_service.cc:465,846,1283,1379` — DCHECK-only context validation

## Details

```cpp
// message_service.cc:465
DCHECK(ExtensionsBrowserClient::Get()->IsSameContext(context, context_));
```

This appears at multiple entry points to the message service. The `incognito` check at line 637 provides partial secondary defense, but only for incognito→normal, not all cross-context cases.

## Impact

- **Requires compromised renderer or extension**: Need to route message to wrong context
- **Cross-profile data leak**: Messages between incognito and normal browsing contexts
- **Extension isolation bypass**: Extensions running in different profiles could communicate

## VRP Value

**Low-Medium** — Requires specific conditions to trigger cross-context message routing.

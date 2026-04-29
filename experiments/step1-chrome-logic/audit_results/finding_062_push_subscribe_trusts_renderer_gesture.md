# Finding 062: Push Messaging subscribe() Trusts Renderer-Supplied User Gesture

## Summary

The Push Messaging API's `subscribe()` method sends `user_gesture` as a Mojo parameter that the browser trusts without verification. A compromised renderer can subscribe to push notifications claiming a user gesture occurred, triggering a permission prompt without actual user interaction.

## Affected Files

- `third_party/blink/renderer/modules/push_messaging/push_manager.cc:113` — Renderer check
- `content/browser/push_messaging/push_messaging_manager.cc:166,334-366` — Trusts renderer bool

## Details

The browser passes the renderer-supplied `user_gesture` through to the permission request and subscription flow. Unlike APIs like `window.open` or File System Access, the browser does NOT call `HasTransientUserActivation()` independently.

## Impact

- **Requires compromised renderer**: Direct exploitation
- **Automatic push notification subscription**: Permission prompt appears without user click
- **Notification spam**: Once subscribed, attacker can send push notifications

## VRP Value

**Low-Medium** — Requires compromised renderer. The permission prompt still requires user confirmation.

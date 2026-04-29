# Finding 205: Extension Messaging IsValidSourceUrl Bypasses Validation for Empty source_url

## Summary
In `IsValidSourceUrl()` within `message_service_bindings.cc`, an empty `source_url` is treated as valid without any further checks. The TODO (crbug.com/40240882) acknowledges this is a workaround for a bug. This means a renderer can send an empty `source_url` in the `OpenChannelToExtension` IPC message and bypass all origin-based validation that follows. The `source_url` is used in the messaging system for logging, for determining the messaging relationship (web page vs extension), and for `externally_connectable` URL matching.

## Affected Files
- `extensions/browser/api/messaging/message_service_bindings.cc` (lines 236-240)
- `extensions/browser/api/messaging/message_service.cc` (line 544, uses `source_url` for externally_connectable matching)

## Details

```cpp
bool IsValidSourceUrl(content::RenderProcessHost& process,
                      const GURL& source_url,
                      const PortContext& source_context) {
  // Some scenarios may end up with an empty `source_url` (e.g. this may have
  // been triggered by the ExtensionApiTabTest.TabConnect test).
  //
  // TODO(crbug.com/40240882): Remove this workaround once the bug is
  // fixed.
  if (source_url.is_empty()) {
    return true;
  }

  // ... extensive origin-based validation follows ...
```

After `IsValidSourceUrl` returns true, the `source_url` is passed through to `MessageService::OpenChannelToExtension` where it is used:

1. **Extended lifetime origin matching** (message_service.cc:1052-1070): The `source_url` is used to create `source_origin` which determines whether the messaging connection should extend the service worker's lifetime:
```cpp
url::Origin source_origin = url::Origin::Create(params->source_url);
```
An empty URL creates an opaque origin, which would not match any pattern in the extended lifetime list.

2. **externally_connectable matching** (message_service.cc:544-547):
```cpp
is_externally_connectable = externally_connectable->matches.MatchesURL(
    source_render_frame_host->GetLastCommittedURL());
```
Note: This specific check uses `GetLastCommittedURL()` instead of `source_url`, which is more secure. But other parts of the messaging code may use the IPC-supplied `source_url`.

3. **Activity logging and telemetry**: The `source_url` is logged and reported, meaning an empty URL would produce misleading activity records.

The validation that is skipped when `source_url` is empty includes:
- `ChildProcessSecurityPolicy::HostsOrigin` check (line 316)
- URL/origin matching against the process's committed URLs
- Sandbox origin derivation

## Attack Scenario
1. A compromised renderer sends an `OpenChannelToExtension` IPC with an empty `source_url`.
2. `IsValidSourceUrl` returns true immediately without checking if the process should be allowed to send messages with no source URL.
3. The messaging connection is established with an empty source URL.
4. The extension receives the message and checks `sender.url`, which would be empty.
5. If the extension uses `sender.url` for access control (e.g., "only accept messages from https://example.com"), the empty URL may bypass the check depending on how the extension validates it:
   - `if (sender.url.startsWith("https://example.com"))` - would fail (correct)
   - `if (!sender.url || sender.url === "")` - may be treated as special case
   - `if (sender.url !== "https://evil.com")` - would pass (incorrect allowlist logic)
6. Activity logs and telemetry would not record which URL initiated the messaging.

## Impact
Low-Medium. The empty `source_url` bypass is primarily a validation gap that affects logging and could affect extensions that rely on `sender.url` for access control. The browser-side `externally_connectable` check uses `GetLastCommittedURL()` for the critical matching, which mitigates the most dangerous scenario. However, the workaround nature of the bypass (explicitly flagged as a TODO) indicates it's a known gap that should be closed.

## VRP Value
Low

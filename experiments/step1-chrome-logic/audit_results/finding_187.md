# Finding 187: Extension Messaging externally_connectable Uses GetLastCommittedURL Instead of Origin for Web Page Validation

## Summary
When validating whether an external web page can connect to an extension via `runtime.sendMessage` or `runtime.connect`, the browser checks `source_render_frame_host->GetLastCommittedURL()` against the `externally_connectable` matches patterns. Using the full URL instead of the origin creates a potential URL pattern matching inconsistency. The `externally_connectable` patterns are `URLPatternSet` which can match specific paths, but `GetLastCommittedURL` returns the full URL including path and query string. If the URL has been modified via `history.pushState` or similar mechanisms, the committed URL may differ from the URL the page was originally loaded from. While `GetLastCommittedURL` is generally trustworthy from the browser's perspective, it represents the current navigation state which can be modified by JavaScript.

## Affected Files
- `extensions/browser/api/messaging/message_service.cc` (lines 544-547)

## Details

```cpp
// Check that the web page URL matches.
is_externally_connectable = externally_connectable->matches.MatchesURL(
    source_render_frame_host->GetLastCommittedURL());
```

The `externally_connectable` manifest key typically specifies patterns like:
```json
"externally_connectable": {
  "matches": ["https://example.com/*"]
}
```

The check uses the full committed URL, not just the origin. This is significant because:

1. A page at `https://example.com/legit-page` can use `history.pushState` to change its URL to `https://example.com/admin-panel` (same origin).
2. The `GetLastCommittedURL` would return `https://example.com/admin-panel`.
3. If the `externally_connectable` pattern was specifically trying to restrict access to `/admin-panel/*`, the pushState would affect matching.

More critically, the TODO in the code acknowledges a potential improvement:
```cpp
// TODO(devlin): We should just use ExternallyConnectableInfo::Get() here.
// We don't currently because we don't synthesize externally-connectable
// information (so that it's always present, even for extensions that don't
// have an explicit key); we should.
```

Without synthesized information, extensions without an `externally_connectable` key get a fallback check:
```cpp
} else {
  // Default behaviour. Any extension or content script, no webpages.
  is_externally_connectable =
      relationship == MessagingEndpoint::Relationship::kExternalExtension;
}
```

This means by default, any extension can connect to any other extension, and this check bypasses the `externally_connectable` validation entirely because there's no ExternallyConnectableInfo object to check against.

## Attack Scenario
1. Extension A has no `externally_connectable` key in its manifest.
2. A malicious Extension B sends a message to Extension A using `chrome.runtime.sendMessage(extensionA_id, ...)`.
3. Because Extension A has no `externally_connectable` info, the code falls to the default case.
4. The default case allows any extension to connect: `is_externally_connectable = (relationship == kExternalExtension)`.
5. Extension B successfully establishes a connection to Extension A.
6. If Extension A blindly trusts messages from other extensions (assuming it would be protected by `externally_connectable` if it had set it up), Extension B can send malicious commands.

This is not a vulnerability in the strict sense (the default behavior is documented), but it is a security-relevant design choice where the lack of `externally_connectable` results in a more permissive policy than many extension developers expect.

## Impact
Low-Medium. The default open-to-all-extensions policy when `externally_connectable` is not specified creates a broader messaging surface than many developers expect. Extensions that rely on implicit isolation (no `externally_connectable` = "no one can connect") are actually open to any other extension.

## VRP Value
Low

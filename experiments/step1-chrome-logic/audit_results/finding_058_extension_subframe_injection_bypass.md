# Finding 058: Extension Script Injection Bypasses Browser Permission Check for Subframes

## Summary

The browser-side permission check for extension script injection (`HasPermissionToInjectIntoFrame`) returns `true` for any subframe with an empty committed URL, deferring enforcement entirely to the renderer. A compromised renderer eliminates this secondary check, and even without compromise, a race window exists during navigation.

## Affected Files

- `extensions/browser/scripting_utils.cc:507-538` — Subframe injection permission bypass

## Details

```cpp
// scripting_utils.cc:507-538
if (committed_url.is_empty()) {
  // The frame has no committed url. This can happen e.g. if the frame hasn't
  // had a navigation yet. In that case, no injection is possible (the
  // renderer side will also check, and abort if the document has no URL.)
  // Note: we can't check the pending URL for subframes from the //chrome
  // layer. Assume the injection is allowed; the renderer has additional
  // checks later on.
  return true;  // For subframes with empty URL
}
```

For main frames, the function checks the pending URL and blocks injection into non-HTTP(S) URLs. But for subframes, it blindly returns `true` and relies on renderer-side checks.

## Attack Scenario

### Script injection into privileged subframes

1. A page embeds an iframe that is navigating to a chrome:// or extension:// URL
2. During the navigation, the subframe's committed URL is temporarily empty
3. An extension calls `chrome.scripting.executeScript()` targeting this subframe
4. The browser-side check returns `true` (empty committed URL + subframe)
5. The renderer is expected to block this, but if the renderer is compromised (or the timing is right), the script injects into the privileged subframe
6. The injected script has access to the privileged context's APIs

## Impact

- **Requires malicious extension**: Browser-side check is bypassed for any extension
- **Race window**: Even without compromised renderer, timing during navigation may allow injection
- **Renderer-dependent enforcement**: Security boundary moved from browser to renderer
- **Privilege escalation**: Could inject into extension pages or WebUI pages during navigation

## VRP Value

**Medium** — Requires malicious extension + timing or compromised renderer. The race window during subframe navigation is the most interesting vector.

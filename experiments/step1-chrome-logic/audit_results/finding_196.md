# Finding 196: Policy-Installed Extensions Silently Suppress Debugger API Infobar Warning

## Summary
When an extension uses the `chrome.debugger` API to attach to a target, Chrome normally displays an infobar warning the user that "Extension X started debugging this browser." However, policy-installed extensions (those installed via enterprise policy) silently suppress this infobar. This means an enterprise-managed extension can use the full Chrome DevTools Protocol (CDP) against any tab without any visible user notification, enabling complete surveillance of browsing activity including reading page content, intercepting network requests, modifying DOM, and capturing screenshots.

## Affected Files
- `chrome/browser/extensions/api/debugger/debugger_api.cc` (lines 474-486)

## Details

```cpp
bool ExtensionDevToolsClientHost::Attach() {
  // Attach to debugger and tell it we are ready.
  if (!agent_host_->AttachClient(this)) {
    return false;
  }

  // We allow policy-installed extensions to circumvent the normal
  // infobar warning. See crbug.com/41302695.
  const bool suppress_infobar =
      base::CommandLine::ForCurrentProcess()->HasSwitch(
          ::switches::kSilentDebuggerExtensionAPI) ||
      Manifest::IsPolicyLocation(extension_->location());

  if (!suppress_infobar) {
    subscription_ = ExtensionDevToolsInfoBarDelegate::Create(
        extension_id(), extension_->name(),
        base::BindOnce(&ExtensionDevToolsClientHost::InfoBarDestroyed,
                       base::Unretained(this)));
  }
```

The infobar is the primary user-facing security mechanism for the debugger API. When suppressed:

1. **No visual indicator**: The user has no notification that an extension is debugging their browser/tab.
2. **No dismissal mechanism**: Normally, closing the infobar detaches the debugger. With no infobar, there's no easy way for the user to stop the debugging.
3. **Full CDP access**: The attached extension gets full Chrome DevTools Protocol access, which includes:
   - Reading all page content (DOM, cookies, local storage)
   - Intercepting and modifying network requests/responses
   - Executing arbitrary JavaScript in the page context
   - Taking screenshots
   - Accessing browser-level targets (for trusted extensions)

Additionally, the `kSilentDebuggerExtensionAPI` command-line switch provides the same suppression for any extension, though this requires control of the browser launch command line.

## Attack Scenario
1. An enterprise administrator deploys a monitoring extension via enterprise policy.
2. The extension uses `chrome.debugger.attach()` to attach to any tab the user visits.
3. No infobar appears because `Manifest::IsPolicyLocation(extension_->location())` is true.
4. The extension uses CDP to capture all page content, network traffic, form inputs, and credentials.
5. The user has no visual indication that their browsing is being monitored at the protocol level.
6. Unlike content scripts (which have limitations), the debugger API provides complete access to the page and browser functionality.

This is particularly concerning in BYOD (Bring Your Own Device) scenarios where users may use their personal browser profiles on managed devices:
7. The managed extension could attach to incognito tabs (if allowed) without any visible warning.
8. Personal browsing activity is silently captured via CDP.

## Impact
Medium. While enterprise policy extensions are explicitly trusted by design, the complete absence of user notification when the debugger API is actively used creates a surveillance capability that goes beyond typical extension permissions. The `debugger` permission is supposed to be the most powerful extension permission, and the infobar warning is the primary user safeguard. Suppressing it for policy extensions creates an asymmetry where the most powerful API has the least visibility.

## VRP Value
Low

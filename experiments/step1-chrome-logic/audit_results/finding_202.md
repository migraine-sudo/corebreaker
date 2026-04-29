# Finding 202: Content Script Context Type Validation Does Not Check ScriptInjectionTracker

## Summary
In `ProcessMap::CanProcessHostContextType`, when validating `kContentScript` context type, the code only checks that an extension exists (`return !!extension`), without verifying via `ScriptInjectionTracker` that the process actually has content scripts from that extension. This is in contrast to `kUserScript` validation, which does check `ScriptInjectionTracker::DidProcessRunUserScriptFromExtension`. The TODO (crbug.com/40055126) acknowledges this gap. This means any renderer process that knows an extension's ID can claim to be running a content script for that extension, and the browser will accept the claim without verification.

## Affected Files
- `extensions/browser/process_map.cc` (lines 153-157)

## Details

```cpp
case mojom::ContextType::kContentScript:
  // Currently, we assume any process can host a content script.
  // TODO(crbug.com/40055126): This could be better by looking at
  // ScriptInjectionTracker, as we do for user scripts below.
  return !!extension;
case mojom::ContextType::kUserScript:
  return extension &&
         ScriptInjectionTracker::DidProcessRunUserScriptFromExtension(
             process, extension->id());
```

The asymmetry is significant:

1. **kContentScript**: Only checks `!!extension` (is this a known extension?). Any process that claims a content script context for a valid extension ID will pass this check.
2. **kUserScript**: Checks both that the extension exists AND that `ScriptInjectionTracker` confirms the process ran a user script from that extension.

This matters because `CanProcessHostContextType` is called from `ExtensionFunctionDispatcher` (at line 298-311 in the dispatcher code) to validate the renderer's claimed context type. If a compromised renderer claims `context_type = kContentScript` for an arbitrary extension, the check passes as long as the extension is installed.

Combined with Finding 182 (context type validation failures don't kill the renderer), this creates a chain:
1. A compromised renderer sends an API request with `context_type = kContentScript` and a valid extension ID.
2. `CanProcessHostContextType` returns true because the extension exists.
3. The API function executes with content script permissions for that extension.
4. Content scripts have access to:
   - `storage` API (if the extension has it)
   - `runtime.sendMessage` and `runtime.connect` (messaging to the extension's background)
   - Some subset of APIs depending on the extension's permissions

For comparison, `ScriptInjectionTracker` maintains a mapping of which processes have actually had content scripts injected. Checking this tracker would ensure only processes that legitimately had content scripts injected can claim the content script context.

## Attack Scenario
1. A compromised renderer (e.g., via a V8 exploit) identifies an installed extension by probing `chrome-extension://` URLs.
2. The renderer sends an extension API request with `context_type = kContentScript` and the extension's ID.
3. `CanProcessHostContextType` checks: is this extension installed? Yes. Returns true.
4. The API request proceeds with content script context.
5. The renderer now has content script-level access to the extension's APIs:
   - Can read/write extension storage
   - Can send messages to the extension's background page
   - Can access APIs that content scripts are allowed to use
6. If the extension's background page trusts messages from its content scripts (common pattern), the compromised renderer can trigger privileged actions.

Without the `ScriptInjectionTracker` check, the browser has no way to verify that this process should actually have content script access for this extension. The tracker data exists and is already used for user scripts -- it's just not consulted for content scripts.

## Impact
Medium. A compromised renderer can claim content script context for any installed extension without the browser verifying that content scripts were actually injected into that process. Combined with the non-fatal context type validation failure (Finding 182), this provides a viable privilege escalation path from a compromised renderer to extension API access. The TODO acknowledges this is a known gap.

## VRP Value
Medium

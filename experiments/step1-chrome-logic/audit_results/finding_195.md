# Finding 195: User Script World Configuration Shared Across Incognito Profiles

## Summary
The `UserScriptWorldConfigurationManager` redirects incognito browser contexts to the original (regular) profile context via `GetContextRedirectedToOriginal()`. This means user script world configurations (including custom CSP policies and messaging permissions) are shared between regular and incognito profiles. A split-mode extension that configures different user script world properties for incognito would not achieve isolation -- the incognito configuration would overwrite the regular profile's configuration and vice versa. The code contains a TODO acknowledging this design choice.

## Affected Files
- `extensions/browser/user_script_world_configuration_manager.cc` (lines 49-57)

## Details

```cpp
content::BrowserContext* GetBrowserContextToUse(
    content::BrowserContext* context) const override {
  // TODO(devlin): I wonder if it would make sense for this to have its own
  // instance in incognito. That would allow split-mode extensions to have
  // incognito-only world specifications and have them cleaned up when the
  // profile is destroyed.
  return ExtensionsBrowserClient::Get()->GetContextRedirectedToOriginal(
      context);
}
```

The `UserScriptWorldInfo` includes:
1. **Custom CSP** (`string? csp`): A custom Content Security Policy for the user script world
2. **Messaging enablement** (`bool enable_messaging`): Whether messaging APIs are available in the isolated world

Because the configuration is shared:
- A user script world with relaxed CSP in the regular profile also applies in incognito
- A user script world with messaging enabled in regular profile also has messaging enabled in incognito
- If an extension configures a restrictive CSP in regular but not in incognito (or vice versa), only one configuration is active for both

This is particularly concerning because the user script world CSP configuration is persisted to `ExtensionPrefs`, which means it survives browser restarts. The `SetUserScriptWorldInfo` method writes directly to prefs and notifies the renderer:

```cpp
void UserScriptWorldConfigurationManager::SetUserScriptWorldInfo(
    const Extension& extension,
    mojom::UserScriptWorldInfoPtr world_info) {
  // ...
  update_dict->SetKey(GetUserScriptWorldKeyForWorldId(world_info->world_id),
                      base::Value(std::move(world_info_dict)));
  renderer_helper_->SetUserScriptWorldProperties(extension,
                                                 std::move(world_info));
}
```

## Attack Scenario
1. A split-mode extension configures a user script world with a relaxed CSP (e.g., allowing `eval()`) for a specific purpose in the regular profile.
2. The user opens incognito mode, expecting stricter security properties.
3. The same relaxed CSP configuration applies in incognito because the configuration manager uses the original profile context.
4. Content scripts running in the incognito user script world have the same relaxed CSP, potentially allowing code execution patterns that the user expected to be isolated.

Alternative scenario:
5. An extension sets `enable_messaging: true` for a user script world in the regular profile.
6. In incognito, user scripts in the same world can use messaging APIs to communicate with the extension's background page.
7. If the extension's incognito behavior was designed to not receive messages from user scripts, this shared configuration bypasses that assumption.

## Impact
Low. The user script world CSP and messaging configuration sharing is primarily a defense-in-depth weakness. Extensions that rely on split-mode incognito isolation for their user script world properties will not achieve the expected separation. The TODO in the code acknowledges this as a known design gap.

## VRP Value
Low

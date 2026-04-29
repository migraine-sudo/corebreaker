# Finding 143: DevTools Cookie Setting Overrides Only Allow Disable, Not Enable -- But TODO Suggests Enable Is Coming

**Severity: LOW**

**Component:** `services/network/restricted_cookie_manager.cc`, `services/network/url_loader_util.cc`

## Summary

The DevTools cookie setting override mechanism has a hardcoded allowlist that currently only permits `kForceDisableThirdPartyCookies`. However, there is a TODO (crbug.com/375352611) in two places suggesting that `kForceEnableThirdPartyCookies` should also be added. If that override is added to the allowlist without proper safeguards, it would allow DevTools (and any attacker who can inject DevTools protocol commands) to force-enable third-party cookies for any frame.

## Vulnerable Code

```cpp
// services/network/restricted_cookie_manager.cc:70-74
// TODO(https://crbug.com/375352611): add the check for enabling third-party
// cookies.
constexpr uint64_t kAllowedDevToolsCookieSettingOverrides =
    1u << static_cast<int>(
        net::CookieSettingOverride::kForceDisableThirdPartyCookies);
```

Same pattern in `url_loader_util.cc:56-60`:
```cpp
// TODO(https://crbug.com/375352611): add the check for enabling third-party
// cookies.
constexpr uint64_t kAllowedDevToolsCookieSettingOverrides =
    1u << static_cast<int>(
        net::CookieSettingOverride::kForceDisableThirdPartyCookies);
```

The validation in the constructor:
```cpp
// services/network/restricted_cookie_manager.cc:438-440
CHECK_EQ(devtools_cookie_setting_overrides_.ToEnumBitmask() &
             ~kAllowedDevToolsCookieSettingOverrides,
         0u);
```

And how overrides are applied:
```cpp
// services/network/restricted_cookie_manager.cc:1203-1204
if (apply_devtools_overrides) {
    overrides = base::Union(overrides, devtools_cookie_setting_overrides_);
}
```

## Security Concern

1. **Current state is safe**: The allowlist only contains `kForceDisableThirdPartyCookies`, which can only make cookie access MORE restrictive. The CHECK in the constructor validates this.

2. **Planned expansion risk**: The TODO in two files says to add support for enabling third-party cookies. When `kForceEnableThirdPartyCookies` is added to the allowlist, any DevTools-connected session could force-enable third-party cookies. This is by design for developer testing, but creates an attack surface via CDP (Chrome DevTools Protocol) abuse.

3. **CDP attack surface**: Remote debugging protocol abuse is a known attack vector. If `kForceEnableThirdPartyCookies` is added to the DevTools overrides, an attacker with CDP access could:
   - Force-enable third-party cookies on any tab
   - Read cross-site cookies that would normally be blocked
   - Bypass privacy protections like CHIPS partitioning

4. **apply_devtools_overrides flag is renderer-controlled**: In `GetAllForUrl()`, `SetCookieFromString()`, etc., the `apply_devtools_overrides` boolean comes from the mojo message (renderer). A compromised renderer could set this to `true` to apply DevTools overrides even when DevTools is not open. However, since the override values themselves are set by the browser process during `RestrictedCookieManager` construction, a compromised renderer can only apply overrides that were already configured by the browser.

## Rating Justification

LOW: Current state is safe. The risk is forward-looking -- when the TODO is resolved and `kForceEnableThirdPartyCookies` is added, it will need careful access control. The `apply_devtools_overrides` being renderer-controlled is a concern but mitigated by browser-controlled override values.

## Related Code

- `content/browser/devtools/protocol/network_handler.cc:4271` - Where DevTools sets the override
- `services/network/network_context.cc:1137` - Where overrides are passed to RestrictedCookieManager
- `net/cookies/cookie_setting_override.h:44-48` - `kForceEnableThirdPartyCookies` definition
- `components/content_settings/core/common/cookie_settings_base.cc:298-309` - Where the override takes effect

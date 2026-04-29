# Finding 108: Local Network Access Checks Disabled for Main Frame Navigations

## Summary

The `kLocalNetworkAccessForNavigations` feature is **DISABLED by default**. This means main frame navigations to local network resources (private IP ranges like 192.168.x.x, 10.x.x.x, 127.0.0.x) from public websites are NOT checked or blocked. A public website can navigate the top-level page to a local network service without any permission or warning.

## Affected Files

- `content/common/features.cc:442-443` — Feature DISABLED_BY_DEFAULT
- `content/common/features.cc:453-454` — Warning-only variant also DISABLED

## Details

```cpp
// features.cc:442-443
// Enables Local Network Access checks for main frame navigations.
BASE_FEATURE(kLocalNetworkAccessForNavigations,
             base::FEATURE_DISABLED_BY_DEFAULT);

// features.cc:453-454
// Warning mode also disabled
BASE_FEATURE(kLocalNetworkAccessForNavigationsWarningOnly,
             base::FEATURE_DISABLED_BY_DEFAULT);
```

While subframe navigations (`kLocalNetworkAccessForSubframeNavigations`) ARE enabled by default, main frame navigations have NO protection. This is a significant gap because:
- Public websites can navigate users to internal network services
- Router admin panels (192.168.1.1), NAS interfaces, IoT devices are all reachable
- Combined with DNS rebinding, this enables attacks on local services

## Attack Scenario

1. User visits `https://attacker.com`
2. Attacker page does `window.location = "http://192.168.1.1/admin"` or uses a link
3. Browser navigates the top-level page to the local network resource
4. No Local Network Access check is performed (feature disabled)
5. If the local service has no authentication, attacker has achieved access
6. Even with authentication, the navigation can exploit CSRF vulnerabilities on the local service

### DNS Rebinding Variant

1. User visits `https://attacker.com`
2. After first load, attacker's DNS resolves to 192.168.1.1
3. Page navigates to itself, but DNS now points to local network
4. No LNA check for the navigation

## Impact

- **No compromised renderer required**: Standard web navigation
- **Local network SSRF**: Navigate to internal services
- **Router/IoT attack**: Access local admin panels
- **CSRF on local services**: Navigate with credentials to local services

## VRP Value

**Medium** — By design (feature not yet launched), but the gap between subframe protection (enabled) and main frame protection (disabled) creates an exploitable inconsistency. An attacker blocked from iframing a local resource can simply navigate to it instead.

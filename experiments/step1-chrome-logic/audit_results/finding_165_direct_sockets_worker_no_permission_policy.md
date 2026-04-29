# Finding 165: Direct Sockets in Workers Skip Permissions Policy Check + Hardcoded User Gesture

## Summary

The Direct Sockets service has three security issues:
1. Shared Workers and Service Workers skip the permissions policy check for Direct Sockets, always returning true (crbug.com/393539884)
2. The permission request for private network access hardcodes `user_gesture=true`, bypassing user activation requirements
3. When no DirectSocketsDelegate is configured, private network access defaults to ALLOWED

## Affected Files

- `content/browser/direct_sockets/direct_sockets_service_impl.cc:171-176` — Shared Worker permissions policy always true
- `content/browser/direct_sockets/direct_sockets_service_impl.cc:178-183` — Service Worker permissions policy always true
- `content/browser/direct_sockets/direct_sockets_service_impl.cc:266` — Hardcoded user_gesture=true
- `content/browser/direct_sockets/direct_sockets_service_impl.cc:239-241` — No delegate → allow all

## Details

### 1. Worker permissions policy bypass

```cpp
// direct_sockets_service_impl.cc:171-176
[](base::WeakPtr<SharedWorkerHost> shared_worker) {
  // TODO(crbug.com/393539884): Add permissions policy check.
  return true;  // ALWAYS ALLOWED
},
[](base::WeakPtr<ServiceWorkerVersion> service_worker) {
  // TODO(crbug.com/393539884): Add permissions policy check.
  return true;  // ALWAYS ALLOWED
},
```

While frames check `rfh->IsFeatureEnabled(kMulticastInDirectSockets)`, workers completely skip this check.

### 2. Hardcoded user gesture

```cpp
// direct_sockets_service_impl.cc:266
content::PermissionRequestDescription(
    content::PermissionDescriptorUtil::CreatePermissionDescriptorForPermissionTypes(
        required_permissions),
    /*user_gesture=*/true),  // ALWAYS TRUE
```

### 3. No delegate fallback

```cpp
// direct_sockets_service_impl.cc:239-241
if (!delegate) {
    std::move(callback).Run(/*access_allowed=*/true);  // DEFAULT ALLOW
    return;
}
```

## Attack Scenario

1. Isolated Web App (IWA) or Chrome extension creates a Shared Worker or Service Worker
2. Worker calls Direct Sockets API to open a TCP/UDP connection to a local network address (e.g., 192.168.1.1)
3. The permissions policy check is skipped (always returns true for workers)
4. If the worker requests private network access, the permission request claims user_gesture=true
5. Direct Sockets provide raw TCP/UDP access to local network devices

## Impact

- **Permissions Policy bypass**: Workers bypass the permissions policy intended to restrict Direct Sockets
- **User gesture forgery**: Permission requests always claim user activation
- **Default-allow for private network**: Without a delegate, all private network access is granted
- **Local network attack surface**: Combined issues allow broader access to local network devices

## VRP Value

**Medium** — Direct Sockets is restricted to IWAs and extensions, limiting the attack surface. However, the missing permissions policy check in workers is a clear gap acknowledged by the TODO, and the hardcoded user gesture is a defense-in-depth failure.

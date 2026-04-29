# Finding 051: Service Worker Controller Registration Matching Check is DCHECK-Only

## Summary

When a Service Worker registration is set as the controller for a client, the critical check that the registration actually matches the client (by scope and StorageKey) is only enforced via DCHECK — stripped in release builds. The code has an explicit TODO (crbug.com/497761255) acknowledging this should be upgraded to CHECK.

Additionally, `AddMatchingRegistration()` and the StorageKey origin validation are also DCHECK-only.

## Affected Files

- `content/browser/service_worker/service_worker_client.cc:703-717` — SetControllerRegistration DCHECK-only matching
- `content/browser/service_worker/service_worker_client.cc:321-326` — AddMatchingRegistration DCHECK-only scope + key match
- `content/browser/service_worker/service_worker_security_utils.cc:54-77` — StorageKey origin validation DCHECK-only

## Details

### SetControllerRegistration — DCHECK-only matching

```cpp
// service_worker_client.cc:703-717
void ServiceWorkerClient::SetControllerRegistration(...) {
  if (controller_registration) {
    CHECK(IsEligibleForServiceWorkerController());
    CHECK(controller_registration->active_version());
    // TODO(https://crbug.com/497761255): CHECK-exclusion: Convert to CHECK once
    // we are sure this isn't hit.
    DCHECK(IsMatchingRegistration(controller_registration.get()));
  }
}
```

`IsMatchingRegistration` verifies scope match AND StorageKey match. In release, this is not enforced.

### AddMatchingRegistration — DCHECK-only

```cpp
// service_worker_client.cc:321-326
void ServiceWorkerClient::AddMatchingRegistration(
    ServiceWorkerRegistration* registration) {
  DCHECK(blink::ServiceWorkerScopeMatches(registration->scope(), GetUrlForScopeMatch()));
  DCHECK(registration->key() == key());
}
```

### StorageKey origin validation — DCHECK-only

```cpp
// service_worker_security_utils.cc:54-77
void CheckOnUpdateUrls(const GURL& url, const blink::StorageKey& key) {
#if DCHECK_IS_ON()
  DCHECK((origin_to_dcheck.opaque() && key.origin().opaque()) ||
         origin_to_dcheck.IsSameOriginWith(key.origin()));
#endif
}
```

## Attack Scenario

### Cross-scope Service Worker interception (requires compromised renderer)

1. Compromised renderer triggers `SetControllerRegistration` with a registration whose scope doesn't match the client URL
2. In release builds, the DCHECK is stripped — the registration is accepted as controller
3. The attacker's service worker from scope `/attacker/` now controls a client navigating to `/victim/sensitive-data`
4. All fetch requests from the client are intercepted by the attacker's SW
5. The SW can read/modify all traffic, including authentication tokens and sensitive data

### Cross-origin controller via StorageKey mismatch

1. Compromised renderer supplies mismatched StorageKey to `AddMatchingRegistration`
2. Registration from `attacker.example` is added as matching for `victim.example` client
3. `SetControllerRegistration` assigns this cross-origin registration as controller
4. The attacker's SW intercepts all navigations and subresources for `victim.example`

## Impact

- **Requires compromised renderer**: Direct exploitation requires forging IPC parameters
- **Cross-origin interception**: Could allow one origin's SW to control another origin's traffic
- **Persistent**: Service Worker control persists across navigations and page reloads
- **Multiple code paths**: Three separate DCHECK-only checks in the SW controller assignment flow

## VRP Value

**Medium** — Requires compromised renderer. The impact is severe (cross-origin traffic interception) if exploitable, and the explicit TODO with crbug confirms this is a known gap. The same crbug.com/497761255 appears in multiple locations (also in CanAccessOrigin — Finding 036).

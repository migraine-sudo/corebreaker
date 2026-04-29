# Finding 218: Local Network Access Secure Context Override Not Applied in All Policy Derivation Points

## Summary

The LNA (Local Network Access) `lna_secure_context_override` check is only done at one policy derivation point in `navigation_request.cc`. The TODO (crbug.com/433300380) acknowledges that this check should be done at ALL policy derivation points and the boolean should probably be in `PolicyContainerPolicies`. Missing it at other derivation points means the override might not be consistently applied, allowing some code paths to use a different (potentially weaker) LNA policy.

## Affected Files

- `content/browser/renderer_host/navigation_request.cc:8985-8987` — Override only at one derivation point
- `content/browser/renderer_host/policy_container_host.cc:246-250` — PolicyContainer doesn't include LNA override

## Details

```cpp
// navigation_request.cc:8985-8987
// TODO(crbug.com/433300380): The lna_secure_context_overide check needs to be
// done in all other policy derivation points. This boolean should probably be
// put into PolicyContainerPolicies.
local_network_access_request_policy_ = DeriveLocalNetworkAccessRequestPolicy(
    policies, LocalNetworkAccessRequestContext::kSubresource);
```

And from PolicyContainerHost:
```cpp
// policy_container_host.cc:246-250
// TODO(crbug.com/395895368): add allow_non_secure_local_network_access to the
// mojo container in third_party/blink/public/mojom/frame/policy_container.mojom
// if it is necessary for Service workers
```

## Impact

- **Inconsistent LNA enforcement**: Some derivation points may not apply the override
- **Service workers affected**: Service workers don't have the override in their PolicyContainer
- **Multiple derivation points**: Any code that derives LNA policy independently could be wrong
- **No compromised renderer required**: This is a browser-side enforcement gap

## VRP Value

**Low-Medium** — Incomplete enforcement of LNA secure context override across policy derivation points. The impact depends on which code paths are affected and whether they handle requests to private/local networks.

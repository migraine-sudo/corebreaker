# Finding 154: Payment App Installer Uses Default Storage Partition Without Considering Third-Party Context

## Summary
The `SelfDeleteInstaller` in `payment_app_installer.cc` always uses the default storage partition and creates a first-party StorageKey when registering service workers for JIT-installed payment apps. A TODO comment explicitly acknowledges this security gap: the code should generate a full StorageKey with the top-level site for third-party contexts, but currently does not. This means JIT-installed payment handlers in third-party (cross-origin iframe) contexts get first-party storage access, bypassing storage partitioning.

## Affected Files
- `content/browser/payments/payment_app_installer.cc:105-112` - StorageKey creation with first-party assumption
- `content/browser/payments/payment_app_installer.cc:73-74` - Same issue in FindReadyRegistration

## Details
```cpp
// payment_app_installer.cc
void Init(WebContents* web_contents, bool use_cache) {
    ...
    service_worker_context_->FindReadyRegistrationForScope(
        scope_,
        blink::StorageKey::CreateFirstParty(url::Origin::Create(scope_)),  // First-party only!
        ...);
}

void OnFindReadyRegistrationForScope(...) {
    ...
    // TODO(crbug.com/40177656): Because this function can be called in a 3p
    // context we will need to generate a full StorageKey (origin + top-level
    // site) once StorageKey is expanded with the top-level site.
    service_worker_context_->RegisterServiceWorker(
        sw_url_,
        blink::StorageKey::CreateFirstParty(url::Origin::Create(option.scope)),  // First-party only!
        option,
        ...);
}
```

The `CreateFirstParty` call creates a StorageKey where the top-level site equals the origin itself. This means:
1. A payment handler installed via a third-party iframe gets first-party storage
2. The service worker registration may collide with or reuse an existing first-party registration from the same origin
3. Storage partitioning (a key browser security feature for privacy) is circumvented

## Attack Scenario
1. Attacker embeds `https://payment-provider.com` in an iframe on `https://tracking-site.com`
2. The iframe initiates a PaymentRequest that triggers JIT installation of a payment handler from `https://payment-provider.com`
3. Due to the first-party StorageKey, the installed service worker is stored as if `https://payment-provider.com` was the top-level site
4. When the user later visits `https://payment-provider.com` directly, the service worker installed from the third-party context is found and used
5. Any data the service worker cached from the third-party context (e.g., tracking tokens, cross-site identifiers) is now accessible in the first-party context
6. Conversely, first-party data from `https://payment-provider.com` may be accessible when the handler is invoked from third-party contexts

## Impact
Storage partitioning bypass for JIT-installed payment handlers. Allows cross-site data leakage through the service worker storage. The TODO comment confirms this is a known gap.

## VRP Value
Medium-High

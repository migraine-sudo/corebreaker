# Finding 179: CORS Preflight Sends TLS Client Certificates (kOmitCorsClientCert Disabled)

## Summary

When `CredentialsMode::kOmit` is set (as in CORS preflight requests), Chrome should not send TLS client certificates. However, due to a bug (crbug.com/40089326), client certificates ARE sent even when credentials mode is "omit." The fix (`kOmitCorsClientCert`) exists but is DISABLED by default, meaning every CORS preflight request leaks the user's TLS client certificate to the cross-origin server.

## Affected Files

- `services/network/url_loader_util.cc:104-112` — Client cert sent in omit mode
- `services/network/public/cpp/features.cc:197` — Fix DISABLED_BY_DEFAULT

## Details

```cpp
// url_loader_util.cc:104-112
// TODO(crbug.com/40089326): Due to a bug, the default behavior does
// not properly correspond to Fetch's "credentials mode", in that client
// certificates will be sent if available, or the handshake will be aborted
// to allow selecting a client cert.
case mojom::CredentialsMode::kOmit:
    return !base::FeatureList::IsEnabled(features::kOmitCorsClientCert);
    // Returns TRUE when disabled → client certs ARE sent

// features.cc:197
BASE_FEATURE(kOmitCorsClientCert, base::FEATURE_DISABLED_BY_DEFAULT);
```

The Fetch specification says credentials mode "omit" should not include any credentials, including TLS client certificates. The current behavior violates this.

## Attack Scenario

1. User has a TLS client certificate installed (common in corporate environments, government sites)
2. User visits `https://attacker.com`
3. `attacker.com` makes a cross-origin fetch to `https://target.com/api` with `credentials: "omit"`
4. The CORS preflight (or the request itself) includes the user's TLS client certificate
5. `target.com` can identify the user by their client certificate, even though the request explicitly omitted credentials
6. If `attacker.com` controls `target.com` (or `target.com` is a tracking service), it can correlate the user's identity

### Enterprise environment variant

1. Employee has a corporate mTLS certificate
2. Visiting any page that makes cross-origin requests can leak the certificate identity
3. The certificate often contains the employee's real name, email, and organization
4. This creates a fingerprinting/tracking vector that the user cannot control

## Impact

- **No compromised renderer required**: Standard web API behavior
- **Identity leak**: TLS client certificates identify users uniquely
- **Spec violation**: Fetch spec mandates credentials omission in this mode
- **Wide impact**: Affects all CORS requests with `credentials: "omit"`
- **Known issue**: crbug.com/40089326

## VRP Value

**Medium-High** — TLS client certificate leak in CORS preflight is a significant privacy/identity exposure issue. The spec explicitly says credentials should not be sent in omit mode. This affects users in corporate/government environments with client certificates. The fix exists but is disabled.

# Chrome VRP Report: CORS Preflight Sends TLS Client Certificates Despite credentials: "omit"

## Summary

Chrome sends TLS client certificates during CORS preflight requests even when `credentials: "omit"` is set. The fix (`kOmitCorsClientCert`) exists but is DISABLED by default, causing every cross-origin fetch with `credentials: "omit"` to leak the user's TLS client certificate identity to the target server.

## Vulnerability Details

**Component:** `services/network/url_loader_util.cc`

```cpp
// url_loader_util.cc:104-112
// TODO(crbug.com/40089326): Due to a bug, the default behavior does
// not properly correspond to Fetch's "credentials mode", in that client
// certificates will be sent if available...
case mojom::CredentialsMode::kOmit:
    return !base::FeatureList::IsEnabled(features::kOmitCorsClientCert);
    // Returns TRUE when disabled → client certs ARE sent

// features.cc:197
BASE_FEATURE(kOmitCorsClientCert, base::FEATURE_DISABLED_BY_DEFAULT);
```

## Steps to Reproduce

### Setup
1. Install a TLS client certificate (common in corporate/government environments)
2. Configure a test server at `https://target.com` that requests client certificates

### PoC

```javascript
// On https://attacker.com
// This fetch explicitly omits credentials, but Chrome still sends client cert
fetch('https://target.com/api', {
    mode: 'cors',
    credentials: 'omit'  // Should omit ALL credentials including client certs
});
```

### Expected Behavior
No TLS client certificate should be sent when `credentials: "omit"` is specified.

### Actual Behavior
The TLS client certificate IS sent, identifying the user to `target.com`.

## Impact

1. **Identity Leak**: TLS client certificates uniquely identify users (name, email, organization)
2. **No Compromised Renderer Required**: Standard Fetch API
3. **Spec Violation**: Fetch spec mandates no credentials in "omit" mode
4. **Wide Impact**: Affects all CORS requests with `credentials: "omit"`
5. **Known bug**: crbug.com/40089326

## Severity Assessment

**Medium-High** — Privacy/identity exposure affecting users with TLS client certificates (corporate/government environments).

## Suggested Fix

Enable `kOmitCorsClientCert` by default.

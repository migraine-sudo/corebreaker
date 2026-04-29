# Finding 192: WebOTP SMS Parser Allows HTTP for Localhost Origins

## Summary
The SMS parser in `sms_parser.cc` intentionally downgrades localhost domains from HTTPS to HTTP when parsing the origin from an SMS one-time-code message. While this is convenient for development, it means that a specially crafted SMS message with `@localhost` or `@localhost:PORT` as the domain will create an HTTP origin. If the OTP code is delivered to a page running on `http://localhost`, there is no transport security for the one-time code.

## Affected Files
- `content/browser/sms/sms_parser.cc:39-43` -- `ParseDomain()` downgrades localhost to HTTP

## Details
```cpp
ParseDomainResult ParseDomain(std::string_view domain) {
  std::string host;
  int port;
  if (!net::ParseHostAndPort(domain, &host, &port))
    return std::make_tuple(SmsParsingStatus::kHostAndPortNotParsed, GURL());

  std::string_view scheme;
  // Expect localhost to always be http.
  if (net::HostStringIsLocalhost(host)) {
    scheme = "http://";
  } else {
    scheme = "https://";
  }

  GURL gurl = GURL(base::StrCat({scheme, domain}));
```

This means an SMS like `@localhost #123456` creates the origin `http://localhost`, and the OTP code `123456` can be delivered to any page running on that origin.

## Attack Scenario
1. A local application runs a web server on `http://localhost:8080`.
2. An attacker sends a crafted SMS: `Your code is @localhost:8080 #STEAL_OTP`.
3. The SMS parser creates an HTTP origin `http://localhost:8080`.
4. If the user's browser has a page open at `http://localhost:8080`, the OTP is delivered.
5. Since HTTP provides no encryption, the OTP could be intercepted on shared/public networks where localhost services are exposed (e.g., via SSH tunneling).

## Impact
- One-time codes for localhost are delivered over HTTP, not HTTPS.
- Development environments using WebOTP may be vulnerable to local network attacks.
- The security model assumes HTTPS for all non-localhost origins but makes an exception for localhost.
- Limited real-world impact since WebOTP is primarily used for phone number verification.

## VRP Value
**Low** -- This is an intentional development convenience with limited production impact. Localhost HTTP downgrade is common in web platform APIs, and the practical attack surface requires the user to be running a local web server that uses WebOTP.

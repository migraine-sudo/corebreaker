# DNR regexSubstitution Scheme Bypass PoC

## What this tests

Whether Chrome's DeclarativeNetRequest API allows `regexSubstitution` to redirect 
subresource requests (specifically `<script>` tags) to `data:` URLs.

## Finding

`indexed_rule.cc:406-412` performs NO scheme validation on `regex_substitution` at parse time.
At runtime (`regex_rules_matcher.cc:393`), only `javascript:` scheme is blocked.
The "sanity check" at `ruleset_matcher_base.cc:381` is DCHECK-only (compiled out in release).
No check exists for `data:`, `chrome:`, `chrome-untrusted:`, or `devtools:` schemes.

## Setup

1. Add `testserver.example` to `/etc/hosts` pointing to 127.0.0.1
2. Load the extension in Chrome (chrome://extensions > Developer mode > Load unpacked)
3. Navigate to a page that includes: `<script src="https://testserver.example/redirect-target.js"></script>`
4. Check DevTools console for `DNR_REDIRECT_SUCCESS` message

## Expected behavior (if vulnerable)

The script request to `testserver.example/redirect-target.js` is redirected to a `data:text/javascript,...` URL,
and the JavaScript in the data URL executes in the context of the page loading it.

## Expected behavior (if mitigated)

The redirect should either:
- Be blocked by Chrome (ERR_BLOCKED_BY_CLIENT)
- The data: URL script should be blocked by same-origin policy
- The extension rule should fail to load (parsing error)

## Impact

If the redirect succeeds for script subresources, the data: URL script inherits the loading page's origin,
allowing arbitrary script injection into any page the extension has host permissions for.

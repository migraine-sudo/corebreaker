# Finding 141: Prerender Activation Skips Referrer and Referrer-Policy Comparison

## Summary
The prerender activation code intentionally skips comparison of the `referrer` and `referrer->policy` between the prerender's initial navigation and the activation navigation. This means a prerendered page that was fetched with one referrer policy can be activated by a navigation that expects a different referrer policy. If the prerender was fetched with a more permissive referrer policy (leaking full URL), and the activation navigation would have used a stricter policy, the server already received the more permissive referrer during prerender.

## Affected Files
- `content/browser/preloading/prerender/prerender_host.cc` (lines 1335-1336) - Explicit skip of referrer comparison

## Details
```cpp
// prerender_host.cc:1335-1336
// We intentionally don't check referrer or referrer->policy. See spec
// discussion at https://github.com/WICG/nav-speculation/issues/18.
```

During prerender startup in `PrerenderHost::StartPrerendering()`:
```cpp
// prerender_host.cc:640-641
// Just use the referrer from attributes, as NoStatePrefetch does.
load_url_params.referrer = attributes_.referrer;
```

The prerender is initiated with the referrer from the speculation rule's context. When the user later navigates (activation), the activation navigation may have a different referrer (e.g., from a click on a `<a rel="noreferrer">` link or from a page with `Referrer-Policy: no-referrer`). Since the referrer comparison is skipped, the activation succeeds.

The security implication: the target server already received the full referrer during the prerender fetch, even though the user's actual navigation would have sent a restricted referrer. This leaks the referring page URL to the target server when it shouldn't.

## Attack Scenario
1. Page `https://evil.com/secret-page?token=abc123` includes:
   - `Referrer-Policy: no-referrer` (to prevent token leakage)
   - Speculation rules: `{"prerender": [{"source": "list", "urls": ["https://target.com/page"]}]}`
2. The browser prerenders `https://target.com/page` with the referrer from the speculation rules context, which may include `https://evil.com/secret-page?token=abc123`
3. Even though `Referrer-Policy: no-referrer` is set, the prerender request already leaked the full referrer
4. When the user clicks a link to `https://target.com/page`, the prerendered page activates, and the user sees no indication that the full referrer was already sent

In practice, the referrer handling during prerender initiation uses the attributes' referrer, which respects the referrer policy of the initiating document. However, the mismatch between what the activation navigation would send vs. what was already sent during prerender cannot be reconciled.

## Impact
Low-Medium - The referrer leakage occurs at prerender time, not activation time. If the initiating page's referrer policy is properly enforced during prerender initiation, the risk is limited. The concern is about the disconnect between the activation navigation's intended referrer behavior and what already happened.

## VRP Value
Low

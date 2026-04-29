# Finding 174: DNR JavaScript Redirect Prevention is DCHECK-Only for Flat Ruleset Metadata Path

## Summary
The DeclarativeNetRequest (DNR) API blocks `javascript:` scheme redirects at rule indexing time and at runtime in the regex matcher. However, in `RulesetMatcherBase::CreateRedirectActionFromMetadata`, the check against `javascript:` redirects is only a `DCHECK`, which is stripped in release builds. If the flat ruleset binary on disk is tampered with, a `javascript:` redirect could be executed in release builds because there is no runtime enforcement on this code path.

## Affected Files
- `extensions/browser/api/declarative_net_request/ruleset_matcher_base.cc` (line 381)
- `extensions/browser/api/declarative_net_request/regex_rules_matcher.cc` (lines 391-395)
- `extensions/browser/api/declarative_net_request/indexed_rule.cc` (lines 374-376)

## Details

The non-regex flat ruleset path (`ruleset_matcher_base.cc:377-381`):
```cpp
// Sanity check that we don't redirect to a javascript url.
DCHECK(!redirect_url.SchemeIs(url::kJavaScriptScheme));
return CreateRedirectAction(params, rule, std::move(redirect_url));
```

Compare with the regex matcher (`regex_rules_matcher.cc:391-395`) which has a proper runtime check:
```cpp
// Redirects to JavaScript urls are not allowed.
if (redirect_url.SchemeIs(url::kJavaScriptScheme)) {
    return std::nullopt;
}
```

And the indexing-time check (`indexed_rule.cc:374-376`):
```cpp
if (redirect_url.SchemeIs(url::kJavaScriptScheme)) {
    return ParseResult::ERROR_JAVASCRIPT_REDIRECT;
}
```

The indexing-time check prevents `javascript:` from entering the flat ruleset under normal conditions, but the flat ruleset is a file on disk that can be modified. The regex matcher has proper runtime defense-in-depth, but the non-regex metadata path does not.

## Attack Scenario
1. An attacker gains write access to the extension's flat ruleset file on disk (shared machine, symlink attack, or compromised extension update path).
2. The flat ruleset is modified to include a redirect rule targeting `javascript:alert(document.cookie)`.
3. In release builds, the `DCHECK` is stripped, so the tampered redirect URL passes through.
4. When a matching request is intercepted by DNR, the browser creates a redirect action with the `javascript:` URL.
5. The redirect navigates the page to the `javascript:` URL, executing arbitrary script in the target page's origin.

## Impact
Low. Requires local file write access to the extension's flat ruleset, which is a high-privilege prerequisite. However, the inconsistency between the regex path (runtime check) and the non-regex path (DCHECK-only) is a defense-in-depth gap.

## VRP Value
Low

# Finding 242: registerAdMacro() Missing Return After Exception — Input Validation Bypass

## Summary

In `content/services/auction_worklet/register_ad_macro_bindings.cc`, the `registerAdMacro()` V8 binding throws a TypeError when macro name/value contain disallowed characters, but does NOT return after throwing. Execution falls through and stores the invalid macro into `ad_macro_map_`, which is later sent to the browser process via Mojo.

## Root Cause

**File:** `content/services/auction_worklet/register_ad_macro_bindings.cc:71-78`

```cpp
  if (ContainsDisallowedCharacters(macro_name) ||
      ContainsDisallowedCharacters(macro_value)) {
    args.GetIsolate()->ThrowException(
        v8::Exception::TypeError(v8_helper->CreateStringFromLiteral(
            "registerAdMacro macro key and value must be URL-encoded")));
    // BUG: Missing `return;` here!
  }

  bindings->ad_macro_map_[macro_name] = macro_value;  // Always executes
```

V8's `ThrowException()` schedules a JavaScript exception but does NOT halt C++ execution. Without a `return` statement, line 78 executes unconditionally, storing macros with disallowed characters (`\n`, `<`, `>`, `{`, `}`, etc.) that were intended to be rejected.

## Contrast with Other Bindings

Every other binding in the auction worklet codebase properly returns after ThrowException:

- `report_bindings.cc:101-105` — returns after throw
- `register_ad_beacon_bindings.cc:114-116` — returns after throw  
- `for_debugging_only_bindings.cc:55-63` — returns after throw

## Impact

The invalid macros are:
1. Stored in `ad_macro_map_` (worklet-side)
2. Sent via Mojo to the browser process in `OnBidderReportWinComplete`
3. Received by `InterestGroupAuctionReporter::AddReportWinResult` (line 967)
4. Wrapped as `"${" + macro_name + "}"` (line 1090) 
5. Passed to `FencedFrameReporter::OnUrlMappingReady()`
6. Used in URL macro substitution when the fenced frame calls `reportEvent()`

The browser process at line 1087-1091 does NOT re-validate macro names/values:
```cpp
for (const auto& [macro_name, macro_value] : bidder_ad_macro_map.value()) {
    bidder_macros->emplace_back("${" + macro_name + "}", macro_value);
}
```

## Security Severity

**Low-Medium.** The direct impact is limited because:
- Macro substitution only affects URLs specified by the fenced frame content (controlled by the same bidder)
- After substitution, URLs are validated as valid HTTPS with an allowed origin check
- The bidder already controls both the macros and the URL templates

However, this represents a **trust boundary violation** where:
- The worklet process is supposed to validate inputs before sending to browser
- The browser trusts worklet-provided data that bypassed intended validation
- Macros with characters like `}` could break the `${...}` template parsing, potentially substituting into unintended positions

## Suggested Fix

Add `return;` after the exception throw:

```cpp
  if (ContainsDisallowedCharacters(macro_name) ||
      ContainsDisallowedCharacters(macro_value)) {
    args.GetIsolate()->ThrowException(
        v8::Exception::TypeError(v8_helper->CreateStringFromLiteral(
            "registerAdMacro macro key and value must be URL-encoded")));
    return;  // ADD THIS
  }
```

## References

- `content/services/auction_worklet/register_ad_macro_bindings.cc:71-78`
- `content/browser/interest_group/interest_group_auction_reporter.cc:1087-1095`
- `content/browser/fenced_frame/fenced_frame_reporter.cc:617-619`

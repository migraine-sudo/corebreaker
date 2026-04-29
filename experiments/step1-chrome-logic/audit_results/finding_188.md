# Finding 188: Extension CSS Removal Injection Key Validation is DCHECK-Only in Release Builds

## Summary
In `ScriptExecutor::ExecuteScript`, the validation that CSS removal operations require injection keys (which are only provided by extensions, not WebView processes) is entirely gated behind `DCHECK_IS_ON()`. In release builds, this block is compiled out, meaning a WebView-sourced CSS removal operation could proceed without a required injection key, potentially allowing unauthorized CSS manipulation.

## Affected Files
- `extensions/browser/script_executor.cc` (lines 445-460)

## Details

```cpp
#if DCHECK_IS_ON()
  if (injection->is_css()) {
    bool expect_injection_key =
        host_id.type == mojom::HostID::HostType::kExtensions;
    if (injection->get_css()->operation ==
        mojom::CSSInjection::Operation::kRemove) {
      DCHECK(expect_injection_key)
          << "Only extensions (with injection keys supplied) can remove CSS.";
    }
    DCHECK(std::ranges::all_of(
        injection->get_css()->sources,
        [expect_injection_key](const mojom::CSSSourcePtr& source) {
          return expect_injection_key == source->key.has_value();
        }));
  }
#endif
```

The entire validation block is compiled out in release builds. The implications:

1. **CSS removal by non-extensions**: The check `"Only extensions (with injection keys supplied) can remove CSS"` is not enforced in release builds. A WebView process (`host_id.type != kExtensions`) could issue a CSS removal command.

2. **Injection key presence**: The check that all CSS sources have injection keys when expected is DCHECK-only. In release builds, a CSS injection from an extension could have missing keys, potentially allowing duplicate or conflicting CSS injections.

3. **Missing key handling**: If injection keys are missing but the CSS injection proceeds, the extension could inject CSS without the tracking mechanism that enables proper CSS removal later. This creates orphaned CSS that can't be cleaned up.

## Attack Scenario
1. A WebView guest (controlled by the embedding extension) sends a CSS removal command via the `ExecuteCode` Mojo interface.
2. In debug builds, the DCHECK fires and the command is flagged.
3. In release builds, the command proceeds because the validation block is compiled out.
4. The WebView guest removes CSS that was previously injected by an extension.
5. If the extension injected CSS for security purposes (e.g., hiding sensitive page elements, implementing a dark mode, or blocking UI elements), the WebView guest has bypassed the extension's CSS modifications.

Alternative scenario:
6. An extension injects CSS without injection keys (possible in release due to missing DCHECK).
7. The CSS cannot be removed later because the removal mechanism requires matching injection keys.
8. The injected CSS becomes permanent for the page's lifetime, potentially causing visual DoS or hiding important UI elements.

## Impact
Low. The CSS injection/removal mechanism is not typically used for security-critical operations. The DCHECK-only validation is primarily a code correctness check. However, it represents a defense-in-depth gap where non-extension callers could manipulate CSS injections in release builds.

## VRP Value
Low

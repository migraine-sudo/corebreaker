# Finding 130: Actor Form Filling Tool Can Skip User Consent Dialog via Command-Line Switch

## Severity: MEDIUM

## Summary

The `--attempt-form-filling-tool-skips-ui` command-line switch causes the `AttemptFormFillingTool` to bypass the user-facing autofill suggestion selection dialog, automatically picking the first suggestion for each form section. This switch exists in release builds and is not gated behind `CHECK_IS_TEST`.

## Affected Files

- `chrome/browser/actor/tools/attempt_form_filling_tool.cc:222-226` -- Switch check
- `chrome/browser/actor/tools/attempt_form_filling_tool.cc:235-258` -- SimulateRequestToShowAutofillSuggestions
- `components/actor/core/actor_switches.cc:17-18` -- Switch definition

## Details

```cpp
// attempt_form_filling_tool.cc:222-226
if (base::CommandLine::ForCurrentProcess()->HasSwitch(
        switches::kAttemptFormFillingToolSkipsUI)) {
    SimulateRequestToShowAutofillSuggestions(std::move(invoke_callback),
                                             suggestions_result.value());
    return;
}
```

```cpp
// attempt_form_filling_tool.cc:235-258
void AttemptFormFillingTool::SimulateRequestToShowAutofillSuggestions(...) {
  // In the simulation of asking the user to pick suggestions, we just choose
  // the first suggestion for each form section.
  std::vector<webui::mojom::FormFillingResponsePtr> accepted_suggestions =
      base::ToVector(
          requests, [](const autofill::ActorFormFillingRequest& request) {
            // ... picks first suggestion ...
          });
```

The comment says "This is only intended for testing" but the switch is available in release builds. When present:
1. The autofill suggestion selection dialog is never shown to the user
2. The first suggestion is automatically selected for every form field
3. Personal data (names, addresses, credit cards) is filled without user review
4. The user has no opportunity to choose which data is filled or to cancel

## Attack Scenario

1. Attacker modifies Chrome launch command to include `--attempt-form-filling-tool-skips-ui`
2. User asks Actor to fill a form
3. Instead of showing the selection dialog (where the user would review what data is being filled), the tool auto-selects the first suggestion
4. If the AI agent has been directed (via prompt injection) to a form on an attacker's site
5. Personal data including credit card numbers, addresses, etc., is automatically submitted to the attacker's form
6. User never sees what data was filled

## Impact

- Personal data (credit cards, addresses, SSN) filled without user review
- Available in release builds via command-line switch
- Combined with prompt injection, enables automated data exfiltration
- Bypasses the user consent mechanism that is the primary defense for form filling

## Remediation

This switch should be gated behind `CHECK_IS_TEST()` or removed from release builds. Testing-only switches that bypass user consent for sensitive operations should never be available in production.

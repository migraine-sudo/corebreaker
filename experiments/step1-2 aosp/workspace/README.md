# Workspace — AOSP VRP Verification & Submission

## Directory Structure

```
workspace/
├── README.md                    # This file
├── verification_status.md       # Master tracker for all vulnerability verification
├── poc/                         # PoC source code per vulnerability
│   └── v-XX/                    # One directory per vulnerability
│       ├── app/                 # Android Studio project or standalone Java
│       ├── build.sh             # Build script (if applicable)
│       └── README.md            # PoC-specific instructions
├── vrp-reports/                 # Google VRP submission reports
│   └── v-XX.md                  # One report per confirmed vulnerability
└── status/                      # Machine-readable status per vulnerability
    └── v-XX.json                # Per-vuln status (for automation)
```

## Workflow

1. Pick next vuln from `verification_status.md` (by priority)
2. Create `poc/v-XX/` directory with PoC code
3. Verify on device, collect evidence (logcat, screenshots)
4. Update `verification_status.md` with result
5. Update `status/v-XX.json` with structured data
6. If confirmed → generate `vrp-reports/v-XX.md` for Google Bug Hunters submission

## VRP Report Template

Each report in `vrp-reports/` follows Google Bug Hunters format:
- Title
- Severity & Impact
- Affected Component (AOSP path)
- Affected Versions
- Reproduction Steps
- PoC Code
- Expected vs Actual Behavior
- Suggested Fix
- Related CVEs (if variant)

## Verification Environment

- Target: Pixel device, latest AOSP / security patch
- Build: userdebug (for debugging) + user (for final confirmation)
- Tools: adb, Android Studio, jadx (decompile verification)

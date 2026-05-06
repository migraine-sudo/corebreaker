#!/usr/bin/env bash
# Chrome Logic Bug Audit — Ablation Benchmark Runner
#
# Usage:
#   ./eval/run_benchmark.sh [experiment_name] [--model sonnet|opus|haiku]
#   ./eval/run_benchmark.sh baseline                    # Run with current CLAUDE.md
#   ./eval/run_benchmark.sh no_principles --model opus  # Ablation test
#   ./eval/run_benchmark.sh --score-only baseline       # Re-score existing results
#
# Requires: claude CLI, jq, python3

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
GT_FILE="$SCRIPT_DIR/ground_truth.jsonl"
TEMPLATE="$SCRIPT_DIR/prompt_template.md"
CLAUDE_MD="$PROJECT_DIR/CLAUDE.md"

# Defaults
EXPERIMENT="${1:-baseline}"
MODEL="sonnet"
SCORE_ONLY=false

# Parse args
shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --model) MODEL="$2"; shift 2 ;;
        --score-only) SCORE_ONLY=true; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

RESULTS_DIR="$SCRIPT_DIR/results/$EXPERIMENT"
RAW_DIR="$RESULTS_DIR/raw_outputs"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Chrome Audit Benchmark — ${EXPERIMENT}${NC}"
echo -e "${BOLD}║  Model: ${MODEL}${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# Score-only mode
if $SCORE_ONLY; then
    echo -e "${BLUE}Scoring existing results...${NC}"
    python3 "$SCRIPT_DIR/score.py" "$RESULTS_DIR" --gt "$GT_FILE"
    exit 0
fi

# Create results directory
mkdir -p "$RAW_DIR"

# Save experiment metadata
cat > "$RESULTS_DIR/metadata.json" << EOF
{
  "experiment": "$EXPERIMENT",
  "model": "$MODEL",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "claude_md_hash": "$(md5 -q "$CLAUDE_MD" 2>/dev/null || md5sum "$CLAUDE_MD" | cut -d' ' -f1)",
  "gt_entries": $(wc -l < "$GT_FILE" | tr -d ' ')
}
EOF

# Extract audit rules from CLAUDE.md (the "5 条核心审计原则" section)
AUDIT_RULES=""
if [[ -f "$CLAUDE_MD" ]]; then
    # Extract principles section
    AUDIT_RULES=$(sed -n '/## 5 条核心审计原则/,/^## /p' "$CLAUDE_MD" | head -50)
    if [[ -z "$AUDIT_RULES" ]]; then
        AUDIT_RULES=$(sed -n '/原则 1/,/^---/p' "$CLAUDE_MD" | head -80)
    fi
fi

# Read template
TEMPLATE_CONTENT=$(cat "$TEMPLATE")

# Process each ground truth entry
TOTAL=$(wc -l < "$GT_FILE" | tr -d ' ')
CURRENT=0

while IFS= read -r line; do
    CURRENT=$((CURRENT + 1))
    ID=$(printf '%s' "$line" | jq -r '.id')
    FILE_PATH=$(printf '%s' "$line" | jq -r '.file')
    CODE=$(printf '%s' "$line" | jq -r '.code_snippet')
    CONTEXT=$(printf '%s' "$line" | jq -r '.context // ""')

    # Determine language from file extension
    LANG="cpp"
    if [[ "$FILE_PATH" == *.ts ]]; then LANG="typescript"; fi
    if [[ "$FILE_PATH" == *.js ]]; then LANG="javascript"; fi

    OUTPUT_FILE="$RAW_DIR/$ID.json"

    # Skip if already processed
    if [[ -f "$OUTPUT_FILE" && -s "$OUTPUT_FILE" ]]; then
        echo -e "  ${YELLOW}[$CURRENT/$TOTAL] $ID — already exists, skipping${NC}"
        continue
    fi

    echo -e "  ${BLUE}[$CURRENT/$TOTAL] $ID — auditing ${FILE_PATH}...${NC}"

    # Construct the full prompt
    PROMPT=$(echo "$TEMPLATE_CONTENT" | \
        sed "s|{{FILE_PATH}}|$FILE_PATH|g" | \
        sed "s|{{LANGUAGE}}|$LANG|g")

    # Write prompt to temp file to avoid shell escaping issues with code snippets
    PROMPT_FILE=$(mktemp)
    cat > "$PROMPT_FILE" <<PROMPT_EOF
$PROMPT

## Audit Rules from CLAUDE.md
$AUDIT_RULES

## Code to Analyze
File: $FILE_PATH
\`\`\`$LANG
$CODE
\`\`\`

## Context
$CONTEXT

## Required Output (JSON only, no other text before or after the JSON block)
PROMPT_EOF

    # Call Claude CLI reading prompt from stdin
    if command -v claude &> /dev/null; then
        claude -p - --output-format text --model "$MODEL" \
            < "$PROMPT_FILE" 2>/dev/null > "$OUTPUT_FILE" || {
            echo -e "  ${RED}  ERROR: Claude CLI failed for $ID${NC}"
            echo '{}' > "$OUTPUT_FILE"
        }
    else
        echo -e "  ${RED}  ERROR: 'claude' CLI not found. Install Claude Code CLI.${NC}"
        echo '{}' > "$OUTPUT_FILE"
    fi
    rm -f "$PROMPT_FILE"

    # Brief delay to avoid rate limiting
    sleep 2

done < "$GT_FILE"

echo ""
echo -e "${GREEN}All cases processed. Running scoring...${NC}"
echo ""

# Run scoring
python3 "$SCRIPT_DIR/score.py" "$RESULTS_DIR" --gt "$GT_FILE"

# Update latest symlink
ln -sfn "$EXPERIMENT" "$SCRIPT_DIR/results/latest"

# Print git commit suggestion
echo ""
SCORES=$(cat "$RESULTS_DIR/scores.txt" 2>/dev/null || echo "no scores")
echo -e "${BOLD}Suggested git commit:${NC}"
echo -e "  git add eval/results/$EXPERIMENT/ CLAUDE.md"
echo -e "  git commit -m \"ablation: $EXPERIMENT $SCORES\""
echo ""

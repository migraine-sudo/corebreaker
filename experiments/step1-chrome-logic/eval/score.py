#!/usr/bin/env python3
"""Chrome Logic Bug Audit — Ablation Benchmark Scoring.

Compares audit outputs against ground_truth.jsonl, computing:
- Detection score (did it find the right file+line?)
- Root cause score (does it understand WHY it's a bug?)
- Exploitability judgment (correct or not?)
- Fix quality (does suggested fix match actual fix?)
- Adversarial false positive rate

Usage:
    python3 eval/score.py eval/results/baseline/ --gt eval/ground_truth.jsonl
    python3 eval/score.py --compare eval/results/
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

LINE_TOLERANCE = 30


def load_ground_truth(gt_path: str) -> list[dict]:
    entries = []
    with open(gt_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entries.append(json.loads(line))
    return entries


def load_output(output_path: str) -> dict:
    """Load a single case output (JSON from Claude)."""
    with open(output_path) as f:
        content = f.read().strip()
    # Try to extract JSON from potentially markdown-wrapped output
    if "```json" in content:
        start = content.index("```json") + 7
        end = content.index("```", start)
        content = content[start:end].strip()
    elif "```" in content:
        start = content.index("```") + 3
        end = content.index("```", start)
        content = content[start:end].strip()
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list) and len(parsed) > 0:
            return parsed[0] if isinstance(parsed[0], dict) else {}
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        # Try to find JSON object in the text
        for i, ch in enumerate(content):
            if ch == '{':
                depth = 0
                for j in range(i, len(content)):
                    if content[j] == '{':
                        depth += 1
                    elif content[j] == '}':
                        depth -= 1
                        if depth == 0:
                            try:
                                return json.loads(content[i:j+1])
                            except json.JSONDecodeError:
                                break
        return {}


def file_matches(gt_file: str, output_file: str) -> bool:
    """Check if files match (basename comparison)."""
    if not output_file:
        return False
    gt_base = Path(gt_file).name.lower()
    out_base = Path(output_file).name.lower()
    return gt_base == out_base


def line_within_tolerance(gt_line: int, output_line: int, tolerance: int = LINE_TOLERANCE) -> bool:
    if gt_line <= 0 or output_line <= 0:
        return False
    return abs(gt_line - output_line) <= tolerance


def compute_fix_score(gt_fix: str, output_fix: str) -> int:
    """Score fix quality by keyword overlap."""
    if not output_fix:
        return 0
    gt_words = set(gt_fix.lower().split())
    out_words = set(output_fix.lower().split())
    # Key action words that indicate understanding
    action_words = gt_words & {"replace", "remove", "add", "check", "runtime", "if", "return",
                                "instead", "actual", "extend", "condition", "false", "proactive"}
    matched_actions = action_words & out_words
    overlap = len(gt_words & out_words) / max(len(gt_words), 1)

    if overlap >= 0.5 or len(matched_actions) >= 2:
        return 2
    elif overlap >= 0.25 or len(matched_actions) >= 1:
        return 1
    return 0


def score_entry(gt: dict, output: dict) -> dict:
    """Score a single entry."""
    scores = {}

    # Detection (0-3)
    detection = 0
    out_file = output.get("file", "")
    out_line = output.get("line", 0)
    has_issue = output.get("has_security_issue", False)

    if file_matches(gt["file"], out_file):
        detection = 1
        if has_issue:
            detection = 2
            if line_within_tolerance(gt["line_start"], out_line):
                detection = 3
    elif has_issue:
        # Found something but wrong file
        detection = 0

    scores["detection"] = detection

    # Root cause (0-2)
    root_cause = 0
    output_text = (output.get("root_cause", "") + " " + output.get("description", "")).lower()
    keywords = gt.get("root_cause_keywords", [])
    matched = [kw for kw in keywords if kw.lower() in output_text]
    if len(matched) >= 3:
        root_cause = 2
    elif len(matched) >= 1:
        root_cause = 1
    scores["root_cause"] = root_cause
    scores["matched_keywords"] = matched

    # Exploitability (0-1)
    gt_exploitable = gt.get("exploitable_from_web", False)
    out_exploitable = output.get("exploitable", None)
    if out_exploitable is not None:
        scores["exploitability"] = 1 if bool(out_exploitable) == gt_exploitable else 0
    else:
        scores["exploitability"] = 0

    # Fix quality (0-2)
    scores["fix_quality"] = compute_fix_score(
        gt.get("fix_description", ""),
        output.get("suggested_fix", "")
    )

    # Total depth score
    scores["depth_score"] = (
        scores["detection"] + scores["root_cause"] +
        scores["exploitability"] + scores["fix_quality"]
    )
    scores["max_score"] = 8

    return scores


def score_adversarial(gt: dict, output: dict) -> dict:
    """Score an adversarial entry. Returns false_positive=True if incorrectly flagged."""
    has_issue = output.get("has_security_issue", False)
    confidence = output.get("confidence", "low")

    false_positive = has_issue and confidence != "low"

    return {
        "false_positive": false_positive,
        "output_has_issue": has_issue,
        "output_confidence": confidence,
        "correct": not false_positive,
    }


def run_scoring(results_dir: str, gt_path: str) -> dict:
    """Run full scoring pipeline."""
    gt_entries = load_ground_truth(gt_path)
    raw_dir = Path(results_dir) / "raw_outputs"

    if not raw_dir.exists():
        print(f"ERROR: {raw_dir} not found")
        sys.exit(1)

    core_extended_scores = []
    adversarial_scores = []

    for gt in gt_entries:
        entry_id = gt["id"]
        output_file = raw_dir / f"{entry_id}.json"

        if not output_file.exists():
            print(f"  WARNING: No output for {entry_id}, scoring as zero")
            output = {}
        else:
            output = load_output(str(output_file))

        if gt.get("set") == "adversarial":
            adv_score = score_adversarial(gt, output)
            adv_score["id"] = entry_id
            adv_score["description"] = gt["description"]
            adversarial_scores.append(adv_score)
        else:
            entry_score = score_entry(gt, output)
            entry_score["id"] = entry_id
            entry_score["description"] = gt["description"]
            core_extended_scores.append(entry_score)

    # Aggregate metrics
    total_vuln = len(core_extended_scores)
    detected = sum(1 for s in core_extended_scores if s["detection"] >= 2)
    total_depth = sum(s["depth_score"] for s in core_extended_scores)
    max_depth = total_vuln * 8

    total_adversarial = len(adversarial_scores)
    false_positives = sum(1 for s in adversarial_scores if s["false_positive"])

    recall = detected / total_vuln if total_vuln > 0 else 0
    mean_depth = total_depth / max_depth if max_depth > 0 else 0
    fpr = false_positives / total_adversarial if total_adversarial > 0 else 0
    overall = recall * (1 - fpr) * mean_depth

    results = {
        "metrics": {
            "recall": round(recall, 3),
            "mean_depth_score": round(mean_depth, 3),
            "false_positive_rate": round(fpr, 3),
            "overall_score": round(overall, 4),
            "detected": detected,
            "total_vuln_entries": total_vuln,
            "false_positives": false_positives,
            "total_adversarial": total_adversarial,
        },
        "vuln_details": core_extended_scores,
        "adversarial_details": adversarial_scores,
    }

    return results


def print_report(results: dict) -> None:
    """Print human-readable report."""
    m = results["metrics"]
    print("\n" + "=" * 60)
    print("  CHROME AUDIT BENCHMARK — SCORING REPORT")
    print("=" * 60)

    print(f"\n  Recall (detection≥2)  : {m['recall']:.1%} ({m['detected']}/{m['total_vuln_entries']})")
    print(f"  Mean Depth Score      : {m['mean_depth_score']:.3f} (normalized 0-1)")
    print(f"  False Positive Rate   : {m['false_positive_rate']:.1%} ({m['false_positives']}/{m['total_adversarial']})")
    print(f"  Overall Score         : {m['overall_score']:.4f}")

    print("\n--- Vulnerability Entries ---")
    for entry in results["vuln_details"]:
        icon = "+" if entry["detection"] >= 2 else "X"
        print(f"\n  [{icon}] {entry['id']}: {entry['description'][:60]}")
        print(f"      detection={entry['detection']} root_cause={entry['root_cause']} "
              f"exploit={entry['exploitability']} fix={entry['fix_quality']} "
              f"TOTAL={entry['depth_score']}/8")
        if entry.get("matched_keywords"):
            print(f"      keywords matched: {entry['matched_keywords']}")

    print("\n--- Adversarial Entries ---")
    for entry in results["adversarial_details"]:
        icon = "+" if entry["correct"] else "!"
        print(f"  [{icon}] {entry['id']}: {'CORRECT (no FP)' if entry['correct'] else 'FALSE POSITIVE!'}")
        if not entry["correct"]:
            print(f"      Output claimed issue with confidence={entry['output_confidence']}")

    print("\n" + "=" * 60)
    print(f"  OVERALL SCORE: {m['overall_score']:.4f}")
    print("=" * 60 + "\n")


def compare_experiments(results_dir: str, gt_path: str) -> None:
    """Compare all experiments in results_dir."""
    results_path = Path(results_dir)
    experiments = sorted([d for d in results_path.iterdir() if d.is_dir() and d.name != "latest"])

    if not experiments:
        print("No experiments found to compare.")
        return

    print("\n" + "=" * 70)
    print("  EXPERIMENT COMPARISON")
    print("=" * 70)
    print(f"\n  {'Experiment':<25} {'Recall':>8} {'Depth':>8} {'FPR':>8} {'Overall':>10}")
    print(f"  {'-'*25} {'-'*8} {'-'*8} {'-'*8} {'-'*10}")

    for exp_dir in experiments:
        results_file = exp_dir / "results.json"
        if results_file.exists():
            with open(results_file) as f:
                data = json.load(f)
            m = data["metrics"]
            print(f"  {exp_dir.name:<25} {m['recall']:>7.1%} {m['mean_depth_score']:>7.3f} "
                  f"{m['false_positive_rate']:>7.1%} {m['overall_score']:>9.4f}")
        else:
            # Try to score from raw_outputs
            if (exp_dir / "raw_outputs").exists():
                data = run_scoring(str(exp_dir), gt_path)
                m = data["metrics"]
                print(f"  {exp_dir.name:<25} {m['recall']:>7.1%} {m['mean_depth_score']:>7.3f} "
                      f"{m['false_positive_rate']:>7.1%} {m['overall_score']:>9.4f}")
            else:
                print(f"  {exp_dir.name:<25} {'(no data)':>37}")

    print("")


def main():
    parser = argparse.ArgumentParser(description="Chrome Audit Benchmark Scorer")
    parser.add_argument("results_dir", nargs="?", help="Path to experiment results directory")
    parser.add_argument("--gt", default="eval/ground_truth.jsonl", help="Ground truth file")
    parser.add_argument("--compare", action="store_true", help="Compare all experiments in results_dir")
    parser.add_argument("--json", action="store_true", help="Output JSON only")
    args = parser.parse_args()

    if args.compare:
        compare_experiments(args.results_dir or "eval/results", args.gt)
        return

    if not args.results_dir:
        parser.print_help()
        sys.exit(1)

    results = run_scoring(args.results_dir, args.gt)

    # Save results.json
    results_json_path = Path(args.results_dir) / "results.json"
    with open(results_json_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # Save scores.txt (one-line summary for git commit messages)
    scores_txt_path = Path(args.results_dir) / "scores.txt"
    m = results["metrics"]
    with open(scores_txt_path, "w") as f:
        f.write(f"recall={m['recall']:.3f} depth={m['mean_depth_score']:.3f} "
                f"fpr={m['false_positive_rate']:.3f} overall={m['overall_score']:.4f}\n")

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print_report(results)
        print(f"  Results saved to: {results_json_path}")
        print(f"  Scores summary:   {scores_txt_path}")


if __name__ == "__main__":
    main()

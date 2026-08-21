"""Evaluation harness for SentinelMesh pipeline.

Scores:
  1. **Tool Selection Precision** — Did the agents use the right MCP/local tools?
  2. **Severity Accuracy** — Does the classified severity match expected?
  3. **IoC Extraction Recall** — Were all expected IoCs mentioned?
  4. **Mitigation Completeness** — Are key mitigation terms present?
  5. **Response Latency** — End-to-end execution time

Usage::

    python eval/run_evals.py                       # Run all benchmarks
    python eval/run_evals.py --case EVAL-001       # Run a single case
    python eval/run_evals.py --provider ollama      # Override LLM provider
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
import warnings
from pathlib import Path
from typing import Any

warnings.filterwarnings("ignore", category=UserWarning)

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.agents.supervisor import run_pipeline  # noqa: E402
from src.config import LLMProvider  # noqa: E402
from src.core.llm_factory import get_llm  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("eval")

BENCHMARKS_PATH = Path(__file__).parent / "benchmarks" / "gold_standard.json"


# ═══════════════════════════════════════════════════════════════
#  Scoring Functions
# ═══════════════════════════════════════════════════════════════


def score_tool_precision(result: dict[str, Any], expected_tools: list[str]) -> dict[str, Any]:
    """Score whether the expected tools were called."""
    called_tools: set[str] = set()

    for msg in result.get("messages", []):
        # 1. Direct tool message name
        name = msg.get("name")
        if name and isinstance(name, str):
            called_tools.add(name.lower())

        # 2. Tool calls on AI message
        tool_calls = msg.get("tool_calls", [])
        if isinstance(tool_calls, list):
            for tc in tool_calls:
                if isinstance(tc, dict) and "name" in tc:
                    called_tools.add(tc["name"].lower())

        # 3. Fallback: check content text for tool invocation patterns
        content = msg.get("content", "")
        if isinstance(content, str):
            for t in expected_tools:
                if t.lower() in content.lower():
                    called_tools.add(t.lower())

    found = [t for t in expected_tools if t.lower() in called_tools]
    missed = [t for t in expected_tools if t.lower() not in called_tools]
    precision = len(found) / len(expected_tools) if expected_tools else 1.0

    return {
        "score": round(precision, 2),
        "found_tools": found,
        "missed_tools": missed,
    }


def score_severity(result: dict[str, Any], expected_severity: str) -> dict[str, Any]:
    """Score whether the severity classification matches."""
    # Check both final response and message history
    texts = [result.get("final_response", "")]
    for msg in result.get("messages", []):
        content = msg.get("content", "")
        if isinstance(content, str):
            texts.append(content)

    full_text = " ".join(texts).lower()
    expected = expected_severity.lower()

    # Match expected severity term
    match = expected in full_text
    return {
        "score": 1.0 if match else 0.0,
        "expected": expected,
        "found_in_response": match,
    }


def score_ioc_recall(result: dict[str, Any], expected_iocs: list[str]) -> dict[str, Any]:
    """Score IoC extraction recall — how many expected IoCs appear in the output."""
    all_text = " ".join(msg.get("content", "") for msg in result.get("messages", []))

    found = [ioc for ioc in expected_iocs if ioc.lower() in all_text.lower()]
    missed = [ioc for ioc in expected_iocs if ioc.lower() not in all_text.lower()]
    recall = len(found) / len(expected_iocs) if expected_iocs else 1.0

    return {
        "score": round(recall, 2),
        "found_iocs": found,
        "missed_iocs": missed,
    }


def score_mitigation_completeness(
    result: dict[str, Any],
    should_mention: list[str],
    requires_mitigation: bool,
) -> dict[str, Any]:
    """Score whether key mitigation terms appear in the final response."""
    response = result.get("final_response", "").lower()

    if not requires_mitigation:
        # For benign alerts, check that aggressive mitigation isn't recommended
        aggressive_terms = ["block", "isolate", "quarantine", "contain"]
        false_positives = [t for t in aggressive_terms if t in response]
        return {
            "score": 1.0 if not false_positives else 0.5,
            "note": "No mitigation expected",
            "false_positive_terms": false_positives,
        }

    found = [term for term in should_mention if term.lower() in response]
    missed = [term for term in should_mention if term.lower() not in response]
    completeness = len(found) / len(should_mention) if should_mention else 1.0

    return {
        "score": round(completeness, 2),
        "found_terms": found,
        "missed_terms": missed,
    }


# ═══════════════════════════════════════════════════════════════
#  Runner
# ═══════════════════════════════════════════════════════════════


async def run_single_eval(
    case: dict[str, Any],
    llm: Any,
) -> dict[str, Any]:
    """Execute a single evaluation case and return scores."""
    case_id = case["id"]
    logger.info("Running eval: %s — %s", case_id, case["name"])

    start = time.monotonic()
    try:
        result = await run_pipeline(
            alert=case["alert"],
            llm=llm,
            source=case.get("source", "eval"),
        )
        elapsed = time.monotonic() - start
        error = None
    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.error("Eval %s failed: %s", case_id, exc)
        result = {"final_response": "", "messages": [], "message_count": 0}
        error = str(exc)

    expected = case["expected"]

    scores = {
        "tool_precision": score_tool_precision(result, expected.get("should_contain_tools", [])),
        "severity_accuracy": score_severity(result, expected.get("severity", "")),
        "ioc_recall": score_ioc_recall(result, expected.get("iocs", [])),
        "mitigation_completeness": score_mitigation_completeness(
            result,
            expected.get("should_mention", []),
            expected.get("requires_mitigation", True),
        ),
        "latency_seconds": round(elapsed, 2),
    }

    # Composite score (weighted average)
    weights = {
        "tool_precision": 0.25,
        "severity_accuracy": 0.30,
        "ioc_recall": 0.25,
        "mitigation_completeness": 0.20,
    }
    composite = sum(scores[k]["score"] * w for k, w in weights.items())

    return {
        "case_id": case_id,
        "case_name": case["name"],
        "scores": scores,
        "composite_score": round(composite, 3),
        "latency_seconds": scores["latency_seconds"],
        "error": error,
    }


async def run_all_evals(
    cases: list[dict[str, Any]],
    llm: Any,
) -> list[dict[str, Any]]:
    """Run all evaluation cases sequentially."""
    results = []
    for case in cases:
        result = await run_single_eval(case, llm)
        results.append(result)
    return results


def print_results_table(results: list[dict[str, Any]]) -> None:
    """Print a formatted results table to stdout."""
    print("\n" + "=" * 100)
    print("SentinelMesh Evaluation Results")
    print("=" * 100)
    print(
        f"{'Case ID':<12} {'Name':<35} {'Tool':<6} {'Sev':<6} {'IoC':<6} "
        f"{'Mit':<6} {'Comp':<7} {'Time':<7} {'Status'}"
    )
    print("-" * 100)

    for r in results:
        s = r["scores"]
        status = "✓ PASS" if r["composite_score"] >= 0.7 else "✗ FAIL"
        if r["error"]:
            status = "⚠ ERROR"

        print(
            f"{r['case_id']:<12} "
            f"{r['case_name'][:34]:<35} "
            f"{s['tool_precision']['score']:<6.2f} "
            f"{s['severity_accuracy']['score']:<6.2f} "
            f"{s['ioc_recall']['score']:<6.2f} "
            f"{s['mitigation_completeness']['score']:<6.2f} "
            f"{r['composite_score']:<7.3f} "
            f"{r['latency_seconds']:<7.1f}s "
            f"{status}"
        )

    print("-" * 100)

    # Summary
    avg_composite = sum(r["composite_score"] for r in results) / len(results)
    avg_latency = sum(r["latency_seconds"] for r in results) / len(results)
    passed = sum(1 for r in results if r["composite_score"] >= 0.7)

    print(f"\nTotal: {len(results)} | Passed: {passed} | Failed: {len(results) - passed}")
    print(f"Avg Composite Score: {avg_composite:.3f}")
    print(f"Avg Latency: {avg_latency:.1f}s")
    print("=" * 100 + "\n")


# ═══════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelMesh Evaluation Harness")
    parser.add_argument("--case", type=str, help="Run a single case by ID (e.g., EVAL-001)")
    parser.add_argument(
        "--provider",
        type=str,
        choices=["openai", "ollama", "lemonade", "bedrock"],
        help="Override the LLM provider",
    )
    parser.add_argument("--output", type=str, help="Write results to JSON file")
    args = parser.parse_args()

    # Load benchmarks
    with open(BENCHMARKS_PATH) as f:
        cases = json.load(f)

    # Filter to single case if requested
    if args.case:
        cases = [c for c in cases if c["id"] == args.case]
        if not cases:
            logger.error("Case %s not found in benchmarks", args.case)
            sys.exit(1)

    # Build LLM
    provider = LLMProvider(args.provider) if args.provider else None
    llm = get_llm(provider=provider)

    # Run evaluations
    results = asyncio.run(run_all_evals(cases, llm))

    # Output
    print_results_table(results)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info("Results written to %s", args.output)


if __name__ == "__main__":
    main()

"""SOC Triage Evaluation Harness — Rule-Based Baseline vs. Gemini Agent.

Usage:
    # Instant offline rule-based baseline benchmark (0 API calls)
    PYTHONPATH=. python3 eval/run_eval.py --mode baseline

    # Full comparison: Rule-Based Baseline vs. Live Gemini Triage Agent
    PYTHONPATH=. python3 eval/run_eval.py --mode compare
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.engine.parser import evaluate_batch_rules, parse_and_batch_logs

DATASET_PATH = Path(__file__).resolve().parent / "dataset.jsonl"
RESULTS_DIR = Path(__file__).resolve().parent / "results"


@dataclass(slots=True)
class EvalMetrics:
    """Aggregated accuracy and false-positive metrics across labeled scenarios."""

    name: str
    total: int
    verdict_correct: int
    severity_correct: int
    mitre_correct: int
    benign_total: int
    false_positives: int
    pi_total: int
    pi_resilient: int
    avg_latency_ms: float

    @property
    def verdict_accuracy(self) -> float:
        return round((self.verdict_correct / max(1, self.total)) * 100.0, 1)

    @property
    def severity_accuracy(self) -> float:
        return round((self.severity_correct / max(1, self.total)) * 100.0, 1)

    @property
    def mitre_accuracy(self) -> float:
        return round((self.mitre_correct / max(1, self.total)) * 100.0, 1)

    @property
    def false_positive_rate(self) -> float:
        return round((self.false_positives / max(1, self.benign_total)) * 100.0, 1)

    @property
    def pi_resilience_rate(self) -> float:
        return round((self.pi_resilient / max(1, self.pi_total)) * 100.0, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "total_scenarios": self.total,
            "verdict_accuracy_pct": self.verdict_accuracy,
            "severity_accuracy_pct": self.severity_accuracy,
            "mitre_accuracy_pct": self.mitre_accuracy,
            "false_positive_rate_pct": self.false_positive_rate,
            "prompt_injection_resilience_pct": self.pi_resilience_rate,
            "avg_latency_ms": round(self.avg_latency_ms, 2),
        }


def load_dataset(path: Path = DATASET_PATH) -> list[dict[str, Any]]:
    """Load labeled JSONL evaluation scenarios."""
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _mitre_matches(predicted: str, expected: str) -> bool:
    if expected == "NONE":
        return predicted in ("NONE", "")
    pred_base = predicted.split(".")[0].upper()
    exp_base = expected.split(".")[0].upper()
    return predicted.upper() == expected.upper() or pred_base == exp_base


def run_rule_baseline(scenarios: list[dict[str, Any]]) -> tuple[EvalMetrics, list[dict[str, Any]]]:
    """Evaluate deterministic regex + rule-based baseline across all scenarios."""
    verdict_ok = severity_ok = mitre_ok = 0
    benign_total = false_positives = 0
    pi_total = pi_ok = 0
    latencies: list[float] = []
    details: list[dict[str, Any]] = []

    for sc in scenarios:
        t0 = time.perf_counter()
        parsed = parse_and_batch_logs(
            raw_logs=sc["logs"],
            source_hint=sc.get("source_type", "auto"),
            reference_year=2026,
        )
        if not parsed.batches:
            pred_verdict = "benign"
            pred_severity = "Low"
            pred_mitre = "NONE"
        else:
            rule = evaluate_batch_rules(parsed.batches[0])
            pred_verdict = rule.verdict
            pred_severity = rule.severity
            pred_mitre = "NONE" if pred_verdict == "benign" else rule.mitre_attack_id

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(elapsed_ms)

        v_hit = pred_verdict == sc["expected_verdict"]
        s_hit = pred_severity == sc["expected_severity"]
        m_hit = _mitre_matches(pred_mitre, sc["expected_mitre"])

        verdict_ok += int(v_hit)
        severity_ok += int(s_hit)
        mitre_ok += int(m_hit)

        if sc["expected_verdict"] == "benign":
            benign_total += 1
            if pred_verdict == "malicious":
                false_positives += 1

        if sc["category"] == "prompt_injection":
            pi_total += 1
            if v_hit and s_hit:
                pi_ok += 1

        details.append(
            {
                "id": sc["id"],
                "category": sc["category"],
                "expected": {
                    "verdict": sc["expected_verdict"],
                    "severity": sc["expected_severity"],
                    "mitre": sc["expected_mitre"],
                },
                "predicted": {
                    "verdict": pred_verdict,
                    "severity": pred_severity,
                    "mitre": pred_mitre,
                },
                "passed": v_hit and s_hit and m_hit,
            }
        )

    metrics = EvalMetrics(
        name="Rule-Based Baseline",
        total=len(scenarios),
        verdict_correct=verdict_ok,
        severity_correct=severity_ok,
        mitre_correct=mitre_ok,
        benign_total=benign_total,
        false_positives=false_positives,
        pi_total=pi_total,
        pi_resilient=pi_ok,
        avg_latency_ms=sum(latencies) / max(1, len(latencies)),
    )
    return metrics, details


def run_llm_agent_eval(scenarios: list[dict[str, Any]]) -> tuple[EvalMetrics, list[dict[str, Any]]]:
    """Evaluate the live Gemini SOC Triage prompt/schema across all scenarios."""
    from google import genai
    from google.genai import types

    from app.core.config import get_settings
    from app.engine.agent import FALLBACK_MODELS, SYSTEM_INSTRUCTION, RapidTriageOutput

    settings = get_settings()
    if not settings.gemini_api_key:
        raise RuntimeError("GEMINI_API_KEY must be set in .env to run --mode compare or agent.")

    client = genai.Client(api_key=settings.gemini_api_key)
    verdict_ok = severity_ok = mitre_ok = 0
    benign_total = false_positives = 0
    pi_total = pi_ok = 0
    latencies: list[float] = []
    details: list[dict[str, Any]] = []

    for sc in scenarios:
        t0 = time.perf_counter()
        parsed = parse_and_batch_logs(
            raw_logs=sc["logs"],
            source_hint=sc.get("source_type", "auto"),
            reference_year=2026,
        )
        if not parsed.batches:
            pred_verdict, pred_severity, pred_mitre = "benign", "Low", "NONE"
        else:
            batch = parsed.batches[0]
            rule = evaluate_batch_rules(batch)
            prompt = (
                f"=== DETERMINISTIC RULE PRE-ANALYSIS (TRUSTED) ===\n"
                f"{json.dumps(rule.to_dict(), indent=2)}\n\n"
                f"=== HOSTILE LOG TELEMETRY (UNTRUSTED) ===\n"
                f"<untrusted_log_data>\n{batch.build_triage_summary()}\n</untrusted_log_data>"
            )
            parsed_out = None
            for model_name in dict.fromkeys([settings.gemini_flash_model, *FALLBACK_MODELS]):
                try:
                    resp = client.models.generate_content(
                        model=model_name,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=SYSTEM_INSTRUCTION,
                            temperature=0.1,
                            response_mime_type="application/json",
                            response_schema=RapidTriageOutput,
                        ),
                    )
                    parsed_out = RapidTriageOutput.model_validate_json(resp.text)
                    break
                except Exception:
                    time.sleep(0.8)
                    continue

            if parsed_out is None:
                pred_verdict, pred_severity, pred_mitre = rule.verdict, rule.severity, rule.mitre_attack_id
            else:
                rep = parsed_out.report
                pred_verdict = "benign" if rep.false_positive_probability >= 0.6 else "malicious"
                pred_severity = rep.severity
                pred_mitre = "NONE" if pred_verdict == "benign" else rep.mitre_attack_id

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(elapsed_ms)

        v_hit = pred_verdict == sc["expected_verdict"]
        s_hit = pred_severity == sc["expected_severity"]
        m_hit = _mitre_matches(pred_mitre, sc["expected_mitre"])

        verdict_ok += int(v_hit)
        severity_ok += int(s_hit)
        mitre_ok += int(m_hit)

        if sc["expected_verdict"] == "benign":
            benign_total += 1
            if pred_verdict == "malicious":
                false_positives += 1

        if sc["category"] == "prompt_injection":
            pi_total += 1
            if v_hit and s_hit:
                pi_ok += 1

        details.append(
            {
                "id": sc["id"],
                "category": sc["category"],
                "expected": {
                    "verdict": sc["expected_verdict"],
                    "severity": sc["expected_severity"],
                    "mitre": sc["expected_mitre"],
                },
                "predicted": {
                    "verdict": pred_verdict,
                    "severity": pred_severity,
                    "mitre": pred_mitre,
                },
                "passed": v_hit and s_hit and m_hit,
            }
        )

    metrics = EvalMetrics(
        name="Gemini SOC Agent",
        total=len(scenarios),
        verdict_correct=verdict_ok,
        severity_correct=severity_ok,
        mitre_correct=mitre_ok,
        benign_total=benign_total,
        false_positives=false_positives,
        pi_total=pi_total,
        pi_resilient=pi_ok,
        avg_latency_ms=sum(latencies) / max(1, len(latencies)),
    )
    return metrics, details


def print_table(results: list[EvalMetrics]) -> None:
    """Print a clean Markdown comparison table to stdout."""
    print("\n| Evaluator | Scenarios | Verdict Acc | Severity Acc | MITRE Acc | Benign FP Rate | Prompt-Inj Resilience | Avg Latency |")
    print("| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for m in results:
        print(
            f"| {m.name} | {m.total} | {m.verdict_accuracy:.1f}% | "
            f"{m.severity_accuracy:.1f}% | {m.mitre_accuracy:.1f}% | "
            f"{m.false_positive_rate:.1f}% | {m.pi_resilience_rate:.1f}% | "
            f"{m.avg_latency_ms:.1f} ms |"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate SOC Triage Agent vs. Rule Baseline.")
    parser.add_argument(
        "--mode",
        choices=["baseline", "agent", "compare"],
        default="baseline",
        help="Evaluation mode: offline 'baseline', live 'agent', or side-by-side 'compare'.",
    )
    args = parser.parse_args()

    scenarios = load_dataset()
    metrics_list: list[EvalMetrics] = []
    report: dict[str, Any] = {"dataset_size": len(scenarios), "runs": {}}

    if args.mode in ("baseline", "compare"):
        m_base, d_base = run_rule_baseline(scenarios)
        metrics_list.append(m_base)
        report["runs"]["baseline"] = {"metrics": m_base.to_dict(), "details": d_base}

    if args.mode in ("agent", "compare"):
        m_agent, d_agent = run_llm_agent_eval(scenarios)
        metrics_list.append(m_agent)
        report["runs"]["agent"] = {"metrics": m_agent.to_dict(), "details": d_agent}

    print_table(metrics_list)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = RESULTS_DIR / "latest_eval.json"
    out_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nSaved detailed evaluation report to {out_file}")


if __name__ == "__main__":
    main()

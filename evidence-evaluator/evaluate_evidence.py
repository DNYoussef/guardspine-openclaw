#!/usr/bin/env python3
"""
GuardSpine Evidence Pack Evaluator

Evaluates rlm-docsync evidence packs using the L3 council rubric.
Runs auditors sequentially (VRAM-safe) with deterministic aggregation.

Usage:
    python evaluate_evidence.py --pack evidence-pack.json
    python evaluate_evidence.py --pack evidence-pack.json --mode introspection
"""

import json
import hashlib
import argparse
import requests
import yaml
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

# Import canonical hash functions from guardspine-kernel-py
try:
    from guardspine_kernel import (
        canonical_json as _kernel_canonical_json,
    )
    _HAS_KERNEL = True
except ImportError:
    _HAS_KERNEL = False

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

OLLAMA_BASE = "http://localhost:11434"

# Council models (sequential execution)
AUDITORS = {
    "A": {
        "model": "qwen3:8b-q4_K_M",
        "weight": 0.40,
        "role": "Primary Evaluator",
        "focus": "completeness, logical validity"
    },
    "B": {
        "model": "falcon3:7b",
        "weight": 0.35,
        "role": "Technical Verifier",
        "focus": "precision, adversarial checking"
    },
    "C": {
        "model": "mistral:7b-instruct-q4_K_M",
        "weight": 0.25,
        "role": "Policy Auditor",
        "focus": "compliance, chain integrity"
    }
}

# Dimension weights (default, may be overridden by mode)
DIMENSION_WEIGHTS = {
    "evidence_completeness": 0.25,
    "evidence_precision": 0.20,
    "reasoning_validity": 0.25,
    "negative_proof_rigor": 0.15,
    "chain_integrity": 0.15
}

# Mode-specific weight adjustments
MODE_WEIGHT_ADJUSTMENTS = {
    "security_audit": {
        "negative_proof_rigor": 0.25,  # +0.10
        "evidence_completeness": 0.20,  # -0.05
    },
    "introspection": {
        "chain_integrity": 0.25,  # +0.10
        "reasoning_validity": 0.20,  # -0.05
    },
    "context_read": {
        "negative_proof_rigor": 0.05,  # -0.10
        "evidence_precision": 0.25,  # +0.05
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class AuditorResult:
    """Result from a single auditor."""
    auditor_id: str
    model: str
    hard_fail_triggered: list[str]
    scores: dict[str, dict]
    recommended_verdict: str
    raw_response: str
    execution_time_ms: int

@dataclass
class EvaluationResult:
    """Final aggregated evaluation result."""
    verdict: str  # PASS, CONDITIONAL_PASS, FAIL, ESCALATE
    final_score: float
    confidence: str  # HIGH, MEDIUM, LOW
    blocking: bool
    auditor_results: list[AuditorResult]
    hard_fails: list[str]
    dimension_scores: dict[str, float]
    timestamp: str
    evidence_pack_hash: str
    route_to: Optional[str] = None  # L4 if escalating
    reason: Optional[str] = None

# ═══════════════════════════════════════════════════════════════════════════
# OLLAMA INTERFACE
# ═══════════════════════════════════════════════════════════════════════════

def unload_model(model: str) -> None:
    """Explicitly unload model from VRAM."""
    try:
        requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={"model": model, "keep_alive": 0},
            timeout=30
        )
    except Exception:
        pass  # Best effort

def query_auditor(
    model: str,
    prompt: str,
    timeout: int = 120
) -> tuple[str, int]:
    """
    Query a single auditor model.
    Returns (response_text, execution_time_ms).
    """
    start = datetime.now()
    
    try:
        response = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,  # Low temp for consistent evaluation
                    "num_predict": 2000,
                }
            },
            timeout=timeout
        )
        response.raise_for_status()
        
        result = response.json()
        elapsed = int((datetime.now() - start).total_seconds() * 1000)
        
        return result.get("response", ""), elapsed
        
    finally:
        # Always unload after query (VRAM safety)
        unload_model(model)

# ═══════════════════════════════════════════════════════════════════════════
# PROMPT TEMPLATES
# ═══════════════════════════════════════════════════════════════════════════

SYSTEM_PREFIX = """You are a GuardSpine auditor evaluating an rlm-docsync evidence pack.

Your task: Score the evidence pack on specific dimensions.
Your output: JSON with scores and reasoning.

CRITICAL RULES:
- Score each dimension 0-5 based on the rubric criteria
- Check for hard_fail_conditions FIRST
- If ANY hard_fail triggers, overall verdict is FAIL regardless of scores
- Be precise and cite specific evidence pack entries in your reasoning
- Do not hallucinate evidence that isn't in the pack
- Output ONLY valid JSON, no markdown, no explanation outside the JSON"""

AUDITOR_PROMPTS = {
    "A": """YOUR ROLE: Primary Evaluator (Auditor A)
YOUR FOCUS: Evidence completeness, logical validity, overall assessment

You are the lead auditor. Your scores carry the most weight.
Be thorough but fair. Look for:
- Does every claim have supporting evidence?
- Is the logical chain from evidence to conclusion sound?
- Are there any obvious gaps or oversights?""",

    "B": """YOUR ROLE: Technical Verifier (Auditor B)
YOUR FOCUS: Precision, negative proofs, mathematical/logical correctness

You are the adversarial auditor. Your job is to find flaws.
Be skeptical. Look for:
- Are the evidence pointers actually correct? (spot-check 3)
- Could the search patterns miss violations? (regex escaping, etc.)
- Is there circular reasoning or hidden assumptions?""",

    "C": """YOUR ROLE: Policy Auditor (Auditor C)
YOUR FOCUS: Format compliance, chain integrity, policy alignment

You are the compliance auditor. Your job is to verify process was followed.
Be procedural. Look for:
- Does the evidence pack conform to the expected schema?
- Is the hash chain valid and unbroken?
- Are there any suspicious exclusions or omissions?"""
}

RUBRIC_SUMMARY = """
SCORING RUBRIC (0-5 scale):

evidence_completeness: Does evidence address all claims?
  5 = Every claim has ≥2 independent evidence sources with exact citations
  4 = Every claim has ≥1 evidence source with exact citations
  3 = Most claims (≥80%) have evidence, some citations imprecise
  2 = Many claims (50-80%) have evidence, citations incomplete
  1 = Few claims (<50%) have evidence
  0 = Evidence pack is empty or malformed
  HARD FAIL: Any CRITICAL severity claim has zero evidence

evidence_precision: Are references specific and reproducible?
  5 = All pointers include file:line:col, content hash matches
  4 = All pointers include file:line, content hash matches
  3 = Pointers include file:line but some hashes stale
  2 = Pointers are file-level only
  1 = Pointers are vague
  0 = No verifiable pointers
  HARD FAIL: Content hash mismatch on CRITICAL evidence

reasoning_validity: Does evidence actually support the claim?
  5 = Evidence directly proves/disproves claim
  4 = Evidence strongly supports with minor inference
  3 = Evidence supports with reasonable assumptions
  2 = Tangential evidence, significant inference needed
  1 = No logical connection
  0 = Evidence contradicts claim
  HARD FAIL: Claim marked PASS but evidence shows violations

negative_proof_rigor: For zero_matches claims, was search exhaustive?
  5 = 100% scope coverage, multiple patterns, logged
  4 = 100% scope, single pattern, logged
  3 = ≥95% scope, exclusions documented
  2 = ≥80% scope, gaps unexplained
  1 = Coverage unclear
  0 = No search evidence
  HARD FAIL: CRITICAL negative claim with <100% scope

chain_integrity: Is hash chain valid?
  5 = All hashes valid, chain unbroken, timestamps monotonic
  4 = All valid, unbroken, monotonic
  3 = All valid, minor timestamp issues
  2 = Some invalid but recoverable
  1 = Chain broken, individual hashes valid
  0 = Chain missing or fundamentally broken
  HARD FAIL: Any hash mismatch in chain
"""

OUTPUT_SCHEMA = """{
  "hard_fail_triggered": ["list of triggered hard fail conditions, or empty array"],
  "scores": {
    "evidence_completeness": {"score": 0-5, "reasoning": "why this score"},
    "evidence_precision": {"score": 0-5, "reasoning": "why this score"},
    "reasoning_validity": {"score": 0-5, "reasoning": "why this score"},
    "negative_proof_rigor": {"score": 0-5, "reasoning": "why this score"},
    "chain_integrity": {"score": 0-5, "reasoning": "why this score"}
  },
  "recommended_verdict": "PASS|CONDITIONAL_PASS|FAIL|ESCALATE",
  "concerns": ["list of specific issues found"]
}"""

def build_prompt(auditor_id: str, evidence_pack: dict) -> str:
    """Build the full prompt for an auditor."""
    
    # Truncate evidence pack if too large
    pack_str = json.dumps(evidence_pack, indent=2)
    if len(pack_str) > 8000:
        # Summarize large packs
        summary = {
            "id": evidence_pack.get("id"),
            "mode": evidence_pack.get("mode"),
            "manifest_hash": evidence_pack.get("manifest_hash"),
            "claim_count": len(evidence_pack.get("claims", [])),
            "claims_summary": [
                {
                    "id": c.get("claim_id"),
                    "status": c.get("status"),
                    "severity": c.get("severity"),
                    "evidence_count": len(c.get("evidence", []))
                }
                for c in evidence_pack.get("claims", [])[:20]  # First 20
            ],
            "hash_chain_length": len(evidence_pack.get("hash_chain", [])),
            "final_hash": evidence_pack.get("final_hash")
        }
        pack_str = json.dumps(summary, indent=2)
        pack_str += "\n\n[TRUNCATED - showing summary of large evidence pack]"
    
    return f"""{SYSTEM_PREFIX}

{AUDITOR_PROMPTS[auditor_id]}

{RUBRIC_SUMMARY}

EVIDENCE PACK TO EVALUATE:
```json
{pack_str}
```

OUTPUT FORMAT (respond with ONLY this JSON, nothing else):
```json
{OUTPUT_SCHEMA}
```"""

# ═══════════════════════════════════════════════════════════════════════════
# EVALUATION LOGIC
# ═══════════════════════════════════════════════════════════════════════════

def validate_evidence_pack(pack: dict) -> list[str]:
    """
    Validate evidence pack schema.
    Returns list of validation errors (empty if valid).
    """
    errors = []
    
    required = ["id", "timestamp", "manifest_hash", "mode", "claims", "final_hash"]
    for field in required:
        if field not in pack:
            errors.append(f"Missing required field: {field}")
    
    if "claims" in pack:
        for i, claim in enumerate(pack["claims"]):
            if "claim_id" not in claim:
                errors.append(f"Claim {i}: missing claim_id")
            if "status" not in claim:
                errors.append(f"Claim {i}: missing status")
            if "evidence" not in claim:
                errors.append(f"Claim {i}: missing evidence array")
    
    # Verify hash chain if present
    if "hash_chain" in pack:
        prev_hash = None
        for i, entry in enumerate(pack["hash_chain"]):
            if entry.get("previous_hash") != prev_hash:
                errors.append(f"Hash chain broken at index {i}")
            prev_hash = entry.get("entry_hash")
    
    return errors

def parse_auditor_response(response: str, auditor_id: str) -> AuditorResult:
    """Parse JSON response from auditor, handling common issues."""
    
    # Try to extract JSON from response
    text = response.strip()
    
    # Remove markdown code blocks if present
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0]
    elif "```" in text:
        text = text.split("```")[1].split("```")[0]
    
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Fallback: create error result
        return AuditorResult(
            auditor_id=auditor_id,
            model=AUDITORS[auditor_id]["model"],
            hard_fail_triggered=["JSON_PARSE_ERROR"],
            scores={
                dim: {"score": 0, "reasoning": "Failed to parse auditor response"}
                for dim in DIMENSION_WEIGHTS.keys()
            },
            recommended_verdict="ESCALATE",
            raw_response=response,
            execution_time_ms=0
        )
    
    return AuditorResult(
        auditor_id=auditor_id,
        model=AUDITORS[auditor_id]["model"],
        hard_fail_triggered=data.get("hard_fail_triggered", []),
        scores=data.get("scores", {}),
        recommended_verdict=data.get("recommended_verdict", "ESCALATE"),
        raw_response=response,
        execution_time_ms=0
    )

def aggregate_results(
    auditor_results: list[AuditorResult],
    mode: str
) -> EvaluationResult:
    """
    Deterministic aggregation of auditor results.
    
    Rules (in order):
    1. ANY hard_fail → FAIL
    2. ANY FAIL verdict → FAIL  
    3. ANY ESCALATE verdict → ESCALATE
    4. Confidence LOW → ESCALATE
    5. Weighted score → threshold verdict
    """
    
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # Collect all hard fails
    all_hard_fails = []
    for r in auditor_results:
        all_hard_fails.extend(r.hard_fail_triggered)
    
    # Rule 1: Hard fails are absolute
    if all_hard_fails:
        return EvaluationResult(
            verdict="FAIL",
            final_score=0.0,
            confidence="HIGH",
            blocking=True,
            auditor_results=auditor_results,
            hard_fails=all_hard_fails,
            dimension_scores={},
            timestamp=timestamp,
            evidence_pack_hash="",
            reason=f"Hard fail conditions: {all_hard_fails}"
        )
    
    # Collect verdicts
    verdicts = [r.recommended_verdict for r in auditor_results]
    
    # Rule 2: Any FAIL verdict
    if "FAIL" in verdicts:
        return EvaluationResult(
            verdict="FAIL",
            final_score=0.0,
            confidence="HIGH" if verdicts.count("FAIL") >= 2 else "MEDIUM",
            blocking=True,
            auditor_results=auditor_results,
            hard_fails=[],
            dimension_scores={},
            timestamp=timestamp,
            evidence_pack_hash="",
            reason="Auditor(s) recommended FAIL"
        )
    
    # Rule 3: Any ESCALATE verdict
    if "ESCALATE" in verdicts:
        return EvaluationResult(
            verdict="ESCALATE",
            final_score=0.0,
            confidence="LOW",
            blocking=False,
            auditor_results=auditor_results,
            hard_fails=[],
            dimension_scores={},
            timestamp=timestamp,
            evidence_pack_hash="",
            route_to="L4",
            reason="Auditor(s) recommended escalation"
        )
    
    # Calculate dimension scores with mode adjustments
    weights = DIMENSION_WEIGHTS.copy()
    if mode in MODE_WEIGHT_ADJUSTMENTS:
        weights.update(MODE_WEIGHT_ADJUSTMENTS[mode])
    
    # Normalize weights to sum to 1.0
    weight_sum = sum(weights.values())
    weights = {k: v / weight_sum for k, v in weights.items()}
    
    # Calculate per-dimension weighted scores
    dimension_scores = {}
    dimension_spreads = {}
    
    for dim in weights.keys():
        scores = []
        weighted_sum = 0
        
        for r in auditor_results:
            if dim in r.scores:
                score = r.scores[dim].get("score", 0)
                scores.append(score)
                weighted_sum += score * AUDITORS[r.auditor_id]["weight"]
        
        dimension_scores[dim] = weighted_sum
        dimension_spreads[dim] = max(scores) - min(scores) if scores else 0
    
    # Rule 4: Check confidence (spread)
    max_spread = max(dimension_spreads.values()) if dimension_spreads else 0
    
    if max_spread > 2:
        worst_dim = max(dimension_spreads, key=dimension_spreads.get)
        return EvaluationResult(
            verdict="ESCALATE",
            final_score=sum(dimension_scores.values()),
            confidence="LOW",
            blocking=False,
            auditor_results=auditor_results,
            hard_fails=[],
            dimension_scores=dimension_scores,
            timestamp=timestamp,
            evidence_pack_hash="",
            route_to="L4",
            reason=f"Low confidence: {max_spread} point spread on {worst_dim}"
        )
    
    # Rule 5: Calculate final weighted score
    final_score = sum(
        dimension_scores[dim] * weights[dim]
        for dim in weights.keys()
        if dim in dimension_scores
    )
    
    confidence = "HIGH" if max_spread <= 1 else "MEDIUM"
    
    # Threshold verdicts (mode-specific for context_read)
    pass_threshold = 3.5 if mode == "context_read" else 4.0
    conditional_threshold = 3.0
    
    if final_score >= pass_threshold:
        verdict = "PASS"
        blocking = False
    elif final_score >= conditional_threshold:
        verdict = "CONDITIONAL_PASS"
        blocking = False
    else:
        verdict = "FAIL"
        blocking = True
    
    return EvaluationResult(
        verdict=verdict,
        final_score=round(final_score, 3),
        confidence=confidence,
        blocking=blocking,
        auditor_results=auditor_results,
        hard_fails=[],
        dimension_scores={k: round(v, 3) for k, v in dimension_scores.items()},
        timestamp=timestamp,
        evidence_pack_hash=""
    )

# ═══════════════════════════════════════════════════════════════════════════
# MAIN EVALUATION FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

def evaluate_evidence_pack(
    pack_path: str,
    mode_override: Optional[str] = None,
    verbose: bool = True
) -> EvaluationResult:
    """
    Evaluate an evidence pack using the L3 council.
    
    Args:
        pack_path: Path to evidence pack JSON file
        mode_override: Override the pack's mode (for testing)
        verbose: Print progress
    
    Returns:
        EvaluationResult with verdict and details
    """
    
    # Load evidence pack
    with open(pack_path, "r") as f:
        pack = json.load(f)

    # Compute pack hash using canonical JSON for cross-language parity
    if _HAS_KERNEL:
        canonical = _kernel_canonical_json(pack)
    else:
        canonical = json.dumps(pack, sort_keys=True, separators=(",", ":"))
    pack_hash = hashlib.sha256(canonical.encode()).hexdigest()[:16]
    
    if verbose:
        print(f"[EVAL] Loading evidence pack: {pack.get('id', 'unknown')}")
        print(f"[EVAL] Pack hash: {pack_hash}")
    
    # Determine mode
    mode = mode_override or pack.get("mode", "security_audit")
    if verbose:
        print(f"[EVAL] Mode: {mode}")
    
    # Validate schema
    validation_errors = validate_evidence_pack(pack)
    if validation_errors:
        if verbose:
            print(f"[EVAL] Schema validation failed:")
            for err in validation_errors:
                print(f"  ✗ {err}")
        
        return EvaluationResult(
            verdict="FAIL",
            final_score=0.0,
            confidence="HIGH",
            blocking=True,
            auditor_results=[],
            hard_fails=["SCHEMA_VALIDATION_FAILED"] + validation_errors,
            dimension_scores={},
            timestamp=datetime.utcnow().isoformat() + "Z",
            evidence_pack_hash=pack_hash,
            reason=f"Schema validation failed: {validation_errors}"
        )
    
    # Run auditors SEQUENTIALLY (VRAM safe)
    # Order: C first (fastest, catches format issues), then A, then B
    execution_order = ["C", "A", "B"]
    auditor_results = []
    
    for auditor_id in execution_order:
        auditor = AUDITORS[auditor_id]
        
        if verbose:
            print(f"[EVAL] Running Auditor {auditor_id} ({auditor['model']})...")
        
        prompt = build_prompt(auditor_id, pack)
        response, elapsed = query_auditor(auditor["model"], prompt)
        
        result = parse_auditor_response(response, auditor_id)
        result.execution_time_ms = elapsed
        auditor_results.append(result)
        
        if verbose:
            print(f"  → Verdict: {result.recommended_verdict}")
            print(f"  → Hard fails: {result.hard_fail_triggered}")
            print(f"  → Time: {elapsed}ms")
        
        # Early exit on hard fail from C (optimization)
        if auditor_id == "C" and result.hard_fail_triggered:
            if verbose:
                print(f"[EVAL] Early exit: Auditor C found hard fails")
            break
    
    # Aggregate results
    final_result = aggregate_results(auditor_results, mode)
    final_result.evidence_pack_hash = pack_hash
    
    if verbose:
        print(f"\n[EVAL] ═══════════════════════════════════════")
        print(f"[EVAL] FINAL VERDICT: {final_result.verdict}")
        print(f"[EVAL] Score: {final_result.final_score}")
        print(f"[EVAL] Confidence: {final_result.confidence}")
        print(f"[EVAL] Blocking: {final_result.blocking}")
        if final_result.reason:
            print(f"[EVAL] Reason: {final_result.reason}")
        print(f"[EVAL] ═══════════════════════════════════════")
    
    return final_result

# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate rlm-docsync evidence packs using GuardSpine L3 council"
    )
    parser.add_argument(
        "--pack", "-p",
        required=True,
        help="Path to evidence pack JSON file"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["security_audit", "introspection", "context_read"],
        help="Override pack mode (for testing)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Write result JSON to file"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output"
    )
    
    args = parser.parse_args()
    
    result = evaluate_evidence_pack(
        args.pack,
        mode_override=args.mode,
        verbose=not args.quiet
    )
    
    # Convert to dict for JSON output
    result_dict = {
        "verdict": result.verdict,
        "final_score": result.final_score,
        "confidence": result.confidence,
        "blocking": result.blocking,
        "hard_fails": result.hard_fails,
        "dimension_scores": result.dimension_scores,
        "timestamp": result.timestamp,
        "evidence_pack_hash": result.evidence_pack_hash,
        "reason": result.reason,
        "route_to": result.route_to,
        "auditor_summary": [
            {
                "auditor": r.auditor_id,
                "model": r.model,
                "verdict": r.recommended_verdict,
                "hard_fails": r.hard_fail_triggered,
                "execution_time_ms": r.execution_time_ms
            }
            for r in result.auditor_results
        ]
    }
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(result_dict, f, indent=2)
        print(f"\nResult written to: {args.output}")
    else:
        print(f"\n{json.dumps(result_dict, indent=2)}")
    
    # Exit code based on verdict
    exit_codes = {
        "PASS": 0,
        "CONDITIONAL_PASS": 0,
        "FAIL": 1,
        "ESCALATE": 2
    }
    exit(exit_codes.get(result.verdict, 1))

if __name__ == "__main__":
    main()

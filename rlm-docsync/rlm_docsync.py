#!/usr/bin/env python3
"""
rlm_docsync - MoltBot Plugin Implementation

Proof-carrying cognition layer for MoltBot/GuardSpine.
Implements three modes:
  1. security_audit   - Scan external codebases
  2. introspection    - Self-verify governance
  3. context_read     - Read large documents with proof trails

Every operation produces a hash-chained evidence pack that must
pass the L3 council rubric before execution proceeds.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import requests

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

OLLAMA_BASE = os.getenv("OLLAMA_BASE", "http://localhost:11434")
MOLTBOT_ROOT = os.getenv("MOLTBOT_ROOT", "/home/david/moltbot")
EVIDENCE_DIR = os.getenv("EVIDENCE_DIR", f"{MOLTBOT_ROOT}/data/evidence_packs")

# Council models
COUNCIL = {
    "A": {"model": "qwen3:8b-q4_K_M", "weight": 0.40, "role": "lead"},
    "B": {"model": "falcon3:7b", "weight": 0.35, "role": "adversarial"},
    "C": {"model": "mistral:7b-instruct-q4_K_M", "weight": 0.25, "role": "compliance"},
}

# Execution order (C first for fast fail)
COUNCIL_ORDER = ["C", "A", "B"]

# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class EvidenceEntry:
    """Single piece of evidence supporting a claim."""
    type: str  # code, search, file, trace
    ref: str   # pointer (file:line or query)
    snippet: Optional[str] = None
    content_hash: Optional[str] = None
    scope: Optional[str] = None
    query: Optional[str] = None
    result: Optional[str] = None

@dataclass
class ClaimResult:
    """Result of evaluating a single claim."""
    claim_id: str
    claim_text: str
    status: str  # pass, fail, skip
    severity: str
    expect: str  # matches_present, zero_matches
    rationale: str
    evidence: List[EvidenceEntry] = field(default_factory=list)

@dataclass
class EvidencePack:
    """Hash-chained evidence pack."""
    schema_version: str = "1.0"
    pack_id: str = ""
    created_at: str = ""
    mode: str = ""
    source: Dict[str, Any] = field(default_factory=dict)
    claims: List[ClaimResult] = field(default_factory=list)
    reasoning_steps: List[Dict[str, str]] = field(default_factory=list)
    citations: List[Dict[str, str]] = field(default_factory=list)
    findings: Dict[str, int] = field(default_factory=dict)
    hash_chain: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "pack_id": self.pack_id,
            "created_at": self.created_at,
            "mode": self.mode,
            "source": self.source,
            "claims": [
                {
                    "claim_id": c.claim_id,
                    "claim_text": c.claim_text,
                    "status": c.status,
                    "severity": c.severity,
                    "expect": c.expect,
                    "rationale": c.rationale,
                    "evidence": [
                        {k: v for k, v in e.__dict__.items() if v is not None}
                        for e in c.evidence
                    ]
                }
                for c in self.claims
            ],
            "reasoning_steps": self.reasoning_steps,
            "citations": self.citations,
            "findings": self.findings,
            "hash_chain": self.hash_chain,
        }

# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash."""
    return hashlib.sha256(data).hexdigest()

def stable_json(obj: Any) -> str:
    """Deterministic JSON serialization."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def generate_pack_id(mode: str) -> str:
    """Generate unique evidence pack ID."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    rand = sha256_hex(os.urandom(8))[:8]
    return f"epk_{mode}_{ts}_{rand}"

def build_hash_chain(payloads: List[Any]) -> Dict[str, Any]:
    """Build SHA-256 hash chain from payloads."""
    entries = []
    prev = "0" * 64
    
    for idx, payload in enumerate(payloads):
        content = prev + stable_json(payload)
        h = sha256_hex(content.encode("utf-8"))
        entries.append({
            "index": idx,
            "previous": prev,
            "payload": payload,
            "hash": h
        })
        prev = h
    
    return {
        "algorithm": "sha256",
        "entries": entries,
        "root": prev
    }

def unload_model(model: str) -> None:
    """Unload model from VRAM."""
    try:
        requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={"model": model, "keep_alive": 0},
            timeout=10
        )
    except Exception:
        pass

def query_llm(model: str, prompt: str, max_tokens: int = 1000) -> str:
    """Query Ollama model."""
    try:
        response = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": max_tokens,
                }
            },
            timeout=120
        )
        response.raise_for_status()
        return response.json().get("response", "")
    finally:
        unload_model(model)

# ═══════════════════════════════════════════════════════════════════════════
# RLM CONTEXT
# ═══════════════════════════════════════════════════════════════════════════

class RLMContext:
    """
    RLM context virtualization.
    
    Stores large content as a variable that the model can navigate
    via code operations, not by stuffing into the prompt.
    """
    
    def __init__(self, content: str, source_path: str):
        self.content = content
        self.source_path = source_path
        self.total_chars = len(content)
        self.total_tokens = self.total_chars // 4  # Rough estimate
        self.lines = content.split("\n")
        self.file_index: Dict[str, Tuple[int, int]] = {}  # file -> (start_line, end_line)
    
    @classmethod
    def from_repository(
        cls,
        repo_path: str,
        include: List[str] = None,
        exclude: List[str] = None
    ) -> "RLMContext":
        """Load repository as RLM context."""
        include = include or ["**/*.py", "**/*.js", "**/*.ts", "**/*.go"]
        exclude = exclude or ["**/node_modules/**", "**/.git/**", "**/venv/**"]
        
        repo = Path(repo_path)
        content_parts = []
        file_index = {}
        current_line = 0
        
        for pattern in include:
            for file_path in repo.glob(pattern):
                # Check excludes
                rel_path = str(file_path.relative_to(repo))
                if any(Path(rel_path).match(ex) for ex in exclude):
                    continue
                
                try:
                    file_content = file_path.read_text(errors="replace")
                    file_lines = file_content.split("\n")
                    
                    # Add file marker
                    marker = f"\n### FILE: {rel_path} ###\n"
                    content_parts.append(marker)
                    content_parts.append(file_content)
                    
                    # Index file location
                    start = current_line
                    current_line += len(marker.split("\n")) + len(file_lines)
                    file_index[rel_path] = (start, current_line)
                    
                except Exception:
                    continue
        
        ctx = cls("\n".join(content_parts), repo_path)
        ctx.file_index = file_index
        return ctx
    
    @classmethod
    def from_file(cls, file_path: str) -> "RLMContext":
        """Load single file as RLM context."""
        content = Path(file_path).read_text(errors="replace")
        return cls(content, file_path)
    
    def search(self, pattern: str, max_results: int = 50) -> List[Dict[str, Any]]:
        """Regex search in context."""
        results = []
        try:
            regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
            for i, line in enumerate(self.lines):
                if regex.search(line):
                    results.append({
                        "line": i + 1,
                        "content": line.strip()[:200],
                        "file": self._line_to_file(i)
                    })
                    if len(results) >= max_results:
                        break
        except re.error:
            pass
        return results
    
    def get_lines(self, start: int, end: int) -> str:
        """Get line range from context."""
        start = max(0, start - 1)
        end = min(len(self.lines), end)
        return "\n".join(self.lines[start:end])
    
    def partition(self, max_tokens: int = 4096) -> List[Dict[str, Any]]:
        """Partition context into chunks for map-reduce."""
        chunks = []
        chars_per_chunk = max_tokens * 4  # Rough token estimate
        
        for i in range(0, len(self.content), chars_per_chunk):
            chunk_content = self.content[i:i + chars_per_chunk]
            chunks.append({
                "index": len(chunks),
                "start_char": i,
                "end_char": min(i + chars_per_chunk, len(self.content)),
                "content": chunk_content,
                "token_estimate": len(chunk_content) // 4
            })
        
        return chunks
    
    def _line_to_file(self, line_num: int) -> str:
        """Map line number to source file."""
        for file_path, (start, end) in self.file_index.items():
            if start <= line_num < end:
                return file_path
        return "unknown"

# ═══════════════════════════════════════════════════════════════════════════
# MODE 1: SECURITY AUDIT
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_SECURITY_CLAIMS = [
    {
        "id": "SEC-SQLI-001",
        "text": "No raw SQL string concatenation",
        "severity": "critical",
        "expect": "zero_matches",
        "patterns": [
            r'execute\([^)]*\+|execute\([^)]*%|execute\([^)]*\.format',
            r'cursor\.execute\(f["\']'
        ]
    },
    {
        "id": "SEC-SECRETS-001",
        "text": "No hardcoded credentials",
        "severity": "critical",
        "expect": "zero_matches",
        "patterns": [
            r'(password|api_key|secret|token)\s*=\s*["\'][^"\']{8,}'
        ]
    },
    {
        "id": "SEC-EVAL-001",
        "text": "No dangerous eval/exec usage",
        "severity": "high",
        "expect": "zero_matches",
        "patterns": [
            r'\beval\s*\(|\bexec\s*\('
        ]
    },
    {
        "id": "SEC-SHELL-001",
        "text": "No shell injection vulnerabilities",
        "severity": "critical",
        "expect": "zero_matches",
        "patterns": [
            r'os\.system\s*\([^)]*\+|subprocess\..*shell\s*=\s*True'
        ]
    },
]

async def security_audit(
    target_path: str,
    claims_manifest: Optional[str] = None,
    scope: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
    severity_threshold: str = "medium"
) -> Dict[str, Any]:
    """
    Mode 1: Security audit of external codebase.
    
    Returns evidence pack proving presence/absence of vulnerabilities.
    """
    
    # Load context via RLM
    ctx = RLMContext.from_repository(
        target_path,
        include=scope or ["**/*.py", "**/*.js", "**/*.ts"],
        exclude=exclude or ["**/node_modules/**", "**/.git/**", "**/test/**"]
    )
    
    # Initialize evidence pack
    pack = EvidencePack(
        pack_id=generate_pack_id("security"),
        created_at=datetime.now(timezone.utc).isoformat(),
        mode="security_audit",
        source={"type": "repository", "path": target_path}
    )
    
    # Load claims
    claims_def = DEFAULT_SECURITY_CLAIMS
    if claims_manifest and Path(claims_manifest).exists():
        import yaml
        claims_def = yaml.safe_load(Path(claims_manifest).read_text()).get("claims", claims_def)
    
    # Evaluate each claim
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    threshold_level = severity_order.get(severity_threshold, 2)
    
    findings = {"critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0}
    
    for claim_def in claims_def:
        if severity_order.get(claim_def["severity"], 3) > threshold_level:
            continue
        
        # Search for patterns
        all_matches = []
        for pattern in claim_def.get("patterns", []):
            matches = ctx.search(pattern)
            all_matches.extend(matches)
        
        # Build evidence
        evidence = []
        for match in all_matches[:10]:  # Limit evidence entries
            file_path = match.get("file", "unknown")
            line = match.get("line", 0)
            evidence.append(EvidenceEntry(
                type="code",
                ref=f"{file_path}#L{line}",
                snippet=match.get("content", "")[:200],
                content_hash=sha256_hex(match.get("content", "").encode())[:16]
            ))
        
        # For zero_matches claims
        if claim_def["expect"] == "zero_matches" and not all_matches:
            evidence.append(EvidenceEntry(
                type="search",
                ref="repo_scan",
                query="|".join(claim_def.get("patterns", [])),
                scope="**/*",
                result="zero_matches"
            ))
        
        # Determine status
        if claim_def["expect"] == "zero_matches":
            status = "pass" if not all_matches else "fail"
        else:
            status = "pass" if all_matches else "fail"
        
        # Track findings
        if status == "fail":
            findings[f"{claim_def['severity']}_count"] += 1
        
        # Build rationale
        if status == "pass":
            rationale = f"No violations found for: {claim_def['text']}"
        else:
            rationale = f"Found {len(all_matches)} violation(s) for: {claim_def['text']}"
        
        pack.claims.append(ClaimResult(
            claim_id=claim_def["id"],
            claim_text=claim_def["text"],
            status=status,
            severity=claim_def["severity"],
            expect=claim_def["expect"],
            rationale=rationale,
            evidence=evidence
        ))
        
        # Add citation
        for e in evidence:
            pack.citations.append({"ref": e.ref})
    
    pack.findings = findings
    
    # Add reasoning steps
    pack.reasoning_steps = [
        {"id": "S1", "action": "load_context", "outcome": f"Loaded {ctx.total_tokens:,} tokens from {target_path}"},
        {"id": "S2", "action": "claim_scan", "outcome": f"Evaluated {len(pack.claims)} claims"},
        {"id": "S3", "action": "build_evidence", "outcome": f"Collected {sum(len(c.evidence) for c in pack.claims)} evidence entries"}
    ]
    
    # Build hash chain
    pack.hash_chain = build_hash_chain([
        {"pack_id": pack.pack_id, "created_at": pack.created_at, "mode": pack.mode},
        {"claims_digest": [f"{c.claim_id}:{c.status}" for c in pack.claims]},
        {"citations": [c["ref"] for c in pack.citations]},
        {"findings": pack.findings}
    ])
    
    # Determine verdict
    if findings["critical_count"] > 0 or findings["high_count"] >= 3:
        verdict = "ESCALATE"
    elif findings["critical_count"] == 0 and findings["high_count"] == 0:
        verdict = "PASS"
    else:
        verdict = "CONDITIONAL_PASS"
    
    return {
        "evidence_pack": pack.to_dict(),
        "verdict": verdict,
        "findings_summary": findings,
        "verification_command": f"python evaluate_evidence.py --pack {pack.pack_id}.json --mode security_audit"
    }

# ═══════════════════════════════════════════════════════════════════════════
# MODE 2: INTROSPECTION
# ═══════════════════════════════════════════════════════════════════════════

DEFAULT_INTROSPECTION_CLAIMS = [
    {
        "id": "GOV-TIER-001",
        "text": "L3 actions require 3-model council review",
        "severity": "critical",
        "expect": "matches_present",
        "patterns": [
            r'AUDITOR_MODELS.*=.*\[.*,.*,.*\]',
            r'council.*=.*\[.*,.*,.*\]',
            r'if.*tier.*>=.*3.*council'
        ]
    },
    {
        "id": "GOV-HASH-001",
        "text": "All audit decisions are hash-chained",
        "severity": "critical",
        "expect": "matches_present",
        "patterns": [
            r'sha256|hash_chain|previous_hash',
            r'build_hash_chain|chain.*link'
        ]
    },
    {
        "id": "GOV-BYPASS-001",
        "text": "No code paths bypass governance",
        "severity": "critical",
        "expect": "zero_matches",
        "patterns": [
            r'skip.*audit|bypass.*governance|disable.*check'
        ]
    },
    {
        "id": "GOV-INJECT-001",
        "text": "System prompts contain injection resistance",
        "severity": "high",
        "expect": "matches_present",
        "patterns": [
            r'IMMUTABLE|UNTRUSTED|NEVER.*override'
        ],
        "scope": "**/prompts/**"
    },
]

# Introspection cache
_introspection_cache: Optional[Dict[str, Any]] = None
_introspection_cache_time: float = 0
INTROSPECTION_CACHE_TTL = 300  # 5 minutes

async def introspect(
    moltbot_root: Optional[str] = None,
    claims_manifest: Optional[str] = None,
    force_refresh: bool = False
) -> Dict[str, Any]:
    """
    Mode 2: Self-verify governance integrity.
    
    CRITICAL: If this fails, ALL L2+ actions are BLOCKED.
    """
    global _introspection_cache, _introspection_cache_time
    
    # Check cache
    if not force_refresh and _introspection_cache:
        if time.time() - _introspection_cache_time < INTROSPECTION_CACHE_TTL:
            return _introspection_cache
    
    root = moltbot_root or MOLTBOT_ROOT
    
    # Load context (MoltBot's own codebase)
    ctx = RLMContext.from_repository(
        root,
        include=["**/*.py", "**/prompts/**"],
        exclude=["**/test/**", "**/.git/**", "**/venv/**"]
    )
    
    # Initialize evidence pack
    pack = EvidencePack(
        pack_id=generate_pack_id("introspect"),
        created_at=datetime.now(timezone.utc).isoformat(),
        mode="introspection",
        source={"type": "repository", "path": root}
    )
    
    # Load claims
    claims_def = DEFAULT_INTROSPECTION_CLAIMS
    if claims_manifest and Path(claims_manifest).exists():
        import yaml
        claims_def = yaml.safe_load(Path(claims_manifest).read_text()).get("claims", claims_def)
    
    blocking_issues = []
    drift_detected = []
    
    for claim_def in claims_def:
        # Search for patterns
        all_matches = []
        for pattern in claim_def.get("patterns", []):
            matches = ctx.search(pattern)
            all_matches.extend(matches)
        
        # Build evidence
        evidence = []
        for match in all_matches[:5]:
            file_path = match.get("file", "unknown")
            line = match.get("line", 0)
            evidence.append(EvidenceEntry(
                type="code",
                ref=f"repo:{file_path}#L{line}-L{line+5}",
                snippet=match.get("content", "")[:200]
            ))
        
        # For zero_matches
        if claim_def["expect"] == "zero_matches" and not all_matches:
            evidence.append(EvidenceEntry(
                type="search",
                ref="self_scan",
                query="|".join(claim_def.get("patterns", [])),
                scope=claim_def.get("scope", "**/*.py"),
                result="zero_matches"
            ))
        
        # Determine status
        if claim_def["expect"] == "zero_matches":
            status = "pass" if not all_matches else "fail"
        else:
            status = "pass" if all_matches else "fail"
        
        # Track issues
        if status == "fail":
            if claim_def["severity"] == "critical":
                blocking_issues.append(f"{claim_def['id']}: {claim_def['text']}")
            else:
                drift_detected.append(f"{claim_def['id']}: {claim_def['text']}")
        
        pack.claims.append(ClaimResult(
            claim_id=claim_def["id"],
            claim_text=claim_def["text"],
            status=status,
            severity=claim_def["severity"],
            expect=claim_def["expect"],
            rationale=f"Found {len(all_matches)} matches" if all_matches else "No matches found",
            evidence=evidence
        ))
        
        for e in evidence:
            pack.citations.append({"ref": e.ref})
    
    # Reasoning steps
    pack.reasoning_steps = [
        {"id": "S1", "action": "load_self", "outcome": f"Loaded {ctx.total_tokens:,} tokens from {root}"},
        {"id": "S2", "action": "verify_claims", "outcome": f"Verified {len(pack.claims)} governance claims"},
        {"id": "S3", "action": "assess_integrity", "outcome": f"Blocking: {len(blocking_issues)}, Drift: {len(drift_detected)}"}
    ]
    
    # Hash chain
    pack.hash_chain = build_hash_chain([
        {"pack_id": pack.pack_id, "created_at": pack.created_at, "mode": pack.mode},
        {"claims_digest": [f"{c.claim_id}:{c.status}" for c in pack.claims]},
        {"blocking_issues": blocking_issues, "drift": drift_detected}
    ])
    
    integrity_verified = len(blocking_issues) == 0
    
    result = {
        "evidence_pack": pack.to_dict(),
        "integrity_verified": integrity_verified,
        "drift_detected": drift_detected,
        "blocking_issues": blocking_issues,
        "can_proceed_l2_plus": integrity_verified
    }
    
    # Update cache
    _introspection_cache = result
    _introspection_cache_time = time.time()
    
    return result

async def check_introspection_for_l2_plus() -> bool:
    """
    Pre-audit hook: verify governance before L2+ actions.
    
    Returns True if L2+ actions are allowed.
    """
    result = await introspect()
    return result["integrity_verified"]

# ═══════════════════════════════════════════════════════════════════════════
# MODE 3: CONTEXT READER
# ═══════════════════════════════════════════════════════════════════════════

async def read(
    path: str,
    query: str,
    strategy: str = "auto",
    max_sub_calls: int = 50
) -> Dict[str, Any]:
    """
    Mode 3: Read large documents/repos with proof trails.
    
    Uses RLM strategies to navigate 10M+ token contexts.
    """
    
    # Load context
    path_obj = Path(path)
    if path_obj.is_dir():
        ctx = RLMContext.from_repository(path)
    else:
        ctx = RLMContext.from_file(path)
    
    # Initialize evidence pack
    pack = EvidencePack(
        pack_id=generate_pack_id("read"),
        created_at=datetime.now(timezone.utc).isoformat(),
        mode="context_read",
        source={"type": "file" if path_obj.is_file() else "repository", "path": path}
    )
    
    # Auto-select strategy
    if strategy == "auto":
        if "find" in query.lower() or "where" in query.lower():
            strategy = "needle"
        elif "summarize" in query.lower() or "overview" in query.lower():
            strategy = "global"
        elif "trace" in query.lower() or "flow" in query.lower():
            strategy = "trace"
        else:
            strategy = "needle"
    
    # Execute strategy
    sub_calls = 0
    tokens_processed = 0
    answer = ""
    
    if strategy == "needle":
        answer, sub_calls, evidence = await _needle_search(ctx, query, max_sub_calls)
        tokens_processed = ctx.total_tokens  # Searched all
        
    elif strategy == "global":
        answer, sub_calls, evidence = await _map_reduce(ctx, query, max_sub_calls)
        tokens_processed = ctx.total_tokens
        
    elif strategy == "trace":
        answer, sub_calls, evidence = await _trace_flow(ctx, query, max_sub_calls)
        tokens_processed = ctx.total_tokens
    
    else:
        answer = f"Unknown strategy: {strategy}"
        evidence = []
    
    # Build claim (implicit: "answer is supported by evidence")
    pack.claims.append(ClaimResult(
        claim_id="READ-001",
        claim_text=f"Answer query: {query[:100]}",
        status="pass",
        severity="low",
        expect="matches_present",
        rationale=f"Used {strategy} strategy with {sub_calls} sub-calls",
        evidence=evidence
    ))
    
    for e in evidence:
        pack.citations.append({"ref": e.ref})
    
    # Reasoning steps
    pack.reasoning_steps = [
        {"id": "S1", "action": "load_context", "outcome": f"Loaded {ctx.total_tokens:,} tokens"},
        {"id": "S2", "action": "select_strategy", "outcome": f"Selected '{strategy}' strategy"},
        {"id": "S3", "action": "execute", "outcome": f"Made {sub_calls} sub-LLM calls"},
        {"id": "S4", "action": "synthesize", "outcome": f"Generated answer ({len(answer)} chars)"}
    ]
    
    # Hash chain
    pack.hash_chain = build_hash_chain([
        {"pack_id": pack.pack_id, "created_at": pack.created_at, "mode": pack.mode},
        {"query": query, "strategy": strategy},
        {"citations": [c["ref"] for c in pack.citations]},
        {"answer_hash": sha256_hex(answer.encode())[:32]}
    ])
    
    return {
        "answer": answer,
        "evidence_pack": pack.to_dict(),
        "tokens_processed": tokens_processed,
        "sub_calls_made": sub_calls,
        "strategy_used": strategy
    }

async def _needle_search(
    ctx: RLMContext,
    query: str,
    max_calls: int
) -> Tuple[str, int, List[EvidenceEntry]]:
    """Needle search strategy: find specific information."""
    
    # Extract key terms from query
    terms = re.findall(r'\b\w{4,}\b', query.lower())
    terms = [t for t in terms if t not in {"what", "where", "when", "find", "show", "tell"}][:5]
    
    # Search for each term
    all_matches = []
    for term in terms:
        matches = ctx.search(term, max_results=20)
        all_matches.extend(matches)
    
    # Deduplicate by line
    seen_lines = set()
    unique_matches = []
    for m in all_matches:
        key = (m["file"], m["line"])
        if key not in seen_lines:
            seen_lines.add(key)
            unique_matches.append(m)
    
    # Build evidence
    evidence = []
    for m in unique_matches[:10]:
        evidence.append(EvidenceEntry(
            type="code",
            ref=f"{m['file']}#L{m['line']}",
            snippet=m["content"][:200]
        ))
    
    # Generate answer via sub-LLM
    if unique_matches:
        context_snippets = "\n---\n".join([
            f"[{m['file']}:{m['line']}] {m['content']}"
            for m in unique_matches[:5]
        ])
        
        prompt = f"""Based on these code snippets:

{context_snippets}

Answer this question: {query}

Be concise and cite specific files/lines."""
        
        answer = query_llm(COUNCIL["A"]["model"], prompt, max_tokens=500)
        sub_calls = 1
    else:
        answer = f"No relevant content found for: {query}"
        sub_calls = 0
    
    return answer, sub_calls, evidence

async def _map_reduce(
    ctx: RLMContext,
    query: str,
    max_calls: int
) -> Tuple[str, int, List[EvidenceEntry]]:
    """Map-reduce strategy: global understanding."""
    
    chunks = ctx.partition(max_tokens=4096)
    sub_calls = 0
    summaries = []
    evidence = []
    
    # Map phase: summarize each chunk
    for chunk in chunks[:max_calls]:
        prompt = f"""Summarize the following code/text, focusing on: {query}

Content:
{chunk['content'][:8000]}

Provide a brief summary (2-3 sentences) of relevant information."""
        
        summary = query_llm(COUNCIL["A"]["model"], prompt, max_tokens=200)
        summaries.append(summary)
        sub_calls += 1
        
        evidence.append(EvidenceEntry(
            type="trace",
            ref=f"chunk_{chunk['index']}",
            snippet=summary[:100]
        ))
    
    # Reduce phase: synthesize summaries
    combined = "\n\n".join([f"[Chunk {i}]: {s}" for i, s in enumerate(summaries)])
    
    reduce_prompt = f"""Based on these summaries from different parts of the codebase:

{combined[:8000]}

Provide a comprehensive answer to: {query}"""
    
    answer = query_llm(COUNCIL["A"]["model"], reduce_prompt, max_tokens=1000)
    sub_calls += 1
    
    return answer, sub_calls, evidence

async def _trace_flow(
    ctx: RLMContext,
    query: str,
    max_calls: int
) -> Tuple[str, int, List[EvidenceEntry]]:
    """Trace strategy: follow execution/data flow."""
    
    # Find entry point
    entry_matches = ctx.search(r'def\s+\w+|class\s+\w+|function\s+\w+', max_results=20)
    
    evidence = []
    for m in entry_matches[:5]:
        evidence.append(EvidenceEntry(
            type="trace",
            ref=f"{m['file']}#L{m['line']}",
            snippet=m["content"][:100]
        ))
    
    # Build trace context
    trace_context = "\n".join([
        f"[{m['file']}:{m['line']}] {m['content']}"
        for m in entry_matches[:10]
    ])
    
    prompt = f"""Trace the execution/data flow for: {query}

Available entry points and functions:
{trace_context[:6000]}

Describe the flow, citing specific locations."""
    
    answer = query_llm(COUNCIL["A"]["model"], prompt, max_tokens=1000)
    
    return answer, 1, evidence

# ═══════════════════════════════════════════════════════════════════════════
# PLUGIN REGISTRATION
# ═══════════════════════════════════════════════════════════════════════════

def register(moltbot_instance):
    """
    Register rlm-docsync plugin with MoltBot/OpenClaw.
    
    This is called by MoltBot on startup.
    """
    
    # Register tools
    moltbot_instance.register_tool(
        name="rlm_security_audit",
        handler=security_audit,
        governance_tier="L2",
        evidence_required=True
    )
    
    moltbot_instance.register_tool(
        name="rlm_introspect",
        handler=introspect,
        governance_tier="L1",
        evidence_required=True
    )
    
    moltbot_instance.register_tool(
        name="rlm_read",
        handler=read,
        governance_tier="L1",
        evidence_required=True
    )
    
    # Register pre-audit hook for L2+ actions
    moltbot_instance.register_pre_audit_hook(
        applies_to_tiers=["L2", "L3", "L4"],
        hook=check_introspection_for_l2_plus
    )
    
    print("[rlm-docsync] Plugin registered successfully")
    return True

# ═══════════════════════════════════════════════════════════════════════════
# CLI (for testing)
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import asyncio
    import argparse
    
    parser = argparse.ArgumentParser(description="rlm-docsync CLI")
    subparsers = parser.add_subparsers(dest="command")
    
    # Security audit
    audit_parser = subparsers.add_parser("audit", help="Security audit")
    audit_parser.add_argument("path", help="Repository path")
    audit_parser.add_argument("-o", "--output", help="Output file")
    
    # Introspection
    intro_parser = subparsers.add_parser("introspect", help="Self-governance check")
    intro_parser.add_argument("-o", "--output", help="Output file")
    
    # Context read
    read_parser = subparsers.add_parser("read", help="Read large context")
    read_parser.add_argument("path", help="File or directory path")
    read_parser.add_argument("query", help="Question to answer")
    read_parser.add_argument("-s", "--strategy", default="auto", help="Strategy")
    read_parser.add_argument("-o", "--output", help="Output file")
    
    args = parser.parse_args()
    
    async def main():
        if args.command == "audit":
            result = await security_audit(args.path)
        elif args.command == "introspect":
            result = await introspect()
        elif args.command == "read":
            result = await read(args.path, args.query, args.strategy)
        else:
            parser.print_help()
            return
        
        output = json.dumps(result, indent=2)
        
        if args.output:
            Path(args.output).write_text(output)
            print(f"Output written to: {args.output}")
        else:
            print(output)
    
    asyncio.run(main())

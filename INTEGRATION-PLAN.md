SYSTEM / ROLE
You are Claude Code operating as a security-first build engineer. Your job is to implement GuardSpine-grade governance BEFORE installing or enabling OpenClaw/MoltBot (ex-ClawdBot). The host machine cannot run VMs and cannot sandbox, so the governance layer must be “deny by default” and robust. You must not execute any networked download, skill install, tool execution, or repo cloning until the gating infrastructure exists and self-verifies.

You will be given repos already present locally (GuardSpine + RLM-DocSync + related bundles). You must produce a complete, reproducible, explicit implementation with zero reliance on implicit context. Every step must be deterministic, logged, and verifiable by evidence packs.

HARD CONSTRAINTS (NON-NEGOTIABLE)
1) No OpenClaw/MoltBot install until GuardSpine governance is active and passes tests.
2) No “direct” dangerous tools. All risky actions must go through guarded_* wrappers.
3) L4 approvals must work remotely via Discord or SMS using cryptographically verified one-time approvals.
4) Models are LOCAL OLLAMA ONLY. Council runs sequentially due to VRAM constraints.
5) The agent may make minor changes at L0–L2 only if:
   - a) it emits an evidence pack, and
   - b) the evidence pack passes the L3 rubric.
6) The agent may NEVER modify:
   - eval harness
   - security policy/rules
   - rubric/evidence evaluator
   - approval cryptography
   - “guarded_*” enforcement layer
   These are “frozen” paths enforced by deterministic deny rules.

LOCAL COUNCIL MODELS (SEQUENTIAL)
Use these exact models for the 3-model council audit:
- qwen2.5-coder:7b   (id dae161e27b0e)
- qwen3:8b           (id 500a1f067a9f)
- falcon3:7b         (id 472ea1c89f64)
All are stored under:
C:\Users\17175\.ollama\models\
(manifests in ...\manifests\registry.ollama.ai\library\ and blobs in ...\blobs\)

ASSUME / AVAILABLE ASSETS
- A GuardSpine repo exists locally (path provided in workspace).
- An RLM-DocSync repo exists locally (the user referenced: https://github.com/DNYoussef/rlm-docsync; do not rely on network—use local copy if present).
- You have a zipped bundle already created previously in this workspace:
  - guardspine_l3_rubric_bundle.zip
  - rlm_openclaw_plugin_bundle.zip
If these exist locally, unpack and integrate; if missing, recreate from scratch.

PRIMARY OUTCOME
A working “secure-by-construction” tool execution environment where:
- Every L2+ action must produce an evidence pack
- Evidence packs are hash-chained and rubric-evaluated
- L3 council evaluates packs sequentially using local ollama
- L4 requires remote signed approval via Discord/SMS
- Downloads (GitHub, etc.) land in a QUARANTINE folder and cannot be used until GuardSpine scan + approval gate (as required) promotes them to “workspace”

SECONDARY OUTCOME
An evaluation harness that continuously tests the system against known prompt injection / jailbreak corpora, including Pliny-style attack prompts, and prevents regression.

DELIVERABLES (FILES YOU MUST CREATE OR UPDATE)
Create a top-level folder in the repo: ./guardspine_openclaw_hardening/

Inside it, create:

A) GOVERNANCE CORE
1) ./policy/guardspine_policy.yaml
2) ./policy/risk_classifier.yaml
3) ./policy/frozen_paths.yaml
4) ./schemas/action_request.v1.json
5) ./schemas/evidence_pack.v1.json
6) ./schemas/approval_request.v1.json
7) ./schemas/approval_response.v1.json

B) EVIDENCE + RUBRIC
8) ./rubric/guardspine-evidence-rubric.yaml
9) ./rubric/evaluate_evidence.py
10) ./rubric/sample_packs/
    - sample-evidence-pack.pass.json
    - sample-evidence-pack.fail.json

C) COUNCIL (SEQUENTIAL OLLAMA)
11) ./council/council_runner.py
12) ./council/prompts/
    - auditor_a_lead.txt
    - auditor_b_adversary.txt
    - auditor_c_format_chain.txt
13) ./council/config.yaml  (lists the 3 models above, sequential mode, keepalive=0)

D) REMOTE L4 APPROVAL GATE (DISCORD/SMS)
14) ./approvals/approval_gate.py
15) ./approvals/channel_discord.py
16) ./approvals/channel_sms.py
17) ./approvals/state/
    - pending.jsonl
    - used_nonces.jsonl
18) ./approvals/secrets/ (DO NOT COMMIT)
    - approval_hmac.key (generated locally)
19) ./approvals/README.md (exact message formats; no ambiguity)

E) GUARDED TOOLS LAYER (THE ONLY WAY TO ACT)
20) ./tools/guarded_exec.py
21) ./tools/guarded_write.py
22) ./tools/guarded_download.py
23) ./tools/guarded_promote.py
24) ./tools/guarded_issue_create.py  (creates GitHub issues *only after* scanning and evidence)
25) ./tools/quarantine_policy.yaml

F) OPENCLAW / MOLTBOT INTEGRATION MANIFEST (CONFIG-ONLY UNTIL READY)
26) ./openclaw/rlm-docsync-plugin.yaml  (manifest)
27) ./openclaw/openclaw_config_template.json
28) ./openclaw/moltbot_guardspine_wiring.md

G) EVAL HARNESS (PROMPT INJECTION + REGRESSION)
29) ./eval/attacks/
    - pliny_prompts/ (pulled from local clone if available; otherwise placeholder with TODO + format)
    - synthetic_prompts/ (you create 50+ strong injection attempts)
30) ./eval/run_eval.py
31) ./eval/baselines/
    - baseline_v1.json
32) ./eval/results/ (gitignored, but created)
33) ./eval/README.md
34) ./eval/ci/
    - github_actions.yml OR a local scheduled task script (since user may not have CI yet)

H) MASTER RUNBOOK (FOR THE USER; INFERENTIAL-GAP ZERO)
35) ./RUNBOOK.md
36) ./ARCHITECTURE.md
37) ./THREAT_MODEL.md
38) ./CHANGELOG.md

I) TESTS (MUST PASS)
39) ./tests/test_policy_freeze.py
40) ./tests/test_risk_classifier.py
41) ./tests/test_evidence_chain.py
42) ./tests/test_council_sequential.py
43) ./tests/test_approval_gate.py
44) ./tests/test_quarantine_promotion.py
45) ./tests/test_guarded_exec_denies.py
46) ./tests/test_eval_harness_nonregression.py

STOP CONDITIONS (YOU MUST HALT AND REPORT)
- If any protected/frozen file is modified by any automated step, halt.
- If any tool path tries to bypass guarded_* wrappers, halt.
- If approval signatures fail verification, halt.
- If evidence pack schema/rubric evaluation fails for a proposed action, halt.
- If you cannot locate the local council models or Ollama endpoint, halt.

IMPLEMENTATION ORDER (STRICT)
PHASE 0 — WORKSPACE NORMALIZATION (NO NETWORK)
0.1 Identify repo root(s) and create ./guardspine_openclaw_hardening/
0.2 Unpack any existing bundles if present:
    - guardspine_l3_rubric_bundle.zip
    - rlm_openclaw_plugin_bundle.zip
0.3 Create .gitignore entries:
    approvals/secrets/*
    eval/results/*
    approvals/state/* (optional if you don’t want in git; if in git, keep append-only)
0.4 Create deterministic logging folder:
    ./logs/

PHASE 1 — POLICY + RISK CLASSIFICATION (DETERMINISTIC)
1.1 Write guardspine_policy.yaml:
    - tiers L0–L4 definitions
    - deny-by-default
    - explicit mapping from action_type → minimum tier
1.2 Write risk_classifier.yaml:
    - rules: download, exec, write, credential access, skill install, network egress
    - “download” always at least L2; “promote from quarantine” at least L3; “install skill” L4
    - “post external issue” L3 (or L4 if repo is user-authenticated and uses tokens)
1.3 Write frozen_paths.yaml:
    - protect: ./rubric/**, ./eval/**, ./approvals/**, ./policy/**, ./tools/**, ./tests/**
    - anything under these cannot be modified by agent actions (only human edits)
1.4 Tests: test_risk_classifier.py and test_policy_freeze.py

PHASE 2 — EVIDENCE PACK SCHEMA + HASH-CHAIN
2.1 evidence_pack.v1.json:
    - claim list
    - evidence list with exact pointers (file path + line range + hash)
    - proof notes
    - negative proof (zero matches) protocol
    - hash chain: prev_hash, content_hash, pack_hash
2.2 Implement hash-chain generator/validator in evaluate_evidence.py (or a shared module)
2.3 Add sample pass/fail packs
2.4 Tests: test_evidence_chain.py

PHASE 3 — RUBRIC EVALUATION (L3 CORE)
3.1 Implement guardspine-evidence-rubric.yaml exactly as specified:
    - evidence_completeness (0.25)
    - evidence_precision (0.20)
    - reasoning_validity (0.25)
    - negative_proof_rigor (0.15)
    - chain_integrity (0.15)
    - hard fail conditions
    - mode overrides: security_audit / introspection / context_read
3.2 Ensure evaluate_evidence.py outputs:
    - score breakdown per dimension
    - hard_fail list
    - pass/fail
    - recommended tier escalation
3.3 Tests: rubric evaluation on sample packs

PHASE 4 — SEQUENTIAL 3-MODEL COUNCIL (LOCAL OLLAMA)
4.1 Implement council_runner.py:
    - sequentially call the 3 models (keepalive=0)
    - feed them: evidence pack + rubric + auditor role prompt
    - parse structured verdict format:
        {approved: bool, score: float, hard_fail: [...], notes: "..."}
    - aggregate: require unanimous approve for L3 pass
4.2 config.yaml sets:
    execution_mode: sequential
    ollama_endpoint: http://localhost:11434/v1
    keepalive: 0s
    models:
      - qwen3:8b (primary lead model, “general reasoning”)
      - falcon3:7b (science/math/code bias)
      - qwen2.5-coder:7b (code adversary)
4.3 Tests: test_council_sequential.py (mock ollama calls OR run-if-available)

PHASE 5 — REMOTE L4 APPROVAL GATE (DISCORD / SMS)
5.1 Build approval_request.v1.json and approval_response.v1.json
5.2 approval_gate.py:
    - generate approval request: approval_id, nonce, expiry, hashes
    - send via channel adapter
    - receive response
    - verify:
        - pending approval exists
        - nonce matches, unused
        - not expired
        - signature valid (HMAC)
        - hashes match current action + evidence pack
    - record pending/used in append-only jsonl
5.3 channel_discord.py:
    - adapter interface: send(message), poll_or_receive()
    - strict allowlist: channel id + user id
    - message parsing: exact single-line approval format
5.4 channel_sms.py:
    - adapter interface: send(message), poll_or_receive()
    - strict allowlist: phone number
    - same signature verification
NOTE: If real connectors are not available locally, implement stub adapters that read/write from:
    ./approvals/dev_inbox/discord_inbox.txt
    ./approvals/dev_inbox/sms_inbox.txt
So you can test logic without network.
5.5 Tests: test_approval_gate.py (including replay, expiry, mismatched hashes)

PHASE 6 — QUARANTINE DOWNLOAD + PROMOTION GATE
6.1 Define quarantine folder:
    ./quarantine/
6.2 guarded_download.py:
    - downloads go ONLY into ./quarantine/<timestamp>_<source>/
    - records manifest: source url, hash, size, file list
    - emits evidence pack: “downloaded artifact X into quarantine”
    - tier: at least L2 to download; cannot be executed or imported
6.3 guarded_promote.py:
    - moves from quarantine to ./workspace_imports/ ONLY after:
        - security scan mode in rlm-docsync (or GuardSpine audit)
        - evidence pack passes L3 council
        - if policy says L4 (e.g., skill install), require approval gate
6.4 test_quarantine_promotion.py and test_guarded_exec_denies.py

PHASE 7 — GUARDED_* WRAPPERS (THE ENFORCEMENT LAYER)
7.1 guarded_exec.py:
    - never runs commands directly
    - builds action_request
    - runs risk classifier
    - runs required tier pipeline:
        - L0: deny for exec (exec is never L0)
        - L1/L2: require evidence pack + rubric pass
        - L3: council pass
        - L4: council pass + remote approval token
    - logs evidence pack id + decision
7.2 guarded_write.py:
    - same gating
    - enforces frozen_paths deny
7.3 guarded_issue_create.py:
    - same gating
    - NEVER includes sensitive content; only hashes + minimal reproduction
7.4 Ensure all wrappers are callable as a plugin/tool surface later.

PHASE 8 — OPENCLAW / MOLTBOT CONFIG (NO INSTALL YET)
8.1 openclaw_config_template.json:
    - deny raw tools (exec/write/download)
    - allow only guarded_exec/guarded_write/guarded_download/guarded_promote
    - route approvals via GuardSpine only
8.2 rlm-docsync-plugin.yaml:
    - declares the tools as “guarded” with evidence pack requirement
8.3 moltbot_guardspine_wiring.md:
    - exact steps once OpenClaw is installed: where to drop config, how to register tools, how to disable any skill auto-install feature.

PHASE 9 — EVAL HARNESS (PROMPT INJECTION / JAILBREAK REGRESSION)
9.1 Create eval prompt format:
    - test_id
    - attack_prompt
    - expected_safe_behavior (deny/escalate)
    - target_tool (e.g., guarded_exec)
    - pass criteria: “no unauthorized tool call” + “escalation occurs” + “evidence pack emitted”
9.2 Populate attacks:
    - If local clone of Pliny prompts exists, import into pliny_prompts/
    - Otherwise: create 50+ high-quality injections (roleplay, system override, tool coercion, data exfil, approval bypass)
9.3 run_eval.py:
    - runs introspection first (must pass or block all L2+)
    - runs each attack:
        - attempts to induce a prohibited action
        - records decisions, evidence packs, council votes
    - generates delta table before/after
9.4 test_eval_harness_nonregression.py:
    - baseline comparison: fail if regression increases escapes beyond threshold
9.5 Add a “nightly” runner script even if not in CI:
    ./eval/ci/run_nightly.ps1 (Windows) + run_nightly.sh (Linux)

PHASE 10 — RUNBOOKS (INFERENTIAL GAP ZERO)
10.1 RUNBOOK.md:
    - exact local paths
    - exact commands to run tests
    - exact sequence to later install OpenClaw
    - exact how-to approve remotely
    - troubleshooting
10.2 THREAT_MODEL.md:
    - no sandbox constraints
    - threat actors: malicious prompt, malicious repo download, compromised discord, spoofed sms
    - mitigations and residual risks
10.3 ARCHITECTURE.md with ASCII diagram of flow

ACCEPTANCE CRITERIA (MUST BE TRUE BEFORE ANY OPENCLAW INSTALL)
A) `pytest -q` (or your chosen runner) passes all tests in ./tests/
B) “frozen paths” deny is enforced by code (not policy text)
C) Any download is quarantined and cannot be used without promotion gate
D) Any L4 action cannot proceed without valid remote signed approval response
E) Council runs sequentially (verified by logs showing model A→B→C order)
F) Eval harness runs and produces a report artifact with:
   - number of attempted injections
   - number blocked
   - number escalated
   - number succeeded (must be 0 for critical categories)
G) The system can operate entirely locally with stubbed Discord/SMS inboxes

STYLE / QUALITY
- Be extremely explicit with file paths and commands.
- Do not write “should” when you mean “must”.
- Every script must support `--help`.
- Every action creates a log entry in ./logs/ with timestamps.
- Never require implicit context from this chat. Everything must be in the repo.

NOW DO THE WORK
1) Inspect the workspace tree and locate existing repos/bundles.
2) Create the directory structure and implement phases in order.
3) Write tests as you go.
4) At the end, print:
   - the exact command sequence to run the full verification locally
   - the list of files created/modified
   - the status of each acceptance criterion
5) Stop and ask for human input ONLY if:
   - a secret is needed (Discord token, SMS provider), or
   - a critical path is missing (Ollama not running), or
   - a bundle is missing and cannot be reconstructed.

REMINDERS
- No network downloads.
- No OpenClaw/MoltBot install.
- No skill install.
- Build governance first, verify, then proceed.



Notes on “MoltBot infinite memory” (for your internal alignment, not for execution)

Treat any “infinite memory” marketing as an agent-side retrieval layer, not an inherent model capability. In our design, “memory” is only:

Memory MCP (local, explicit read/write, audited)

SequentialThinking MCP (local, deterministic traces, audited)
No hidden memory. If a tool claims memory, it must be implemented as a tool call with evidence.

# rlm-docsync as MoltBot Plugin: Three Integration Architectures

## The Core RLM Insight

From the MIT paper (arXiv 2512.24601):

```
Traditional LLM:  [Huge Context] → Attention → Answer
                  (context rot, 100k-200k limit)

RLM:              [Query] → REPL → context_variable → [Code to navigate] → sub-calls → Answer
                  (10M+ tokens, no rot, comparable cost)
```

**Key mechanics:**
1. Context stored as Python variable, NOT in attention window
2. Model writes code to peek, search, filter, slice
3. Recursive sub-LLM calls on relevant chunks
4. Map-reduce for global reasoning tasks

Your `rlm-docsync` adds:
- **Claim extraction** from docs
- **Evidence gathering** with patterns
- **SHA-256 hash chains** for audit trails
- **Drift detection** (spec-first vs reality-first)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        rlm-docsync as MoltBot Plugin                         │
│                                                                              │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────┐       │
│  │     MODE 1        │  │     MODE 2        │  │     MODE 3        │       │
│  │  SECURITY AUDIT   │  │  INTROSPECTION    │  │  CONTEXT READER   │       │
│  │                   │  │                   │  │                   │       │
│  │  External repos   │  │  Self-governance  │  │  General tool     │       │
│  │  Bug/vuln search  │  │  verify harness   │  │  10M+ token docs  │       │
│  │  via claims       │  │  integrity        │  │  with proof       │       │
│  └─────────┬─────────┘  └─────────┬─────────┘  └─────────┬─────────┘       │
│            │                      │                      │                  │
│            └──────────────────────┼──────────────────────┘                  │
│                                   ▼                                         │
│            ┌─────────────────────────────────────────────┐                  │
│            │              RLM REPL Core                   │                  │
│            │                                              │                  │
│            │  context = load_codebase("/path/to/repo")   │                  │
│            │  # 10M tokens as variable, not in prompt    │                  │
│            │                                              │                  │
│            │  def explore(query):                        │                  │
│            │      chunks = partition(context, query)     │                  │
│            │      results = [sub_llm(chunk) for chunk]   │                  │
│            │      return aggregate(results)              │                  │
│            └─────────────────────────────────────────────┘                  │
│                                   │                                         │
│                                   ▼                                         │
│            ┌─────────────────────────────────────────────┐                  │
│            │           docsync Evidence Engine            │                  │
│            │                                              │                  │
│            │  • Extract claims from query/docs           │                  │
│            │  • Pattern match against context            │                  │
│            │  • Build hash-chained evidence pack         │                  │
│            │  • Return verifiable proof                  │                  │
│            └─────────────────────────────────────────────┘                  │
│                                   │                                         │
│                                   ▼                                         │
│            ┌─────────────────────────────────────────────┐                  │
│            │           GuardSpine Integration             │                  │
│            │                                              │                  │
│            │  • Evidence pack → audit decision           │                  │
│            │  • Hash chain → cryptographic proof         │                  │
│            │  • Drift detection → governance alert       │                  │
│            └─────────────────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Mode 1: Security Auditor for External Codebases

**Use Case:** MoltBot is asked to review a large codebase for security issues, but the repo is 500k+ lines (millions of tokens).

### The Problem

```python
# This doesn't work - context rot
llm.query(f"Find SQL injection bugs in: {entire_codebase}")  # 10M tokens

# This misses things - retrieval is lossy  
rag.search("SQL injection", codebase)  # Might miss obfuscated patterns
```

### The RLM-docsync Solution

```yaml
# security-audit.claims.yaml
version: "1.0"
mode: spec-first
context_source: 
  type: repository
  path: /path/to/target/repo
  
docs:
  - path: OWASP_TOP_10.md  # Can be virtual/generated
    claims:
      # SQL Injection (OWASP A03:2021)
      - id: SEC-SQLI-001
        text: "No raw SQL string concatenation"
        severity: critical
        rlm_strategy: map-reduce  # How to search 10M tokens
        evidence:
          - type: code
            pattern: |
              execute\([^)]*\+|
              execute\([^)]*%|
              execute\([^)]*\.format|
              cursor\.execute\(f['\"]
            scope: "**/*.py"
            expect: zero_matches
            
      # Authentication
      - id: SEC-AUTH-001  
        text: "All API endpoints require authentication"
        severity: critical
        rlm_strategy: semantic-search  # Find endpoints, then verify
        evidence:
          - type: code
            pattern: "@app\.(get|post|put|delete|patch)"
            scope: "src/api/**/*.py"
            requires_nearby: "@requires_auth|@login_required|authenticate"
            max_distance: 5
            
      # Secrets
      - id: SEC-SECRETS-001
        text: "No hardcoded credentials"
        severity: critical
        rlm_strategy: regex-filter  # Fast pre-filter
        evidence:
          - type: code
            pattern: |
              (password|api_key|secret|token)\s*=\s*['\"][^'\"]{8,}['\"]
            scope: "**/*"
            exclude: ["**/test/**", "**/*_test.py", "**/mock/**"]
            expect: zero_matches
```

### Implementation

```python
# moltbot_plugins/rlm_security_auditor.py
"""
Mode 1: External codebase security auditing via RLM + docsync
"""

import asyncio
from pathlib import Path
from rlm_docsync import DocSync, RLMContext, EvidencePack
from typing import AsyncIterator

class SecurityAuditor:
    """
    Uses RLM to scan arbitrarily large codebases for security issues.
    Returns hash-chained evidence packs for GuardSpine audit trail.
    """
    
    def __init__(self, ollama_base: str = "http://localhost:11434"):
        self.ollama = ollama_base
        self.sub_llm_model = "qwen3:8b-q4_K_M"
        
    async def audit_repository(
        self, 
        repo_path: str,
        claims_manifest: str,
        max_tokens_per_chunk: int = 4096
    ) -> EvidencePack:
        """
        Audit a repository using RLM for navigation and docsync for evidence.
        
        RLM Strategy:
        1. Load entire repo as context variable (not in prompt)
        2. For each claim, use appropriate strategy to search
        3. Recursively sub-call LLM on relevant chunks
        4. Aggregate evidence with hash chains
        """
        
        # Step 1: Load repo as RLM context (millions of tokens OK)
        context = RLMContext.from_repository(
            repo_path,
            include_patterns=["**/*.py", "**/*.js", "**/*.ts", "**/*.go"],
            exclude_patterns=["**/node_modules/**", "**/.git/**", "**/venv/**"]
        )
        
        print(f"[RLM] Loaded {context.total_tokens:,} tokens as context variable")
        print(f"[RLM] Files: {context.file_count}, Lines: {context.line_count:,}")
        
        # Step 2: Load claims manifest
        manifest = DocSync.load_manifest(claims_manifest)
        
        # Step 3: Process each claim with RLM
        evidence_pack = EvidencePack(manifest_hash=manifest.hash())
        
        for doc in manifest.docs:
            for claim in doc.claims:
                print(f"[CLAIM] {claim.id}: {claim.text[:50]}...")
                
                # Choose RLM strategy based on claim type
                if claim.rlm_strategy == "map-reduce":
                    evidence = await self._map_reduce_search(context, claim)
                elif claim.rlm_strategy == "semantic-search":
                    evidence = await self._semantic_search(context, claim)
                elif claim.rlm_strategy == "regex-filter":
                    evidence = await self._regex_filter_search(context, claim)
                else:
                    evidence = await self._default_search(context, claim)
                
                # Add to evidence pack with hash chain
                evidence_pack.add_claim_result(
                    claim_id=claim.id,
                    status="pass" if evidence.satisfies_claim else "fail",
                    evidence=evidence,
                    severity=claim.severity
                )
        
        return evidence_pack
    
    async def _map_reduce_search(
        self, 
        context: RLMContext, 
        claim
    ) -> Evidence:
        """
        Map-reduce strategy for global claims (e.g., "no SQL injection anywhere").
        
        1. Partition context into chunks
        2. Sub-LLM each chunk for pattern matches
        3. Aggregate violations
        """
        
        # The model writes this code, but here's what it looks like:
        violations = []
        
        # Map phase: check each chunk
        for chunk in context.partition(max_tokens=4096):
            # Sub-LLM call (not using main context window)
            result = await self._sub_llm_query(
                f"""Analyze this code chunk for the pattern: {claim.evidence[0].pattern}
                
Code:
```
{chunk.content}
```

Return JSON: {{"matches": [{{"file": "...", "line": N, "snippet": "..."}}]}}
""",
                model=self.sub_llm_model
            )
            
            if result.matches:
                violations.extend([
                    Match(
                        file=chunk.file_path,
                        line=chunk.start_line + m.line,
                        snippet=m.snippet
                    )
                    for m in result.matches
                ])
        
        # Reduce phase: aggregate
        return Evidence(
            claim_id=claim.id,
            matches=violations,
            satisfies_claim=(len(violations) == 0) if claim.expect == "zero_matches" else (len(violations) > 0)
        )
    
    async def _semantic_search(
        self, 
        context: RLMContext, 
        claim
    ) -> Evidence:
        """
        Semantic search strategy for relationship claims.
        
        1. Find all instances of pattern A (e.g., API endpoints)
        2. For each, verify pattern B exists nearby (e.g., auth decorator)
        """
        
        # First pass: find all endpoints
        endpoints = context.regex_search(claim.evidence[0].pattern)
        
        # Second pass: verify each endpoint has auth
        violations = []
        for endpoint in endpoints:
            # Get surrounding context
            surrounding = context.get_lines(
                endpoint.file,
                endpoint.line - claim.max_distance,
                endpoint.line + claim.max_distance
            )
            
            # Check for required pattern
            if not any(p in surrounding for p in claim.requires_nearby.split("|")):
                violations.append(endpoint)
        
        return Evidence(
            claim_id=claim.id,
            total_checked=len(endpoints),
            violations=violations,
            satisfies_claim=(len(violations) == 0)
        )
    
    async def _regex_filter_search(
        self, 
        context: RLMContext, 
        claim
    ) -> Evidence:
        """
        Fast regex pre-filter strategy.
        
        No LLM needed - pure code execution against context variable.
        """
        
        matches = context.regex_search(
            claim.evidence[0].pattern,
            scope=claim.evidence[0].scope,
            exclude=claim.evidence[0].exclude
        )
        
        return Evidence(
            claim_id=claim.id,
            matches=matches,
            satisfies_claim=(len(matches) == 0) if claim.expect == "zero_matches" else (len(matches) > 0)
        )


# GuardSpine integration
class RLMSecurityAuditorTool:
    """
    OpenClaw tool profile for rlm-docsync security auditing.
    """
    
    name = "rlm_security_audit"
    description = "Scan large codebases for security vulnerabilities using RLM"
    
    # GuardSpine tier: L2 (automated audit) or L3 (council review for findings)
    governance_tier = "L2"
    escalate_on_findings = True  # If vulns found, escalate to L3
    
    parameters = {
        "repo_path": {"type": "string", "required": True},
        "claims_manifest": {"type": "string", "required": True},
        "severity_threshold": {"type": "string", "default": "high"}
    }
    
    async def execute(self, params: dict) -> dict:
        auditor = SecurityAuditor()
        evidence_pack = await auditor.audit_repository(
            params["repo_path"],
            params["claims_manifest"]
        )
        
        # Determine if escalation needed
        critical_findings = [
            r for r in evidence_pack.results 
            if r.status == "fail" and r.severity in ["critical", "high"]
        ]
        
        return {
            "evidence_pack": evidence_pack.to_json(),
            "evidence_hash": evidence_pack.hash_chain_root(),
            "findings_count": len([r for r in evidence_pack.results if r.status == "fail"]),
            "critical_findings": len(critical_findings),
            "escalate_to_l3": len(critical_findings) > 0,
            "verification_command": f"docsync verify --pack {evidence_pack.path}"
        }
```

---

## Mode 2: Introspection / Self-Governance Verification

**Use Case:** MoltBot verifies its own governance harness is intact, hasn't drifted, and policies match implementation.

### The Brilliance Here

GuardSpine can use rlm-docsync to **audit itself**:
- "Does my actual code match my documented policies?"
- "Have my governance rules drifted from the manifest?"
- "Is my audit chain actually being enforced?"

This creates a **self-verifying governance system** with cryptographic proof.

```
┌─────────────────────────────────────────────────────────────────┐
│                    INTROSPECTION LOOP                            │
│                                                                  │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐        │
│   │ Governance  │───▶│ rlm-docsync │───▶│  Evidence   │        │
│   │   Docs      │    │   Scanner   │    │    Pack     │        │
│   │             │    │             │    │             │        │
│   │ "L3 needs   │    │ Scans own   │    │ PASS/FAIL   │        │
│   │  3 auditors"│    │ codebase    │    │ + proofs    │        │
│   └─────────────┘    └──────┬──────┘    └──────┬──────┘        │
│                             │                   │               │
│                             ▼                   ▼               │
│                      ┌─────────────────────────────┐           │
│                      │    GuardSpine Council       │           │
│                      │                             │           │
│                      │  Verifies its own evidence  │           │
│                      │  pack before any decision   │           │
│                      └─────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation

```yaml
# guardspine-self-audit.claims.yaml
version: "1.0"
mode: reality-first  # Code is truth, flag if docs are wrong
context_source:
  type: repository
  path: /home/david/moltbot  # MoltBot's own codebase
  
docs:
  - path: docs/GOVERNANCE.md
    claims:
      # Tier enforcement
      - id: GOV-TIER-001
        text: "L3 actions require 3-model council review"
        severity: critical
        evidence:
          - type: code
            pattern: "AUDITOR_MODELS.*=.*\\[.*,.*,.*\\]"
            scope: "**/guardspine*.py"
          - type: code
            pattern: "l3.*council|council.*l3|tier.*3.*model"
            scope: "**/guardspine*.py"
            
      # Hash chain integrity
      - id: GOV-HASH-001
        text: "All audit decisions are hash-chained"
        severity: critical
        evidence:
          - type: code
            pattern: "sha256|hash_chain|evidence_hash"
            scope: "**/guardspine*.py"
          - type: code
            pattern: "previous_hash|chain.*link"
            scope: "**/guardspine*.py"
            
      # No bypass paths
      - id: GOV-BYPASS-001
        text: "No code paths bypass governance"
        severity: critical
        evidence:
          - type: code
            pattern: "skip.*audit|bypass.*governance|disable.*check"
            scope: "**/*.py"
            expect: zero_matches
            exclude: ["**/test/**"]
            
      # Prompt injection resistance
      - id: GOV-INJECT-001
        text: "System prompts contain injection resistance"
        severity: high
        evidence:
          - type: code
            pattern: "IMMUTABLE|UNTRUSTED|NEVER.*override|ignore.*previous"
            scope: "**/prompts/**"
            
  - path: docs/REDTEAM.md
    claims:
      # Pliny coverage
      - id: RED-PLINY-001
        text: "Pliny L1B3RT4S tests are included in harness"
        severity: high
        evidence:
          - type: code
            pattern: "pliny|l1b3rt4s|jailbreak"
            scope: "**/promptfoo*.yaml"
            
      # Regression tests exist
      - id: RED-REGRESS-001
        text: "Regression tests for known vulnerabilities"
        severity: high
        evidence:
          - type: file
            path: "regression.yaml"
          - type: code
            pattern: "regression|known.*vuln"
            scope: "**/run_harness.py"
```

```python
# moltbot_plugins/rlm_introspection.py
"""
Mode 2: Self-governance verification via RLM introspection
"""

from rlm_docsync import DocSync, EvidencePack
from pathlib import Path
import hashlib
import json

class GovernanceIntrospector:
    """
    MoltBot's self-verification system.
    
    Uses rlm-docsync to verify:
    1. Governance implementation matches documentation
    2. No drift between policy and code
    3. Security measures are actually in place
    """
    
    def __init__(self, moltbot_root: str = "/home/david/moltbot"):
        self.root = Path(moltbot_root)
        self.manifest_path = self.root / "guardspine-self-audit.claims.yaml"
        
    async def verify_governance_integrity(self) -> dict:
        """
        Run full self-audit before any high-risk operation.
        
        Returns:
            {
                "integrity_verified": bool,
                "evidence_pack": EvidencePack,
                "drift_detected": list[str],
                "blocking_issues": list[str]
            }
        """
        
        # Load self-audit manifest
        docsync = DocSync(self.manifest_path)
        
        # Run audit against own codebase
        evidence_pack = await docsync.run(
            context_path=str(self.root),
            mode="reality-first"
        )
        
        # Analyze results
        critical_failures = []
        drift_warnings = []
        
        for result in evidence_pack.results:
            if result.status == "fail":
                if result.severity == "critical":
                    critical_failures.append(f"{result.claim_id}: {result.claim_text}")
                else:
                    drift_warnings.append(f"{result.claim_id}: {result.claim_text}")
        
        return {
            "integrity_verified": len(critical_failures) == 0,
            "evidence_pack": evidence_pack,
            "evidence_hash": evidence_pack.hash_chain_root(),
            "drift_detected": drift_warnings,
            "blocking_issues": critical_failures,
            "verification_timestamp": evidence_pack.timestamp,
            "can_proceed": len(critical_failures) == 0
        }
    
    async def pre_action_check(self, action_tier: str) -> bool:
        """
        Called by GuardSpine before any L2+ action.
        
        Returns True only if self-audit passes.
        """
        
        if action_tier in ["L0", "L1"]:
            return True  # Skip for low-risk
            
        result = await self.verify_governance_integrity()
        
        if not result["can_proceed"]:
            print(f"[INTROSPECTION] BLOCKING - Governance integrity failed:")
            for issue in result["blocking_issues"]:
                print(f"  ✗ {issue}")
            return False
            
        if result["drift_detected"]:
            print(f"[INTROSPECTION] WARNING - Drift detected:")
            for drift in result["drift_detected"]:
                print(f"  ⚠ {drift}")
        
        print(f"[INTROSPECTION] PASS - Evidence hash: {result['evidence_hash'][:16]}...")
        return True


# Integration with GuardSpine
class SelfAuditingGuardSpine:
    """
    GuardSpine wrapper that verifies its own integrity before decisions.
    """
    
    def __init__(self, base_guardspine):
        self.base = base_guardspine
        self.introspector = GovernanceIntrospector()
        self._last_integrity_check = None
        self._integrity_cache_seconds = 300  # Re-verify every 5 min
        
    async def audit(self, action, context) -> AuditResult:
        # Step 0: Verify own integrity (cached)
        if self._should_reverify():
            integrity = await self.introspector.verify_governance_integrity()
            
            if not integrity["can_proceed"]:
                return AuditResult(
                    verdict="BLOCKED",
                    reason="Governance integrity check failed",
                    evidence=integrity["evidence_pack"],
                    tier="SELF-AUDIT"
                )
            
            self._last_integrity_check = integrity
        
        # Step 1-N: Normal GuardSpine audit flow
        return await self.base.audit(action, context)
```

---

## Mode 3: General Large Context Reader

**Use Case:** MoltBot needs to read/analyze massive documents, repos, logs that exceed any context window.

### The Problem Space

- Code review on 100k+ line repo
- Analyze year of log files
- Summarize 500-page technical document
- Cross-reference multiple large documents

### RLM Solution with Evidence Trails

```python
# moltbot_plugins/rlm_context_reader.py
"""
Mode 3: General large context reading with proof trails
"""

from rlm_docsync import RLMContext, EvidencePack
from typing import AsyncIterator, Optional
import json

class LargeContextReader:
    """
    Read arbitrarily large documents/repos using RLM strategies.
    
    Key insight: Store context as variable, not in prompt.
    Model navigates via code, not attention.
    """
    
    def __init__(self, sub_llm_model: str = "qwen3:8b-q4_K_M"):
        self.sub_llm = sub_llm_model
        
    async def read_repository(
        self,
        repo_path: str,
        query: str,
        strategy: str = "auto"
    ) -> ReadResult:
        """
        Read a large repository to answer a query.
        
        Strategies:
        - "needle": Find specific information (semantic search)
        - "global": Understand overall structure (map-reduce)
        - "trace": Follow execution/data flow (recursive)
        - "auto": Model chooses based on query
        """
        
        # Load repo as context variable
        context = RLMContext.from_repository(repo_path)
        print(f"[RLM] Loaded {context.total_tokens:,} tokens")
        
        # Create evidence pack for audit trail
        evidence = EvidencePack(query_hash=hashlib.sha256(query.encode()).hexdigest())
        
        if strategy == "auto":
            strategy = await self._classify_query(query)
        
        if strategy == "needle":
            result = await self._needle_search(context, query, evidence)
        elif strategy == "global":
            result = await self._map_reduce(context, query, evidence)
        elif strategy == "trace":
            result = await self._trace_flow(context, query, evidence)
        else:
            result = await self._default_read(context, query, evidence)
        
        return ReadResult(
            answer=result.answer,
            evidence_pack=evidence,
            tokens_processed=result.tokens_processed,
            sub_calls_made=result.sub_calls,
            strategy_used=strategy
        )
    
    async def _needle_search(
        self, 
        context: RLMContext, 
        query: str,
        evidence: EvidencePack
    ) -> InternalResult:
        """
        Find specific information in massive context.
        
        Strategy:
        1. Generate candidate search terms from query
        2. Regex/semantic filter to candidate chunks
        3. Sub-LLM each candidate for relevance
        4. Return most relevant with citation
        """
        
        # Step 1: Query expansion
        search_terms = await self._expand_query(query)
        evidence.add_step("query_expansion", {"terms": search_terms})
        
        # Step 2: Fast filter (code, not LLM)
        candidates = []
        for term in search_terms:
            matches = context.search(term, max_results=50)
            candidates.extend(matches)
        
        evidence.add_step("candidate_filter", {
            "terms_searched": len(search_terms),
            "candidates_found": len(candidates)
        })
        
        # Step 3: Rank candidates via sub-LLM
        ranked = []
        for chunk in candidates[:20]:  # Limit sub-calls
            relevance = await self._sub_llm_query(
                f"Rate relevance 0-10 for query '{query}':\n\n{chunk.content}",
                max_tokens=10
            )
            ranked.append((chunk, relevance.score))
        
        ranked.sort(key=lambda x: x[1], reverse=True)
        evidence.add_step("ranking", {
            "candidates_ranked": len(ranked),
            "top_score": ranked[0][1] if ranked else 0
        })
        
        # Step 4: Generate answer from top results
        top_chunks = [r[0] for r in ranked[:3]]
        answer = await self._sub_llm_query(
            f"Answer based on these excerpts:\n\n" + 
            "\n---\n".join([c.content for c in top_chunks]) +
            f"\n\nQuery: {query}"
        )
        
        evidence.add_step("answer_generation", {
            "chunks_used": len(top_chunks),
            "files_referenced": list(set(c.file for c in top_chunks))
        })
        
        return InternalResult(
            answer=answer,
            tokens_processed=sum(len(c.content) for c in candidates),
            sub_calls=len(ranked) + 2  # ranking + answer
        )
    
    async def _map_reduce(
        self,
        context: RLMContext,
        query: str,
        evidence: EvidencePack
    ) -> InternalResult:
        """
        Global understanding via map-reduce.
        
        Strategy:
        1. Partition context into chunks
        2. Map: Extract relevant info from each chunk
        3. Reduce: Aggregate into coherent answer
        """
        
        # Partition
        chunks = list(context.partition(max_tokens=4096))
        evidence.add_step("partition", {
            "total_chunks": len(chunks),
            "avg_chunk_tokens": context.total_tokens // len(chunks)
        })
        
        # Map phase (parallel sub-calls)
        map_results = []
        for i, chunk in enumerate(chunks):
            result = await self._sub_llm_query(
                f"Extract information relevant to: {query}\n\n{chunk.content}\n\n" +
                "Return JSON: {\"relevant\": bool, \"summary\": str, \"key_facts\": list}"
            )
            if result.relevant:
                map_results.append(result)
            
            evidence.add_step(f"map_{i}", {
                "file": chunk.file_path,
                "relevant": result.relevant
            })
        
        # Reduce phase
        if len(map_results) > 10:
            # Recursive reduce
            answer = await self._recursive_reduce(map_results, query, evidence)
        else:
            # Single reduce
            combined = "\n".join([r.summary for r in map_results])
            answer = await self._sub_llm_query(
                f"Synthesize these summaries to answer: {query}\n\n{combined}"
            )
        
        return InternalResult(
            answer=answer,
            tokens_processed=context.total_tokens,
            sub_calls=len(chunks) + 1
        )
    
    async def _trace_flow(
        self,
        context: RLMContext,
        query: str,
        evidence: EvidencePack
    ) -> InternalResult:
        """
        Trace execution/data flow through codebase.
        
        Strategy:
        1. Identify entry point
        2. Recursively follow calls/references
        3. Build call graph with evidence at each step
        """
        
        # This is where RLM shines - model writes code to navigate
        trace_code = await self._sub_llm_query(
            f"""Write Python code to trace: {query}
            
Available:
- context.search(pattern) -> list of matches
- context.get_file(path) -> file content
- context.get_function(name) -> function body
- context.find_references(symbol) -> list of usages

Return only executable Python."""
        )
        
        # Execute model-generated navigation code
        trace_result = await self._execute_trace(context, trace_code, evidence)
        
        # Synthesize findings
        answer = await self._sub_llm_query(
            f"Explain this execution trace for: {query}\n\n{trace_result}"
        )
        
        return InternalResult(
            answer=answer,
            tokens_processed=trace_result.tokens_seen,
            sub_calls=trace_result.llm_calls + 2
        )


# MoltBot Tool Interface
class RLMReaderTool:
    """
    OpenClaw tool profile for large context reading.
    """
    
    name = "rlm_read"
    description = "Read and analyze large documents/repos beyond context window limits"
    
    governance_tier = "L1"  # Reading is low risk
    
    parameters = {
        "path": {"type": "string", "required": True},
        "query": {"type": "string", "required": True},
        "strategy": {"type": "string", "enum": ["auto", "needle", "global", "trace"]}
    }
    
    async def execute(self, params: dict) -> dict:
        reader = LargeContextReader()
        
        if Path(params["path"]).is_dir():
            result = await reader.read_repository(
                params["path"],
                params["query"],
                params.get("strategy", "auto")
            )
        else:
            result = await reader.read_document(
                params["path"],
                params["query"],
                params.get("strategy", "auto")
            )
        
        return {
            "answer": result.answer,
            "evidence_hash": result.evidence_pack.hash_chain_root(),
            "tokens_processed": result.tokens_processed,
            "sub_calls": result.sub_calls_made,
            "strategy": result.strategy_used,
            "verification": f"docsync verify --pack {result.evidence_pack.path}"
        }
```

---

## Unified Architecture: All Three Modes

```python
# moltbot_plugins/rlm_docsync_plugin.py
"""
Unified rlm-docsync plugin for MoltBot.

Provides three modes:
1. Security auditing of external codebases
2. Self-governance introspection
3. General large context reading
"""

from enum import Enum
from dataclasses import dataclass
from pathlib import Path

class RLMMode(Enum):
    SECURITY_AUDIT = "security"    # Mode 1: External repos
    INTROSPECTION = "introspect"   # Mode 2: Self-verify
    CONTEXT_READ = "read"          # Mode 3: General tool

@dataclass
class RLMDocsyncPlugin:
    """
    MoltBot plugin integrating rlm-docsync for:
    - Infinite context handling (10M+ tokens)
    - Hash-chained evidence trails
    - Self-verifying governance
    """
    
    name = "rlm_docsync"
    version = "1.0.0"
    
    # Component instances
    security_auditor: SecurityAuditor
    introspector: GovernanceIntrospector
    context_reader: LargeContextReader
    
    def __init__(self, config: dict):
        self.security_auditor = SecurityAuditor(
            ollama_base=config.get("ollama_base", "http://localhost:11434")
        )
        self.introspector = GovernanceIntrospector(
            moltbot_root=config.get("moltbot_root", "/home/david/moltbot")
        )
        self.context_reader = LargeContextReader(
            sub_llm_model=config.get("sub_llm_model", "qwen3:8b-q4_K_M")
        )
    
    async def execute(self, mode: RLMMode, params: dict) -> dict:
        """
        Unified entry point for all RLM operations.
        """
        
        if mode == RLMMode.SECURITY_AUDIT:
            evidence_pack = await self.security_auditor.audit_repository(
                params["repo_path"],
                params["claims_manifest"]
            )
            return {
                "mode": "security_audit",
                "findings": evidence_pack.failure_count,
                "evidence_hash": evidence_pack.hash_chain_root(),
                "pack": evidence_pack.to_json()
            }
            
        elif mode == RLMMode.INTROSPECTION:
            result = await self.introspector.verify_governance_integrity()
            return {
                "mode": "introspection",
                "integrity_verified": result["integrity_verified"],
                "drift_detected": result["drift_detected"],
                "blocking_issues": result["blocking_issues"],
                "evidence_hash": result["evidence_hash"]
            }
            
        elif mode == RLMMode.CONTEXT_READ:
            result = await self.context_reader.read_repository(
                params["path"],
                params["query"],
                params.get("strategy", "auto")
            )
            return {
                "mode": "context_read",
                "answer": result.answer,
                "tokens_processed": result.tokens_processed,
                "evidence_hash": result.evidence_pack.hash_chain_root()
            }
    
    # OpenClaw tool registration
    def get_tools(self) -> list:
        return [
            {
                "name": "rlm_security_audit",
                "handler": lambda p: self.execute(RLMMode.SECURITY_AUDIT, p),
                "governance_tier": "L2",
                "escalate_on_findings": True
            },
            {
                "name": "rlm_introspect",
                "handler": lambda p: self.execute(RLMMode.INTROSPECTION, p),
                "governance_tier": "L1",  # Self-check is safe
            },
            {
                "name": "rlm_read",
                "handler": lambda p: self.execute(RLMMode.CONTEXT_READ, p),
                "governance_tier": "L1",
            }
        ]


# GuardSpine integration hook
def register_with_guardspine(guardspine, plugin: RLMDocsyncPlugin):
    """
    Register rlm-docsync plugin with GuardSpine governance.
    
    Special handling:
    - Introspection runs BEFORE any L2+ audit
    - Security audit findings auto-escalate to L3
    - Context reads are logged but low-risk
    """
    
    # Register as pre-audit hook
    guardspine.register_pre_audit_hook(
        tier=["L2", "L3", "L4"],
        hook=plugin.introspector.pre_action_check
    )
    
    # Register tools
    for tool in plugin.get_tools():
        guardspine.register_tool(tool)
    
    # Configure auto-escalation
    guardspine.register_escalation_rule(
        trigger=lambda result: (
            result.get("mode") == "security_audit" and 
            result.get("findings", 0) > 0
        ),
        escalate_to="L3",
        reason="Security vulnerabilities detected"
    )
```

---

## Summary: Three Modes

| Mode | Purpose | RLM Strategy | Evidence Output | GuardSpine Tier |
|------|---------|--------------|-----------------|-----------------|
| **Security Audit** | Scan external repos for vulns | Claims → map-reduce → violations | Hash-chained vuln report | L2 (escalate to L3 on findings) |
| **Introspection** | Verify own governance | Self-audit → drift detection | Integrity proof | L1 (but blocks L2+ if fails) |
| **Context Read** | General 10M+ reading | Auto (needle/global/trace) | Query evidence trail | L1 |

### The Key Insight

Your `rlm-docsync` isn't just a documentation tool—it's a **structured interface for infinite-context cognition with cryptographic audit trails**. Combined with GuardSpine:

1. **Security**: Audit any codebase regardless of size
2. **Integrity**: Self-verify governance before every decision
3. **Capability**: Read anything, prove what you found

This makes MoltBot simultaneously more capable (10M+ context) and more trustworthy (hash-chained evidence for everything it reads).

---
---

# ENRICHMENT: Local Asset Inventory & Implementation Context

*Added 2026-01-31 after full codebase exploration. This section provides the concrete local context needed to execute the plan above with zero ambiguity.*

---

## 1. Complete GuardSpine Ecosystem (10 Repositories)

The plan references "GuardSpine repo" and "RLM-DocSync repo" generically. Here is the exact inventory:

| # | Repo | Local Path | Stack | Key Entry Points | Tests |
|---|------|-----------|-------|-----------------|-------|
| 1 | **GuardSpine** (monorepo) | `D:\Projects\GuardSpine` | Python 3.11+, FastAPI | CLI: `python -m codeguard audit`; API: `backend/app/main.py` on :8000 | 144 passing, 9 test files |
| 2 | **@guardspine/kernel** | `D:\Projects\guardspine-kernel` | TypeScript (ESM), node:crypto | `dist/index.js`: sealBundle, verifyBundle, buildHashChain, computeRootHash | vitest |
| 3 | **guardspine-spec** | `D:\Projects\guardspine-spec` | JSON Schema, Markdown | `schemas/evidence-bundle.schema.json`, `SPECIFICATION.md` | schema validation |
| 4 | **guardspine-product** | `D:\Projects\guardspine-product` | Python | 4 guard lanes: Code Guard, PDF Guard, Image Guard, Sheet Guard; 5 beta lanes | -- |
| 5 | **guardspine-local-council** | `D:\Projects\guardspine-local-council` | Python, httpx | `LocalCouncil.review(ReviewRequest)` async API; Ollama on :11434 | -- |
| 6 | **guardspine-verify** | `D:\Projects\guardspine-verify` | Python | `guardspine-verify bundle.json` CLI; ZIP export validation | -- |
| 7 | **@guardspine/adapter-webhook** | `D:\Projects\guardspine-adapter-webhook` | TypeScript (ESM), vitest | GitHub, GitLab, generic webhook providers | vitest |
| 8 | **guardspine-connector-template** | `D:\Projects\guardspine-connector-template` | Minimal | Template for new connectors | -- |
| 9 | **n8n-nodes-guardspine** | `D:\Projects\n8n-nodes-guardspine` | TypeScript, npm | 7 n8n node types; `GUARDSPINE-MASTER-PLAN.md` | npm test |
| 10 | **rlm-docsync** | `D:\Projects\rlm-docsync` | JavaScript/TypeScript, npm | `docsync run`, `docsync verify` CLI; spec-first and reality-first modes | -- |

### Key Files in GuardSpine Monorepo

| Component | Path | What It Does |
|-----------|------|-------------|
| Backend (FastAPI) | `D:\Projects\GuardSpine\backend\` | 138 endpoints across 17 routers (health, dashboard, approvals, beads, bundles, search, diffs, events, policies, connectors, webhooks, auth, slack, governance, board_packets, alerts, compression) |
| CodeGuard CLI | `D:\Projects\GuardSpine\codeguard\` | `codeguard audit <path> --level L0-L4 --rubric <yaml> --backend ollama --evidence-bundle <dir>` |
| Rubric Evaluator | `D:\Projects\GuardSpine\codeguard\rubrics\evaluator.py` | Regex pattern matching from YAML rubrics against code |
| Rubric Loader | `D:\Projects\GuardSpine\codeguard\rubrics\loader.py` | Loads/parses YAML rubric files |
| Beads Service | `D:\Projects\GuardSpine\backend\app\services\beads_service.py` | Beads task context/metadata integration |
| Board Packet Service | `D:\Projects\GuardSpine\backend\app\services\board_packet_service.py` | Board governance workflow |
| Signing Service | `D:\Projects\GuardSpine\backend\app\services\signing_service.py` | Cryptographic signing |

### 11 Production Rubrics

All at `D:\Projects\GuardSpine\rubrics\`:

| File | Purpose | Size |
|------|---------|------|
| `clarity.yaml` | Cognitive load, readability | 7,396 bytes |
| `connascence.yaml` | 9 coupling types (CoN through CoI) | 5,265 bytes |
| `hipaa-safeguards.yaml` | HIPAA compliance patterns | 4,081 bytes |
| `mece.yaml` | Duplication detection | 6,044 bytes |
| `nasa-safety.yaml` | Power of 10 rules | 5,489 bytes |
| `nomotic.yaml` | Governance policy patterns | 17,792 bytes |
| `pci-dss-requirements.yaml` | PCI-DSS 3.2.1 | 4,814 bytes |
| `safety-violations.yaml` | God objects, parameter bombs | 9,911 bytes |
| `six-sigma.yaml` | DPMO/sigma metrics | 6,905 bytes |
| `soc2-controls.yaml` | SOC2 Type II | 3,394 bytes |
| `theater-detection.yaml` | Fake quality prevention | 8,429 bytes |

---

## 2. Pre-Existing Evidence Packs

These already exist and can be referenced or used as templates:

| Pack | Location | Contents |
|------|----------|----------|
| Current (active) | `D:\Projects\GuardSpine\evidence-pack\` | 8 sections: 00-environment through 08-integration, including council votes, sealed bundles, verification proofs |
| v1-before | `D:\Projects\GuardSpine\evidence-pack-v1-before\` | Baseline rubric scores (pre-fix) |
| v2-after | `D:\Projects\GuardSpine\evidence-pack-v2-after\` | Post-fix rubric scores |
| v3-zero | `D:\Projects\GuardSpine\evidence-pack-v3-zero\` | Zero-state rubric scores |
| v4-council | `D:\Projects\GuardSpine\evidence-pack-v4-council\` | Council audit results |
| Spec audits | `D:\Projects\guardspine-spec\evidence-packs\` | 2 council audit runs (2026-01-31) |

---

## 3. Existing Planning Documents

| Document | Path | Relevance |
|----------|------|-----------|
| Evidence Pack Plan | `D:\Projects\GuardSpine\EVIDENCE-PACK-PLAN.md` | GuardSpine's own product validation plan (Phases A-E). Separate from this OpenClaw hardening plan. |
| Master Plan | `D:\Projects\n8n-nodes-guardspine\GUARDSPINE-MASTER-PLAN.md` | Strategic plan for n8n integration |
| Beads Integration | `D:\2026-AI-EXOSKELETON\guardspine-integration-beads.md` | Beads task system integration spec |
| Phase 2 Beads | `D:\2026-AI-EXOSKELETON\guardspine-phase2-beads.md` | Phase 2 Beads integration plan |
| WoundHealer | `D:\2026-AI-EXOSKELETON\guardspine-woundhealer-spec.md` | Self-healing governance spec |
| Backend Inventory | `C:\Users\17175\GUARDSPINE-INVENTORY.txt` | 167-line inventory: 138 endpoints, 17 routers, 19 services, 6 schemas, 12 rubrics, 144 tests |

---

## 4. Bundle Contents (Unpacked)

The three ZIP files have been unpacked to `C:\Users\17175\Downloads\openclaw x guardspine\`:

### Bundle 2 -- Eval Harness (`bundle2/`)

| File | Lines | Key Classes/Functions |
|------|-------|---------------------|
| `guardspine_provider.py` | ~440 | `classify_risk()` L0-L4, `call_ollama()`, `run_l1_audit()`, `run_l2_rubric()`, `run_l3_council()`, `create_evidence_bundle()`, `call_api()` (Promptfoo entry point) |
| `promptfooconfig.yaml` | ~245 | 3 targets (direct Ollama, GuardSpine-protected, individual council); 50+ red-team plugins; strategies: jailbreak, base64, rot13, leetspeak, crescendo, goat |
| `regression.yaml` | ~195 | Pliny L1B3RT4S, indirect injection, shell injection, encoding bypass, governance bypass, multi-turn escalation |
| `run_harness.py` | ~595 | `VulnerabilityDB`, `run_promptfoo()`, `analyze_results()`, `generate_report()`, `generate_patch_recommendations()`, `continuous_mode(target_rate=95.0, max_iterations=10)` |
| `setup.sh` | ~115 | Checks Node 20+, Python 3.10+, Ollama; pulls qwen3:8b, falcon3:7b, mistral:7b; creates results/regression/patches/reports/evidence dirs |
| `README.md` | ~290 | Pass thresholds: 95%+ ready, 80-95% needs work, <80% critical. Severity: Critical/High/Medium/Low |

### Bundle 3 -- L3 Rubric (`bundle3/`)

| File | Lines | Key Details |
|------|-------|-------------|
| `evaluate_evidence.py` | ~710 | `AuditorResult`, `EvaluationResult`, `validate_evidence_pack()`, `query_auditor()`, `parse_auditor_response()`, `aggregate_results()`. 5 dimensions weighted. Thresholds: PASS >= 4.0, CONDITIONAL 3.0-3.99, FAIL < 3.0. Execution order: C -> A -> B |
| `guardspine-evidence-rubric.yaml` | ~570 | 5 dimensions: completeness(0.25), precision(0.20), reasoning(0.25), negative_proof(0.15), chain_integrity(0.15). Mode overrides for security_audit/introspection/context_read. Auditor roles: A=completeness, B=adversarial, C=compliance |
| `sample-evidence-pack.json` | ~150 | PASSING: introspection mode, 4/4 claims pass (GOV-TIER-001, GOV-HASH-001, GOV-BYPASS-001, GOV-INJECT-001), valid hash chain |
| `sample-evidence-pack-fail.json` | ~130 | FAILING: security_audit mode, 2 FAIL (SQL injection found, unauthed endpoints), 1 PASS (no hardcoded secrets) |

### Bundle 4 -- RLM DocSync Plugin (`bundle4/`)

| File | Lines | Key Details |
|------|-------|-------------|
| `rlm_docsync.py` | ~1000 | Classes: `EvidenceEntry`, `ClaimResult`, `EvidencePack`, `RLMContext` (from_repository, search, get_lines, partition). Functions: `security_audit()`, `introspect()`, `read()`, `_needle_search()`, `_map_reduce()`, `_trace_flow()`. CLI: `audit <path>`, `introspect`, `read <path> <query>` |
| `rlm-docsync-plugin.yaml` | ~630 | 3 tools (rlm_security_audit L2, rlm_introspect L1, rlm_read L1). 6 hooks (before_execute, before_council, after_council, after_execute). REPL restrictions: no os.system/subprocess/eval/exec/__import__. Council: sequential C->A->B, early exit on hard fail |
| `rlm-docsync-plugin-README.md` | ~285 | 3 modes documented. Council weights: qwen3(0.40), falcon3(0.35), mistral(0.25). Evidence schema: pack_id, timestamp, mode, claims[], hash_chain{} |

---

## 5. Library Components for Reuse

The `.claude/library/` (81 production-grade components) contains 11 directly applicable to this plan:

### REUSE (Copy + Adapt) -- 6 Components

| Component | Path in Library | Target Phase | What It Provides | Quality |
|-----------|----------------|-------------|-----------------|---------|
| **guard-lane-base** | `components/governance/guard_lane_base/` | P1 (Policy) | `BaseGuardLane` ABC, `TriggerType` enum (20 event types), `GuardEvent`, `ApprovalSet` with L0-L4 consensus, `LaneEvaluationResult`, `LaneRegistry` polymorphic dispatch | 95 |
| **audit-logging** | `components/observability/audit_logging/` | P2 (Evidence) | `AuditLogger` async with field-level diffs, `calculate_diff()`, `separate_transaction` for compliance, `SyncAuditLogger` variant | 86 |
| **tagging-protocol** | `components/observability/tagging_protocol/` | P2 (Schemas) | WHO/WHEN/PROJECT/WHY metadata generation, `Intent` enum (12 types), `AgentCategory` enum (14 types), `generate_tags()`, `create_payload()` | 88 |
| **quality-gate** | `components/utilities/quality_gate/quality_gate.py` | P5 (Approval) | `GateManager` centralized gate registry, `GateConfig` (threshold, metric_fn, timeout), `GateResult` (passed/failed + metadata), `create_quality_gate()` factory | 85 |
| **model-router** | `components/ai/model_router/providers.py` | P4 (Council) | `ProviderConfig` (name, enabled, timeout, max_tokens, temperature), `ProviderHealth` (status, latency, error rate), provider routing logic | 82 |
| **yaml-safe-write** | `components/utilities/io_helpers/yaml_safe_write.py` | P7 (Guarded Write) | `AtomicWriter` context manager, `yaml_safe_write()` async, `BackupConfig` (max_backups, timestamp), `WriteResult` | 95 |

### PATTERN (Follow Pattern, Write New) -- 5 Components

| Component | Path in Library | Target Phase | Pattern to Follow | Quality |
|-----------|----------------|-------------|-------------------|---------|
| **auditor-base** | `components/patterns/auditor_base/` | P4 (Prompts) | `BaseAuditor` ABC, `AuditorResult` (claims, confidence, grounds), `ActionClass` enum (ACCEPT/REJECT), confidence ceiling enforcement | 85 |
| **spec-validation** | `components/validation/spec_validation/` | P2 (Schemas) | `ValidationSchema`, checkpoint structure for JSON schema validation | 92 |
| **scoring-aggregator** | `components/analysis/scoring_aggregator/` | P4 (Council) | `AnalyzerScore`, weighted multi-analyzer aggregation | 86 |
| **pipeline-executor** | `components/orchestration/pipeline_executor/` | P7 (Guarded Exec) | Sequential executor orchestration pattern | 90 |
| **pytest-fixtures** | `components/testing/pytest-fixtures/fixtures.py` | Tests | `BaseFactory` pattern for PolicyFactory, EvidenceFactory, etc. | 100 |

### Also Useful (Lower Priority)

| Component | Path | Use Case |
|-----------|------|----------|
| **circuit-breaker** | `components/utilities/circuit_breaker/circuit_breaker.py` | Fault tolerance for approval gate timeouts (CLOSED/OPEN/HALF_OPEN states, exponential backoff) |
| **frozen-harness** | `components/cognitive_architecture/loopctl/core.py` | Policy immutability enforcement during governance execution |
| **report-generator** | `components/reporting/report_generator/` | RUNBOOK/ARCHITECTURE doc generation |

---

## 6. MECE: Per-Deliverable Build Strategy

Every file in the manifest mapped to its build strategy:

### A) GOVERNANCE CORE

| # | File | Strategy | Source |
|---|------|----------|--------|
| 1 | `policy/guardspine_policy.yaml` | ADAPT | guard-lane-base (TriggerType, ApprovalSet L0-L4) |
| 2 | `policy/risk_classifier.yaml` | ADAPT | guard-lane-base (LaneEvaluationResult risk scoring) |
| 3 | `policy/frozen_paths.yaml` | PATTERN | yaml-safe-write (AtomicWriter protects paths) |
| 4 | `schemas/action_request.v1.json` | ADAPT | guard-lane-base (GuardEvent) + tagging-protocol (WHO/WHEN/PROJECT/WHY) |
| 5 | `schemas/evidence_pack.v1.json` | ADAPT | audit-logging (AuditEntry) + guardspine-spec schema as reference |
| 6 | `schemas/approval_request.v1.json` | ADAPT | quality-gate (GateConfig) + guard-lane-base (ApprovalSet) |
| 7 | `schemas/approval_response.v1.json` | PATTERN | auditor-base (AuditorResult, ActionClass) |

### B) EVIDENCE + RUBRIC

| # | File | Strategy | Source |
|---|------|----------|--------|
| 8 | `rubric/guardspine-evidence-rubric.yaml` | BUNDLE 3 | Copy from `bundle3/guardspine-evidence-rubric.yaml` |
| 9 | `rubric/evaluate_evidence.py` | BUNDLE 3 | Copy from `bundle3/evaluate_evidence.py` |
| 10 | `rubric/sample_packs/pass.json` | BUNDLE 3 | Copy from `bundle3/sample-evidence-pack.json` |
| 11 | `rubric/sample_packs/fail.json` | BUNDLE 3 | Copy from `bundle3/sample-evidence-pack-fail.json` |

### C) COUNCIL

| # | File | Strategy | Source |
|---|------|----------|--------|
| 12 | `council/council_runner.py` | ADAPT | model-router/providers + scoring-aggregator (weighted votes) |
| 13 | `council/prompts/auditor_a_lead.txt` | PATTERN | auditor-base (BaseAuditor role pattern) |
| 14 | `council/prompts/auditor_b_adversary.txt` | PATTERN | auditor-base |
| 15 | `council/prompts/auditor_c_format_chain.txt` | PATTERN | auditor-base |
| 16 | `council/config.yaml` | ADAPT | model-router/providers (ProviderConfig structure) |

### D) APPROVAL GATE

| # | File | Strategy | Source |
|---|------|----------|--------|
| 17 | `approvals/approval_gate.py` | ADAPT | quality-gate (GateManager) + audit-logging (separate_transaction) |
| 18 | `approvals/channel_discord.py` | BUILD NEW | Stub adapter, reads from dev_inbox/ |
| 19 | `approvals/channel_sms.py` | BUILD NEW | Stub adapter, reads from dev_inbox/ |
| 20-21 | `approvals/state/*.jsonl` | PATTERN | audit-logging (append-only pattern) |
| 22 | `approvals/secrets/` | BUILD NEW | HMAC key generation |
| 23-24 | `approvals/dev_inbox/*.txt` | BUILD NEW | Stub inboxes |
| 25 | `approvals/README.md` | BUILD NEW | Message format documentation |

### E) GUARDED TOOLS

| # | File | Strategy | Source |
|---|------|----------|--------|
| 26 | `tools/guarded_exec.py` | ADAPT | guard-lane-base (LaneRegistry) + quality-gate (pipeline) + audit-logging (evidence trail) |
| 27 | `tools/guarded_write.py` | ADAPT | yaml-safe-write (AtomicWriter) + guard-lane-base (frozen path check) |
| 28 | `tools/guarded_download.py` | PATTERN | circuit-breaker (fault tolerance) |
| 29 | `tools/guarded_promote.py` | ADAPT | quality-gate + pipeline-executor (sequential gates) |
| 30 | `tools/guarded_issue_create.py` | ADAPT | tagging-protocol (metadata) + audit-logging |
| 31 | `tools/quarantine_policy.yaml` | PATTERN | guard-lane-base (risk tier definitions) |

### F) OPENCLAW CONFIG

| # | File | Strategy | Source |
|---|------|----------|--------|
| 32 | `openclaw/rlm-docsync-plugin.yaml` | BUNDLE 4 | Copy from `bundle4/rlm-docsync-plugin.yaml` |
| 33 | `openclaw/openclaw_config_template.json` | BUILD NEW | Deny raw tools, allow guarded_* only |
| 34 | `openclaw/moltbot_guardspine_wiring.md` | BUILD NEW | Exact install steps |

### G) EVAL HARNESS

| # | File | Strategy | Source |
|---|------|----------|--------|
| 35 | `eval/attacks/pliny_prompts/` | BUILD NEW | Placeholder with format |
| 36 | `eval/attacks/synthetic_prompts/` | BUILD NEW | 50+ injection prompts |
| 37 | `eval/run_eval.py` | BUNDLE 2 | Copy from `bundle2/run_harness.py` |
| 38 | `eval/guardspine_provider.py` | BUNDLE 2 | Copy from `bundle2/guardspine_provider.py` |
| 39 | `eval/promptfooconfig.yaml` | BUNDLE 2 | Copy from `bundle2/promptfooconfig.yaml` |
| 40 | `eval/regression.yaml` | BUNDLE 2 | Copy from `bundle2/regression.yaml` |
| 41 | `eval/baselines/baseline_v1.json` | BUILD NEW | Generated from first run |
| 42 | `eval/results/` | BUILD NEW | Gitignored directory |
| 43 | `eval/README.md` | BUNDLE 2 | Copy from `bundle2/README.md` |
| 44 | `eval/ci/run_nightly.*` | BUILD NEW | Scheduled runner scripts |

### H) RUNBOOKS

| # | File | Strategy | Source |
|---|------|----------|--------|
| 45 | `RUNBOOK.md` | BUILD NEW | -- |
| 46 | `ARCHITECTURE.md` | BUILD NEW | -- |
| 47 | `THREAT_MODEL.md` | BUILD NEW | -- |
| 48 | `CHANGELOG.md` | BUILD NEW | -- |

### I) TESTS

| # | File | Strategy | Source |
|---|------|----------|--------|
| 49 | `tests/test_policy_freeze.py` | PATTERN | pytest-fixtures (Factory pattern) |
| 50 | `tests/test_risk_classifier.py` | PATTERN | pytest-fixtures |
| 51 | `tests/test_evidence_chain.py` | PATTERN | pytest-fixtures |
| 52 | `tests/test_council_sequential.py` | PATTERN | pytest-fixtures |
| 53 | `tests/test_approval_gate.py` | PATTERN | pytest-fixtures |
| 54 | `tests/test_quarantine_promotion.py` | PATTERN | pytest-fixtures |
| 55 | `tests/test_guarded_exec_denies.py` | PATTERN | pytest-fixtures |
| 56 | `tests/test_eval_harness_nonregression.py` | PATTERN | pytest-fixtures |

---

## 7. Build Strategy Summary

| Strategy | Count | Files |
|----------|-------|-------|
| **BUNDLE** (copy as-is) | 11 | rubric x4, eval harness x6, openclaw plugin x1 |
| **ADAPT** (copy library component + modify) | 15 | policy x2, schemas x4, council x2, approval gate x1, guarded tools x5, quarantine promote x1 |
| **PATTERN** (follow library pattern, write new) | 12 | frozen_paths, approval_response schema, auditor prompts x3, quarantine download, quarantine policy, all 8 tests |
| **BUILD NEW** (no library match) | 18 | Discord/SMS stubs x2, secrets, dev_inbox x2, README, openclaw config, wiring doc, pliny prompts, synthetic prompts, baseline, results dir, nightly scripts, 4 runbook docs |
| **TOTAL** | **56** | |

---

## 8. Execution Dependency Graph

```
Phase P0: Workspace Normalization
    |--- Create ./guardspine_openclaw_hardening/ at D:\Projects\GuardSpine\
    |--- Copy bundles 2,3,4 into rubric/, eval/, openclaw/
    |--- .gitignore + logs/
    |
    v
Phase P1: Policy + Risk Classification
    |--- ADAPT guard-lane-base -> policy/*.yaml
    |--- Tests: test_policy_freeze.py, test_risk_classifier.py
    |
    v
Phase P2: Evidence Pack Schema + Hash Chain
    |--- ADAPT audit-logging + tagging-protocol -> schemas/*.json
    |--- Tests: test_evidence_chain.py
    |
    v
Phase P3: Rubric -- DONE (bundle3 copied in P0)
    |
    v
Phase P4: Sequential Council
    |--- ADAPT model-router -> council/council_runner.py
    |--- PATTERN auditor-base -> council/prompts/*.txt
    |--- Tests: test_council_sequential.py
    |
    v
Phase P5: Remote L4 Approval Gate
    |--- ADAPT quality-gate -> approvals/approval_gate.py
    |--- BUILD NEW -> channel stubs, dev_inbox, secrets
    |--- Tests: test_approval_gate.py
    |
    v
Phase P6: Quarantine + Promotion
    |--- PATTERN circuit-breaker -> tools/guarded_download.py
    |--- ADAPT pipeline-executor -> tools/guarded_promote.py
    |--- Tests: test_quarantine_promotion.py, test_guarded_exec_denies.py
    |
    v
Phase P7: Guarded Wrappers
    |--- ADAPT guard-lane-base + yaml-safe-write -> tools/guarded_*.py
    |
    v
Phase P8: OpenClaw Config
    |--- bundle4 already copied; BUILD NEW config + wiring doc
    |
    v
Phase P9: Eval Harness
    |--- bundle2 already copied; BUILD NEW synthetic prompts + nightly scripts
    |--- Tests: test_eval_harness_nonregression.py
    |
    v
Phase P10: Runbooks
    |--- BUILD NEW: RUNBOOK.md, ARCHITECTURE.md, THREAT_MODEL.md, CHANGELOG.md
    |
    v
ACCEPTANCE CRITERIA A-G VERIFICATION
    |--- pytest -q ./tests/
    |--- Frozen paths deny enforced by code
    |--- Download quarantine verified
    |--- L4 HMAC approval verified
    |--- Council sequential order verified in logs
    |--- Eval harness: 0 critical escapes
    |--- Full local operation with stub inboxes
```

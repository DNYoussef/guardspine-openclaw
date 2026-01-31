# rlm-docsync: MoltBot Plugin

**Proof-carrying cognition layer for MoltBot/GuardSpine**

## Overview

rlm-docsync integrates RLM (Recursive Language Models) context virtualization with hash-chained evidence packs. Every operation produces cryptographic proof of what was read, analyzed, and concluded.

```
┌─────────────────────────────────────────────────────────────────┐
│                    rlm-docsync Architecture                      │
│                                                                  │
│   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐          │
│   │   Mode 1    │   │   Mode 2    │   │   Mode 3    │          │
│   │  SECURITY   │   │ INTROSPECT  │   │   READER    │          │
│   │   AUDIT     │   │ SELF-CHECK  │   │  10M+ ctx   │          │
│   └──────┬──────┘   └──────┬──────┘   └──────┬──────┘          │
│          │                 │                 │                  │
│          └─────────────────┼─────────────────┘                  │
│                            ▼                                    │
│                   ┌─────────────────┐                           │
│                   │  RLM Context    │                           │
│                   │  (10M tokens    │                           │
│                   │   as variable)  │                           │
│                   └────────┬────────┘                           │
│                            ▼                                    │
│                   ┌─────────────────┐                           │
│                   │  Evidence Pack  │                           │
│                   │  (hash-chained) │                           │
│                   └────────┬────────┘                           │
│                            ▼                                    │
│                   ┌─────────────────┐                           │
│                   │   L3 Council    │                           │
│                   │   Evaluation    │                           │
│                   └─────────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `rlm-docsync-plugin.yaml` | OpenClaw manifest (tools, governance, config) |
| `rlm_docsync.py` | Python implementation |
| `guardspine-evidence-rubric.yaml` | L3 council rubric |
| `evaluate_evidence.py` | Evidence pack evaluator |
| `sample-evidence-pack.json` | Example passing pack |
| `sample-evidence-pack-fail.json` | Example failing pack |

## Quick Start

### 1. Security Audit (Mode 1)

Scan external codebase for vulnerabilities:

```bash
python rlm_docsync.py audit /path/to/repo -o audit-result.json
```

### 2. Introspection (Mode 2)

Verify MoltBot/GuardSpine governance integrity:

```bash
python rlm_docsync.py introspect -o introspect-result.json
```

### 3. Context Read (Mode 3)

Read large documents with proof trails:

```bash
python rlm_docsync.py read /path/to/repo "What does the authentication system do?" -o read-result.json
```

### 4. Evaluate Evidence Pack

```bash
python evaluate_evidence.py --pack audit-result.json --mode security_audit
```

## Three Modes

### Mode 1: Security Audit

**Purpose:** Scan external codebases for vulnerabilities

| Aspect | Value |
|--------|-------|
| Governance Tier | L2 (escalate to L3 on findings) |
| Evidence Mode | `security_audit` |
| Min Rubric Score | 4.0 |
| Escalation Triggers | Critical finding, ≥3 high findings |

**Default Claims:**
- SEC-SQLI-001: No raw SQL string concatenation
- SEC-SECRETS-001: No hardcoded credentials
- SEC-EVAL-001: No dangerous eval/exec usage
- SEC-SHELL-001: No shell injection vulnerabilities

### Mode 2: Introspection

**Purpose:** Self-verify governance integrity

| Aspect | Value |
|--------|-------|
| Governance Tier | L1 (but affects L2+) |
| Evidence Mode | `introspection` |
| Min Rubric Score | 4.0 |
| On Fail | **BLOCK ALL L2+ ACTIONS** |

**Default Claims:**
- GOV-TIER-001: L3 actions require 3-model council
- GOV-HASH-001: All audit decisions are hash-chained
- GOV-BYPASS-001: No code paths bypass governance
- GOV-INJECT-001: System prompts contain injection resistance

**CRITICAL:** Introspection automatically runs before any L2+ action. If it fails, MoltBot cannot proceed.

### Mode 3: Context Reader

**Purpose:** Read large documents with proof trails

| Aspect | Value |
|--------|-------|
| Governance Tier | L1 |
| Evidence Mode | `context_read` |
| Min Rubric Score | 3.5 |
| Max Context | 10M+ tokens |

**Strategies:**
- `needle` — Targeted search for specific information
- `global` — Map-reduce for overall understanding
- `trace` — Follow execution/data flow
- `auto` — Automatically select based on query

## Council Configuration

Your 3-model council (sequential, VRAM-safe):

| Auditor | Model | Weight | Role |
|---------|-------|--------|------|
| **C** | `mistral:7b-instruct-q4_K_M` | 0.25 | Format compliance, fast fail |
| **A** | `qwen3:8b-q4_K_M` | 0.40 | Lead evaluator |
| **B** | `falcon3:7b` | 0.35 | Adversarial verifier |

**Execution Order:** C → A → B (fast fail first, then deep reasoning)

## Evidence Pack Schema

```json
{
  "schema_version": "1.0",
  "pack_id": "epk_security_20260130_abc123",
  "created_at": "2026-01-30T18:00:00Z",
  "mode": "security_audit",
  "claims": [
    {
      "claim_id": "SEC-SQLI-001",
      "claim_text": "No raw SQL string concatenation",
      "status": "pass",
      "severity": "critical",
      "expect": "zero_matches",
      "rationale": "Searched all .py files, no violations found",
      "evidence": [
        {
          "type": "search",
          "ref": "repo_scan",
          "query": "execute\\([^)]*\\+",
          "scope": "**/*.py",
          "result": "zero_matches"
        }
      ]
    }
  ],
  "hash_chain": {
    "algorithm": "sha256",
    "entries": [...],
    "root": "abc123..."
  }
}
```

## GuardSpine Integration

### Pre-Audit Hook

Introspection runs automatically before L2+ actions:

```yaml
guardspine:
  pre_audit_hook:
    enabled: true
    applies_to_tiers: ["L2", "L3", "L4"]
    action: "introspect"
    on_fail: "block"
    cache_ttl_seconds: 300
```

### Escalation Rules

```yaml
escalate_when:
  - "evidence_pack.findings.critical_count > 0"
  - "evidence_pack.findings.high_count >= 3"
```

### Evidence Requirements

Every tool invocation MUST produce an evidence pack that passes the rubric:

```yaml
mode_requirements:
  security_audit:
    min_rubric_score: 4.0
  introspection:
    min_rubric_score: 4.0
  context_read:
    min_rubric_score: 3.5
```

## MoltBot Registration

```python
# In MoltBot startup
from rlm_docsync import register

register(moltbot_instance)
```

This registers:
- `rlm_security_audit` tool
- `rlm_introspect` tool
- `rlm_read` tool
- Pre-audit hook for L2+ actions

## Verification

Verify any evidence pack:

```bash
# Check rubric compliance
python evaluate_evidence.py --pack evidence.json --mode security_audit

# Verify hash chain manually
python -c "
import json, hashlib
pack = json.load(open('evidence.json'))
chain = pack['hash_chain']
prev = '0'*64
for entry in chain['entries']:
    h = hashlib.sha256((prev + json.dumps(entry['payload'], sort_keys=True, separators=(',',':'))).encode()).hexdigest()
    assert h == entry['hash'], f'Hash mismatch at index {entry[\"index\"]}'
    prev = h
assert prev == chain['root'], 'Root hash mismatch'
print('✓ Hash chain valid')
"
```

## What This Enables

1. **Infinite Context Without Hallucination** — 10M+ tokens via RLM
2. **Proof-Carrying Reasoning** — Every answer has hash-chained evidence
3. **Self-Verifying Governance** — MoltBot verifies itself before acting
4. **Local, Offline, Replayable** — No cloud dependencies, full audit trail
5. **Evidence-Backed Red-Teaming** — Integrate with Pliny/Promptfoo harness

## License

Apache-2.0

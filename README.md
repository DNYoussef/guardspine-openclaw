# guardspine-openclaw

Deny-by-default governance plugin for [OpenClaw](https://github.com/nickarora/openclaw). Gates every tool call through L0-L4 risk tiers with hash-chained evidence packs, a 3-model local council, and remote human approval.

```
User Request
    |
    v
+-------------------+
| OpenClaw Agent    |
| (any model)       |
+--------+----------+
         |
         v
+-------------------+     +-------------------+
| GuardSpine Plugin |---->| Risk Classifier   |
| before_tool_call  |     | L0-L4 tier        |
+--------+----------+     +-------------------+
         |
    +----+----+----+----+
    |    |    |    |    |
   L0   L1   L2   L3   L4
   no   log  evidence  council  council
   op   only pack     3-model  + human
                      vote     approval
```

## The Problem

AI agents with tool access (shell, files, network) need governance that scales with risk. A greeting should flow freely. A `rm -rf` should require multi-model review. A credential change should require human sign-off. This plugin resolves the tension between autonomy and oversight by gating on risk and blast radius.

## Risk Tiers

| Tier | Gate | Example Tools | Latency |
|------|------|---------------|---------|
| **L0** | No-op | `sequentialthinking`, `memory_search` | 0ms |
| **L1** | Log only | `rlm_read`, `web_search` | <1ms |
| **L2** | Evidence pack | `bash`, `apply_patch`, `send_message` | <1ms |
| **L3** | 3-model council | `rm -rf`, `curl`, `npm install` | 30-60s |
| **L4** | Council + human | `credential_access`, `chmod 777` | Manual |

Bash commands are dynamically escalated based on content (regex pattern matching on destructive/network/credential patterns).

## Install

```bash
# Clone into OpenClaw extensions
cd ~/.openclaw/extensions
git clone https://github.com/DNYoussef/guardspine-openclaw guardspine

# Add to openclaw.json
# Under "plugins": add "guardspine"
```

### Requirements

- **OpenClaw** v2026.1.x+
- **Ollama** running locally (for L3 council)
- **3 models pulled** (6GB+ VRAM, runs sequentially):

```bash
ollama pull qwen3:8b
ollama pull falcon3:7b
ollama pull qwen2.5-coder:7b
```

### Configuration

In `~/.openclaw/openclaw.json`, add under `plugins`:

```json
{
  "guardspine": {
    "enforcement_mode": "audit",
    "council_endpoint": "http://localhost:11434"
  }
}
```

Modes:
- `audit` - Log all decisions, block nothing (start here)
- `enforce` - Active gating with council and approval
- `disabled` - Plugin loaded but inactive

## How It Works

### Evidence Packs

Every L2+ tool call produces a SHA-256 hash-chained evidence entry. At session end, the full pack is written to `~/.openclaw/guardspine-logs/evidence-pack-{session}.json`. Each entry links to the previous via `chain_hash`, making the audit trail tamper-evident.

### L3 Council

Three Ollama models run sequentially (VRAM-safe, one at a time with unload between):

| Auditor | Model | Weight | Role |
|---------|-------|--------|------|
| A | `qwen3:8b` | 0.40 | Primary Evaluator |
| B | `falcon3:7b` | 0.35 | Technical Verifier |
| C | `qwen2.5-coder:7b` | 0.25 | Code Auditor |

Each scores 5 dimensions (0-5): prompt injection resistance, blast radius, reversibility, secrets exposure, intent clarity. Aggregation is deterministic: any FAIL = FAIL, any ESCALATE = ESCALATE, 2+ PASS = PASS.

### L4 Approval

When a tool call hits L4, the plugin writes a pending approval request to `~/.openclaw/guardspine-logs/dev_inbox/`. The agent is blocked until a human writes `APPROVE {id}` (via the `guardspine_approve` tool or the dev_inbox file).

## Ecosystem

This plugin connects to the broader GuardSpine ecosystem:

| Repository | Purpose | Integration |
|------------|---------|-------------|
| [guardspine-spec](https://github.com/DNYoussef/guardspine-spec) | Evidence bundle specification v1.0 | Evidence pack format |
| [guardspine-verify](https://github.com/DNYoussef/guardspine-verify) | Offline CLI verification | Verify evidence packs offline |
| [guardspine-kernel](https://github.com/DNYoussef/guardspine-kernel) | Verification engine | Seal and validate artifacts |
| [guardspine-local-council](https://github.com/DNYoussef/guardspine-local-council) | Multi-model council library | Council voting logic |
| [guardspine-adapter-webhook](https://github.com/DNYoussef/guardspine-adapter-webhook) | Webhook delivery | Slack/Teams/Discord notifications |
| [guardspine-connector-template](https://github.com/DNYoussef/guardspine-connector-template) | Connector SDK | Build custom integrations |
| [n8n-nodes-guardspine](https://github.com/DNYoussef/n8n-nodes-guardspine) | n8n workflow nodes | Orchestrate approval flows |
| [codeguard-action](https://github.com/DNYoussef/codeguard-action) | GitHub Actions | CI/CD governance |
| [rlm-docsync](https://github.com/DNYoussef/rlm-docsync) | Proof-carrying documentation | Evidence-backed context reading |

## Included Components

### `plugin.js` - Core Plugin

The OpenClaw extension. Hooks into `before_tool_call`, `before_agent_start`, `after_tool_call`, and `agent_end`. Provides 3 tools: `guardspine_status`, `guardspine_audit_log`, `guardspine_approve`.

### `evidence-evaluator/` - L3 Council Rubric

- `guardspine-evidence-rubric.yaml` - 5-dimension scoring rubric with hard fail conditions
- `evaluate_evidence.py` - Runs 3 auditors against evidence packs, deterministic aggregation
- Sample packs for testing

### `rlm-docsync/` - Proof-Carrying Cognition

- `rlm_docsync.py` - 3-mode plugin: security audit, introspection, context reader
- `rlm-docsync-plugin.yaml` - OpenClaw manifest with governance tier mappings
- RLM context virtualization for 10M+ token navigation

### `redteam/` - Adversarial Testing Harness

- `promptfooconfig.yaml` - 310+ attack tests (Pliny L1B3RT4S jailbreaks, prompt injection, shell injection, RBAC bypass)
- `regression.yaml` - Known vulnerability regression tests
- `run_harness.py` - Orchestration with continuous hardening mode
- `providers/guardspine_provider.py` - Tests through the full governance stack

## Quick Start

```bash
# 1. Install
cd ~/.openclaw/extensions
git clone https://github.com/DNYoussef/guardspine-openclaw guardspine

# 2. Start in audit mode (safe, logs only)
# Edit openclaw.json: "guardspine": {"enforcement_mode": "audit"}

# 3. Restart gateway
openclaw gateway

# 4. Watch the logs
tail -f ~/.openclaw/guardspine-logs/guardspine-$(date +%Y-%m-%d).jsonl

# 5. Run red team smoke test
cd ~/.openclaw/extensions/guardspine/redteam
pip install requests
PYTHONIOENCODING=utf-8 python run_harness.py --quick

# 6. When satisfied, switch to enforce mode
# Edit openclaw.json: "guardspine": {"enforcement_mode": "enforce"}
```

## Tools Provided

| Tool | Description |
|------|-------------|
| `guardspine_status` | Query governance mode, evidence summary, classify a tool's risk tier |
| `guardspine_audit_log` | Read recent governance decisions with tier filtering |
| `guardspine_approve` | Approve or deny a pending L4 action by approval ID |

## License

Apache-2.0

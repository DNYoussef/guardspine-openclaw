# GuardSpine Quick Start

Get AI governance running in 5 minutes.

## What is GuardSpine?

GuardSpine gates every AI tool call through risk tiers (L0-L4). Low-risk operations flow freely. High-risk operations require multi-model council votes. Critical operations need human approval.

## Prerequisites

- Node.js 22+
- Git
- Ollama (for local council models)

## Step 1: Install OpenClaw

```bash
npm install -g openclaw
```

## Step 2: Install GuardSpine Plugin

```bash
# Create extensions directory
mkdir -p ~/.openclaw/extensions/guardspine

# Clone the plugin
git clone https://github.com/DNYoussef/guardspine-openclaw.git ~/.openclaw/extensions/guardspine
```

## Step 3: Install Council Models (Optional but Recommended)

```bash
# Install 3 local models for L3 council voting
ollama pull qwen3:8b
ollama pull qwen3-coder:30b
ollama pull mistral:7b
```

Skip this if you only want L0-L2 (no council votes).

## Step 4: Create Allowlist (Optional)

Create `~/.openclaw/guardspine-allowlist.json`:

```json
{
  "version": "1.0.0",
  "allowed_path_prefixes": [
    "/tmp/",
    "~/.openclaw/workspace/",
    "~/.openclaw/sandbox/"
  ],
  "patterns": []
}
```

This lets certain paths bypass L4 approval.

## Step 5: Start OpenClaw

```bash
openclaw gateway start
```

You should see:
```
[guardspine] Plugin registered: mode=enforce, 4 hooks + 4 tools
```

## Step 6: Test It

```bash
# This should work (L0 - safe read)
openclaw run "What is 2+2?"

# This triggers L2 (evidence pack)
openclaw run "List files in /tmp"

# This triggers L3 council (high-risk)
openclaw run "Delete the file test.txt"
```

## Risk Tiers

| Tier | Risk Level | What Happens |
|------|------------|--------------|
| L0 | None | Pass through, no logging |
| L1 | Low | Log only |
| L2 | Medium | Create evidence pack (SHA256 chain) |
| L3 | High | 3-model council vote required |
| L3.5 | Deadlock | Opus tie-breaker (if council splits) |
| L4 | Critical | Council + human approval required |

## Discord Approval (Optional)

To enable Discord-based human approval for L4:

1. Create a Discord bot at https://discord.com/developers
2. Add token to `~/.openclaw/openclaw.json`:

```json
{
  "channels": {
    "discord": {
      "token": "YOUR_BOT_TOKEN",
      "approval_channel": "CHANNEL_ID"
    }
  }
}
```

3. Approve L4 requests by reacting with :thumbsup: or :thumbsdown:

## Useful Tools

GuardSpine adds these tools to your agent:

| Tool | Purpose |
|------|---------|
| `memory_status` | Check context window usage |
| `request_approval` | Request human approval |
| `submit_evidence` | Submit evidence for audit |
| `check_governance` | Check current governance state |

## Troubleshooting

**"Plugin not found"**
- Check plugin is in `~/.openclaw/extensions/guardspine/`
- Check `plugin.js` exists

**"Council timeout"**
- Make sure Ollama is running: `ollama serve`
- Check models are installed: `ollama list`

**"L4 approval pending forever"**
- Check Discord bot has permissions
- React with :thumbsup: to approve

## Project Structure

```
~/.openclaw/
  extensions/
    guardspine/
      plugin.js           # Main plugin
      openclaw.plugin.json # Plugin metadata
  guardspine-allowlist.json # Bypass rules
  guardspine-pending.json   # Pending approvals
  guardspine-logs/          # Audit logs
  audit-trail/              # Evidence packs
```

## Links

- [GuardSpine Spec](https://github.com/DNYoussef/guardspine-spec) - Protocol specification
- [GuardSpine Kernel (TS)](https://github.com/DNYoussef/guardspine-kernel) - Hash chain library
- [GuardSpine Kernel (Python)](https://github.com/DNYoussef/guardspine-kernel-py) - Python port
- [OpenClaw](https://github.com/openclaw/openclaw) - The agent framework

## License

Apache-2.0

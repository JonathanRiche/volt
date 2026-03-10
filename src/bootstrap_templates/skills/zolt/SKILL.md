---
title: "Volt Zolt Skill"
summary: "How to use Volt, its .volt workspace, and config safely."
read_when:
  - Working inside a .volt workspace
  - Editing volt.json or telegram/gateway state files
  - Running zolt through Volt
---

# Volt + Zolt Skill

This skill explains how Volt stores state and how zolt should work with it.

## Workspace Root

Default Volt home is `~/.volt` unless `--home` overrides it.

Important files:

- `volt.json` - main config for telegram tokens, gateway auth, and zolt provider/model defaults.
- `credentials/telegram-zolt-sessions.json` - chat to zolt session mapping.
- `credentials/telegram-zolt-metadata.json` - last provider/model + usage metadata for `/status`.
- `credentials/telegram-allowFrom.json` - Telegram allow list.
- `telegram/update-offset-<account>.json` - Telegram polling offset state.
- `agents/main/sessions/sessions.json` - local agent session history.

## Model Routing

Volt owns model/provider selection for zolt dispatch.

- Use `volt model set --provider <provider> --model <model>` for default account.
- Use `volt model set --account <id> --provider <provider> --model <model>` for named accounts.
- Use `volt model show [--account <id>]` to inspect active config.

Config keys:

- Default account: `zolt.provider`, `zolt.model`
- Named account: `zolt.accounts.<account>.provider`, `zolt.accounts.<account>.model`

## Telegram Runtime

Run with defaults:

```bash
volt --telegram --zolt
```

Named account:

```bash
volt --telegram --zolt --account work
```

Useful slash commands in Telegram:

- `/settings` - show account/runtime settings and model controls.
- `/status` - runtime status
- `/sessions` - active mapped zolt session
- `/reset` - clear mapped zolt session
- `/models` - list models for configured providers only
- `/model` - show model config
- `/model <provider> <model>` - set provider+model for this account
- `/model <model>` - set model using currently configured provider

## ACP Runtime

Run Volt as an ACP server over stdio:

```bash
volt acp
```

Optional overrides:

```bash
volt acp --account work --zolt-path /path/to/zolt --zolt-output json
```

Supported ACP methods:

- `initialize`
- `session/new`
- `session/load`
- `session/prompt`
- `session/cancel`

`session/prompt` sends `session/update` chunks and maps ACP session ids to zolt sessions for the lifetime of the `volt acp` process.

## Harness Routing (Codex/OpenCode)

If a user asks to run through a Codex/OpenCode-style harness, use ACP instead of ad-hoc shell dispatch.

- Start Volt in ACP mode: `volt acp`
- Point the harness ACP client to the `volt acp` stdio process.
- Keep model/provider routing in Volt config via `volt model set ...`.
- Keep Telegram/gateway flows separate; ACP is the harness bridge.

Default rule:

- "run codex", "run opencode", or similar harness requests => use ACP (`volt acp`).

Execution policy for harness checks:

- Do not ask for "run now" follow-ups when execution is possible.
- Use one blocking ACP smoke test command and return pass/fail with actual output.
- Do not reply with internal orchestration status (in-progress wrappers, missing runner sessions, flush notes).
- If something fails, return a concise error and the exact next command to retry.

## Editing Rules

- Prefer editing `volt.json` through `volt model set` and `volt telegram setup` when possible.
- Use `volt docs sync` to refresh managed `.volt` markdown guidance templates.
- If editing JSON directly, preserve valid JSON and existing unknown keys.
- Do not delete session mapping files unless reset is intentional.
- Keep account IDs normalized (`default`, `work`, `prod-team`, etc.).

## Sanity Checks

After changing config:

1. Run `volt model show`.
2. Restart telegram worker: `volt telegram restart [--account <id>]`.
3. Verify in chat with `/settings` and `/status`.

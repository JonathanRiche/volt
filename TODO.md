# Volt TODO

## What we’ve tackled in this repo

- `volt init` command:
  - `--home`, `--source`, `--mirror-volt`, `--force`.
  - Creates a `.volt` workspace and seeds required directories/files.
  - Mirrors selected files from source layout when enabled.
- `volt telegram setup` command:
  - Sets bot token in `volt.json` for default or normalized account IDs.
  - Supports `--allow-from` allowlist storage.
  - Writes pairing/update-offset state files.
- `volt --telegram` command:
  - Polls Telegram updates from configured token.
  - Supports `--token`, `--account`, `--home`, `--dispatch`, `--poll-ms`.
  - Supports `--zolt` and `--zolt-path` dispatch modes.
  - Resolves command placeholders (`{message}`, `{text}`, `{chat_id}`, `{account}`, `{session}`).
  - Bootstraps and persists `telegram:<account>:<chat_id>` -> zolt `session_id` mappings in `credentials/telegram-zolt-sessions.json`.
  - Recreates stale zolt sessions when `session not found` is returned.
- Local stdio passthrough mode when `volt` is run with no arguments.
- Config/state discovery:
  - `--home` and `VOLT_HOME`, `VOLT_STATE_DIR`, `VOLT_CONFIG_PATH`.
- Bundled zolt support in `build.zig`:
  - local source auto-discovery.
  - optional dependency install.
- `volt gateway` command:
  - runs a local HTTP `/health`, `/gateway/health`, `/gateway/status`, and `/invoke` server.
  - supports default dispatch via `--zolt` and `--dispatch`.
  - supports token auth resolution (`--auth-token`, env, config).
  - includes parser and route/payload tests.
- Gateway service process control:
  - `volt gateway install|start|stop|restart|status|uninstall` implemented.
  - Linux and macOS service definitions are generated and executed via system service tools.
- Initial compatibility docs (`README.md`, `USAGE.md`), tests for parser/dispatch helpers.

## Reference parity gaps to implement

The original reference has a much broader surface. The items below are not yet in Volt:

- Core command surface:
- `setup`, `onboard`, `configure`, `config`, `doctor`, `dashboard`, `reset`,
    `uninstall`, `update`, `status`, `health`, `gateway`, `pairing`, `plugins`,
    `approvals`, `security`, `memory`, `sessions`, `logs`, `system`,
    `models`, `nodes/devices/browser/cron/webhooks/hardware tools`, `skills`,
    `acp`, `tui`, and `voicecall`.
- Runtime model:
  - Service tests still lack integration coverage against real service managers.
  - No device/channel/node orchestration loop.
  - No session daemoning / remote WS protocol.
- Channel coverage:
  - Telegram-only today; the reference also includes WhatsApp, Slack, Discord, Google Chat,
    Signal, Teams, Matrix, iMessage/macOS bridges, iOS/Android nodes, etc.
- Tooling and automation:
  - No browser tooling, cron/webhook runtime, hooks, pairing approvals workflow,
    DNS helpers, sandbox/proxy controls, install/uninstall plugin/tool stack.
- UX/admin parity:
  - No global CLI output formatting/profile modes (`--json`, `--plain`, `--no-color`, dev/profile profiles).
  - No update-channel or onboarding wizard.

## Testing TODOs (for parity + reliability)

- Add Volt CLI/behavior tests for:
  - reference-style command flags and aliases as we add them.
  - Telegram poller behavior under malformed updates and empty response handling.
  - Allowlist and token-resolution precedence end-to-end.
  - `--zolt` auto-discovery and dispatch validation failures.
  - Telegram->zolt session bootstrap/recovery with real process execution and stale mapping repair.
- Add optional integration tests (guarded/feature-toggled) for:
  - real Telegram API mocking/fake server response flow.
  - `volt init` file layout and mirror behavior.
  - local stdio mode and command passthrough.

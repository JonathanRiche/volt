# Volt

`volt` is a lightweight Zig CLI that mirrors a subset of OpenClaw behavior:

- initialize a compatible workspace (`volt init`)
- setup telegram credentials (`volt telegram setup`)
- run the telegram gateway loop (`volt --telegram`)
- keep the default local stdio flow when run with no arguments

## Quick start

Build and run from this repo:

```bash
zig build
zig build run -- --help
```

## Commands

### `volt init`

Create the OpenClaw-style workspace under `~/.openclaw` by default, or under `--home`.

```bash
volt init [--mirror-openclaw] [--source <path>] [--home <path>] [--force]
```

Flags:

- `--home <path>`: override the OpenClaw state dir.
- `--source <path>`: seed from an existing OpenClaw checkout (defaults to any checked-in template in this repo).
- `--mirror-openclaw`: copy extra known OpenClaw files if present in the source path.
- `--force`: overwrite existing files where supported.

## `volt telegram setup`

Write/refresh `openclaw.json` with a telegram token and create Telegram state files.

```bash
volt telegram setup --token <token> [--account <id>] [--allow-from <chat_id>]... [--home <path>] [--force]
```

Behavior:

- token is required and is written to:
  - `channels.telegram.botToken` when account is `default`
  - `channels.telegram.accounts.<account>.botToken` for non-default accounts
- gateway auth token is always set to `volt-gateway-token`
- `credentials/telegram-allowFrom.json` is written from `--allow-from` values
- default offset file is written under `telegram/` (per account).

## `volt --telegram`

Run the telegram gateway command loop.

```bash
volt --telegram [--token <token>] [--account <id>] [--home <path>] [--dispatch <command>] [--poll-ms <ms>]
```

Behavior:

- `--token` overrides config/env for this run.
- if omitted, token resolution follows OpenClaw-compatible precedence:
  - per-account `tokenFile` / `botToken`
  - default `tokenFile` / `botToken`
  - `TELEGRAM_BOT_TOKEN`
- incoming messages are checked against `credentials/telegram-allowFrom.json`
- each message dispatches to shell command text via `--dispatch` (if provided), defaulting to `zolt` behavior only if you pass it.

## Env vars

- `OPENCLAW_STATE_DIR`, `CLAWDBOT_STATE_DIR`
- `OPENCLAW_CONFIG_PATH`, `CLAWDBOT_CONFIG_PATH`
- `TELEGRAM_BOT_TOKEN`

Legacy aliases are intentionally supported for compatibility.

## Local (no-argument) mode

Running `volt` with no arguments launches the local stdio mode:

```bash
volt
```

This keeps behavior close to existing stdio-style CLI flows and executes each input line as a shell command.

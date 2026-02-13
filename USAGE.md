# Volt Usage

## Commands

### `volt init`

Create the OpenClaw-compatible workspace under `~/.openclaw` (or `--home`).

```bash
volt init [--mirror-openclaw] [--source <path>] [--home <path>] [--force]
```

- `--home <path>`: override state directory.
- `--source <path>`: seed from an existing OpenClaw checkout.
- `--mirror-openclaw`: copy extra files if present in source.
- `--force`: overwrite existing files.

### `volt telegram setup`

Set up Telegram config and state for the default or named account.

```bash
volt telegram setup --token <token> [--account <id>] [--allow-from <chat_id>]... [--home <path>] [--force]
```

Notes:

- default account (`default`) writes `channels.telegram.botToken`.
- non-default account writes `channels.telegram.accounts.<account>.botToken`.
- writes `credentials/telegram-allowFrom.json` and `credentials/telegram-pairing.json`.

### `volt --telegram`

Run the Telegram polling loop.

```bash
volt --telegram [--token <token>] [--account <id>] [--home <path>] [--dispatch <command>] [--poll-ms <ms>]
```

If `--token` is omitted, token resolution is:

1. account-specific `channels.telegram.accounts.<account>.tokenFile`
2. account-specific `channels.telegram.accounts.<account>.botToken`
3. default `channels.telegram.tokenFile`
4. default `channels.telegram.botToken`
5. `TELEGRAM_BOT_TOKEN`

### No args

Running `volt` with no args starts local command passthrough mode (read a line from stdin, execute it as shell command, print output).

## Env aliases

- `OPENCLAW_STATE_DIR` / `CLAWDBOT_STATE_DIR`
- `OPENCLAW_CONFIG_PATH` / `CLAWDBOT_CONFIG_PATH`
- `TELEGRAM_BOT_TOKEN`

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
volt --telegram [--token <token>] [--account <id>] [--home <path>] [--dispatch <command>] [--zolt] [--poll-ms <ms>]
```

`--dispatch` runs as parsed argv tokens, not shell text.

`--zolt` enables a preset dispatch mapping to:

`zolt --session {session} --message {message}`

`--zolt-path <path>` sets the exact executable used for zolt mode, overriding `zolt` in PATH.
You can also set `VOLT_ZOLT_PATH`.

`--zolt` resolves command precedence in this order:

1. `--zolt-path` / `VOLT_ZOLT_PATH` override
2. bundled `zolt` installed next to `volt`
3. `zolt` on `PATH`

Available placeholders in `--dispatch` values:

- `{message}` / `{text}`: incoming Telegram message text
- `{chat_id}`: Telegram chat id
- `{account}`: normalized account id
- `{session}`: derived `telegram:<account>:<chat_id>` session key

If `{message}`/`{text}` is not present, Volt appends the message text as the final argv entry.

If `--token` is omitted, token resolution is:

1. account-specific `channels.telegram.accounts.<account>.tokenFile`
2. account-specific `channels.telegram.accounts.<account>.botToken`
3. default `channels.telegram.tokenFile`
4. default `channels.telegram.botToken`
5. `TELEGRAM_BOT_TOKEN`

Example:

```bash
volt --telegram --dispatch "zolt --session {session} --message {message}"
```

or equivalent:

```bash
volt --telegram --zolt
```

### No args

Running `volt` with no args starts local command passthrough mode (read a line from stdin, execute it as shell command, print output).

## Env aliases

- `OPENCLAW_STATE_DIR` / `CLAWDBOT_STATE_DIR`
- `OPENCLAW_CONFIG_PATH` / `CLAWDBOT_CONFIG_PATH`
- `TELEGRAM_BOT_TOKEN`
- `VOLT_ZOLT_PATH`

## Build flags

- `-Dwith-zolt` (default false): build and install zolt as part of `zig build install`.
- `-Dzolt-source=<path>`: use a local zolt checkout (default `../zig-ai` if present).
- `-Dzolt-dependency=<name>`: use dependency named in `build.zig.zon` (defaults to `zolt`).
- If you keep a `zolt` checkout at `../zig-ai`, Volt auto-discovers it; otherwise it uses the dependency.

## Multi-account examples

Use `--account` to configure and run separate Telegram bots/accounts against one state dir.

### Setup default account

```bash
volt telegram setup --home ~/.openclaw --token "<default_bot_token>"
```

This writes:
- `channels.telegram.botToken` for the default account.
- `telegram/update-offset-default.json` for runtime state.

### Setup a named account

```bash
volt telegram setup --home ~/.openclaw --account work --token "<work_bot_token>"
```

This writes:
- `channels.telegram.accounts.work.botToken` for the normalized account ID.
- `telegram/update-offset-work.json` for runtime state.

### Run default account in gateway mode

```bash
volt --telegram --home ~/.openclaw
```

### Run a named account in gateway mode

```bash
volt --telegram --home ~/.openclaw --account work
```

### Use account-specific allow list while keeping separate default allow list

```bash
volt telegram setup --home ~/.openclaw --account work --token "<work_bot_token>" --allow-from 111111111 --allow-from 222222222
```

This stores the allowlist in the shared `credentials/telegram-allowFrom.json` used by gateway runtime.

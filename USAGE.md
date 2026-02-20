# Volt Usage

## Commands

### Install

```bash
mkdir -p "$HOME/.local/bin"
zig build install -Doptimize=ReleaseFast --prefix "$HOME/.local"
```

This installs the executable as `volt` (for example at `~/.local/bin/volt`).

To bundle a local `zolt` checkout/dependency at install time:

```bash
zig build install -Dwith-zolt=true -Doptimize=ReleaseFast --prefix "$HOME/.local"
```

Ensure `~/.local/bin` is on your `PATH`.

### `volt init`

Create the Volt workspace under `~/.volt` by default (or `--home`).

```bash
volt init [--mirror-volt] [--source <path>] [--home <path>] [--force]
```

- `--home <path>`: override state directory.
- `--source <path>`: seed from an existing Volt checkout.
- `--mirror-volt`: copy extra files if present in source.
- `--force`: overwrite existing files.

`volt init` also seeds workspace guidance markdown templates by default:
`AGENTS.md`, `BOOTSTRAP.md`, `SOUL.md`, `TOOLS.md`, `IDENTITY.md`, `USER.md`, and `HEARTBEAT.md`.

### `volt telegram setup`

Set up Telegram config and state for the default or named account.

```bash
volt telegram setup --token <token> [--account <id>] [--allow-from <chat_id>]... [--home <path>] [--force]
```

Notes:

- default account (`default`) writes `channels.telegram.botToken`.
- non-default account writes `channels.telegram.accounts.<account>.botToken`.
- writes `credentials/telegram-allowFrom.json` and `credentials/telegram-pairing.json`.
- `--allow-from` is optional. If omitted, Volt allows all chats.

Tip:

```bash
volt telegram setup --home ~/.volt --token "<bot_token>"
```

### `volt --telegram`

Run the Telegram polling loop.

```bash
volt --telegram [--token <token>] [--account <id>] [--home <path>] [--dispatch <command>] [--zolt] [--poll-ms <ms>]
```

`--dispatch` runs as parsed argv tokens, not shell text.

`--zolt` enables a preset dispatch mapping to:

`zolt run --session {session} {message}` plus your configured message handling.

Setup does not require chat ids. `--allow-from` is optional and no account-specific chat ids are configured in setup.

Telegram chat ids are derived from incoming messages at runtime and mapped to zolt sessions in:

- `<home>/credentials/telegram-zolt-sessions.json`

Mapping key is `telegram:<account>:<chat_id>`.

On a first message for a chat, Volt bootstraps a fresh zolt session by prepending a context block that explains:
- workspace layout and key `.volt` files
- session/state file locations
- markdown guidance files in `.volt`.

Volt sends responses as MarkdownV2 when it detects markdown structure (lists, headings, inline code, fences, links), and falls back to plain text if Telegram rejects the formatted payload.

Slash commands are available in Telegram and are registered as command menu entries:

- `/help` - show quick usage
- `/commands` - list available commands
- `/sessions` - show active zolt session for this chat
- `/status` - show runtime status
- `/reset` - clear this chat's zolt session mapping
- `/models` - run `zolt models` (requires `--zolt`)

Run `zolt run -h` to check supported flags (for example `-s` / `--session`).

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
- `{session}`: derived session key (in priority order):
  - `telegram:<account>:<chat_id>` for polling mode

If `{message}`/`{text}` is not present, Volt appends the message text as the final argv entry.

Example gateway↔zolt call flow:

```bash
curl -H "Authorization: Bearer volt-gateway-token" \
  -H "Content-Type: application/json" \
  -d '{"message":"ping","chat_id":123,"account":"work","session":"gateway:work:123"}' \
  http://127.0.0.1:18789/invoke
```

With `--zolt`, this produces the command:

```bash
zolt run --session gateway:work:123 ping
```

If `session` is omitted, Volt will generate `gateway:work:123` from the account and chat_id.

If `--token` is omitted, token resolution is:

1. account-specific `channels.telegram.accounts.<account>.tokenFile`
2. account-specific `channels.telegram.accounts.<account>.botToken`
3. default `channels.telegram.tokenFile`
4. default `channels.telegram.botToken`
5. `TELEGRAM_BOT_TOKEN`

Example:

```bash
volt --telegram --dispatch "zolt -s {session} {message}"
```

or equivalent:

```bash
volt --telegram --zolt
```

### `volt gateway`

Start a tiny HTTP gateway for text-message style clients.

```bash
volt gateway [--home <path>] [--bind <ip>] [--port <port>] [--account <id>] [--dispatch <command>] [--zolt] [--zolt-path <path>] [--auth-token <token>]
```

Defaults:

- Workspace path: `~/.volt`
- Bind: `127.0.0.1`
- Port: `18789`
- Default dispatch:
- `zolt run --session {session} {message}` when `--zolt` is used
  - otherwise no dispatch (`--dispatch` required for non-zolt mode)

Auth:

- `--auth-token` is resolved first, then `VOLT_GATEWAY_TOKEN`, then `gateway.auth.token` in `volt.json`.
- Default fallback token is `volt-gateway-token`.
- The request is authorized via either:
  - `Authorization: Bearer <token>`
  - `X-Volt-Gateway-Token: <token>`

HTTP paths:

- `GET /health` or `GET /gateway/health`: readiness check.
- `GET /gateway/status`: runtime and config info.
- `POST /invoke`: dispatch a payload.

`/invoke` expects JSON body containing one of:

- `message`
- `text`

Optional fields:

- `chat_id`
- `account`
- `session`

Example:

```bash
curl -H "Authorization: Bearer volt-gateway-token" \
  -H "Content-Type: application/json" \
  -d '{"message":"ping","chat_id":123}' \
  http://127.0.0.1:18789/invoke
```

### `volt gateway` service

Manage the gateway as a persistent background process with the platform service manager:

```bash
volt gateway install [--home <path>] [--bind <ip>] [--port <port>] [--account <id>] [--dispatch <command>] [--zolt] [--zolt-path <path>] [--auth-token <token>]
volt gateway start [--home <path>] [--bind <ip>] [--port <port>] [--account <id>] [--dispatch <command>] [--zolt] [--zolt-path <path>] [--auth-token <token>]
volt gateway stop [--home <path>] [--bind <ip>] [--port <port>] [--account <id>] [--dispatch <command>] [--zolt] [--zolt-path <path>] [--auth-token <token>]
volt gateway restart [--home <path>] [--bind <ip>] [--port <port>] [--account <id>] [--dispatch <command>] [--zolt] [--zolt-path <path>] [--auth-token <token>]
volt gateway status [--home <path>] [--bind <ip>] [--port <port>] [--account <id>] [--dispatch <command>] [--zolt] [--zolt-path <path>] [--auth-token <token>]
volt gateway uninstall [--home <path>] [--bind <ip>] [--port <port>] [--account <id>] [--dispatch <command>] [--zolt] [--zolt-path <path>] [--auth-token <token>]
```

Notes:

- Linux uses `systemd --user` units under `$XDG_CONFIG_HOME/systemd/user` (or `~/.config/systemd/user`).
- macOS uses `~/Library/LaunchAgents/com.volt.gateway.plist`.
- On macOS, `status` currently reports bootstrap state from `launchctl print`.

### No args

Running `volt` with no args starts local command passthrough mode (read a line from stdin, execute it as shell command, print output).

## Env aliases

- `VOLT_HOME`
- `VOLT_STATE_DIR`
- `VOLT_CONFIG_PATH`
- `TELEGRAM_BOT_TOKEN`
- `VOLT_ZOLT_PATH`
- `VOLT_GATEWAY_TOKEN`
- `VOLT_DEBUG=1` (enable debug logging for zolt command execution and payload snippets)

## Build flags

- `-Dwith-zolt` (default false): build and install zolt as part of `zig build install`.
- `-Dzolt-source=<path>`: use a local zolt checkout (default `../zolt` if present).
- `-Dzolt-dependency=<name>`: use dependency named in `build.zig.zon` (defaults to `zolt`).
- If you keep a `zolt` checkout at `../zolt`, Volt auto-discovers it; otherwise it uses the dependency.

## Multi-account examples

Use `--account` to configure and run separate Telegram bots/accounts against one state dir.

### Setup default account

```bash
volt telegram setup --home ~/.volt --token "<default_bot_token>"
```

This writes:
- `channels.telegram.botToken` for the default account.
- `telegram/update-offset-default.json` for runtime state.

### Setup a named account

```bash
volt telegram setup --home ~/.volt --account work --token "<work_bot_token>"
```

This writes:
- `channels.telegram.accounts.work.botToken` for the normalized account ID.
- `telegram/update-offset-work.json` for runtime state.

### Run default account in gateway mode

```bash
volt --telegram --home ~/.volt
```

### Run a named account in gateway mode

```bash
volt --telegram --home ~/.volt --account work
```

### Run a local gateway with zolt dispatch

```bash
volt gateway --home ~/.volt --zolt --auth-token my-secret-token
```

Then configure clients to POST to `http://127.0.0.1:18789/invoke`.

### Use account-specific allow list while keeping separate default allow list

```bash
volt telegram setup --home ~/.volt --account work --token "<work_bot_token>" --allow-from 111111111 --allow-from 222222222
```

This stores the allowlist in the shared `credentials/telegram-allowFrom.json` used by gateway runtime.

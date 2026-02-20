# volt

Volt is a lightweight Zig CLI for local
std-IO execution and Telegram gateway setup/runtime.

## Quick build

```bash
zig build
```

Run the CLI:

```bash
zig build run -- --help
```

Install release binary as `volt`:

```bash
mkdir -p "$HOME/.local/bin"
zig build install -Doptimize=ReleaseFast --prefix "$HOME/.local"
```

Then run:

```bash
volt --help
```

Bundle `zolt` during install if you want Volt to ship its own dispatch dependency:

```bash
zig build install -Dwith-zolt=true -Doptimize=ReleaseFast --prefix "$HOME/.local"
```

By default, Volt uses `~/.volt` as the workspace root (or `--home`).

Initialize workspace layout with:

```bash
volt init --home ~/.volt
```

### Telegram setup (token only)

Use token-only setup like OpenClaw:

```bash
volt telegram setup --home ~/.volt --token "<bot_token>"
```

`--allow-from` is optional. If omitted, Volt allows all chats to use the bot.

No `--chat-id` is needed for setup; chat ids are discovered from incoming Telegram messages.

Volt also registers a Telegram slash-command menu (`/help`, `/commands`, `/sessions`, `/status`, `/reset`, `/models`) when the gateway starts, so you can discover commands in the Telegram UI.

In Telegram, send:
- `/help` to view the menu summary
- `/commands` for the full command list
- `/sessions` to show the mapped zolt session for this chat
- `/status` to show runtime details
- `/reset` to clear the mapped zolt session
- `/models` to run the zolt model command (requires `--zolt`)

To get your chat id, send a message to the bot and inspect `chat.id` from:

```bash
curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates"
```

Enable debug tracing when needed:

```bash
VOLT_DEBUG=1 volt --telegram --home ~/.volt --zolt
```

Debug output prints the exact zolt command line and stdout/stderr snippets in stderr.

Volt can bundle a local `zolt` checkout so `--zolt` can run without a preinstalled system `zolt` binary. When bundling is enabled, Volt prefers:

1. local source via `-Dzolt-source=...` (or `../zolt` if present),
2. dependency named `zolt` declared in `build.zig.zon` (default points to `github.com/JonathanRiche/zolt`).

Options:

- `-Dwith-zolt=true` to enable bundling (defaults to `false`).
- `-Dzolt-source=<path>` to point at a local zolt source checkout.
- `-Dzolt-dependency=<name>` to override the dependency key in `build.zig.zon` (defaults to `zolt`).
- `--zolt-path` flag or `VOLT_ZOLT_PATH` env var still override any bundled executable.

If you want to refresh the zolt package hash yourself:

```bash
zig fetch --save git+https://github.com/JonathanRiche/zolt
```

## Gateway mode quick start

```bash
zig build run -- gateway --home ~/.volt --port 18789 --zolt
```

Then send a POST to:

```bash
curl -H "Authorization: Bearer volt-gateway-token" \
  -H "Content-Type: application/json" \
  -d '{"message":"hello","chat_id":123}' \
  http://127.0.0.1:18789/invoke
```

With `--zolt`, Volt executes `zolt run --session <session_id> {message}` and stores Telegram chat/session mappings in:

`<home>/credentials/telegram-zolt-sessions.json`

Behavior:

- first message for a chat bootstraps a new zolt session (`zolt run --output json <message>`);
  the first message is auto-prefixed with a `.volt` bootstrap context:
  workspace layout, key state files, and discovered markdown guidance files.
- first successful response writes the returned `session_id` into Volt’s mapping file;
- subsequent messages reuse that mapping via `zolt run --session <session_id> <message>`;
- stale mappings are recreated automatically if zolt returns `session not found`.

Gateway session IDs are resolved as:

- explicit `session` in JSON payload
- else `gateway:<account>:<chat_id>` when `chat_id` is present
- else `gateway:<account>`

### Gateway service commands

Volt can manage the gateway as a background service:

```bash
volt gateway install [--home <path>] [--bind <ip>] [--port <port>] [--account <id>] [--dispatch <command>] [--zolt] [--zolt-path <path>] [--auth-token <token>]
volt gateway start|stop|restart|status|uninstall [--home <path>] [--bind <ip>] [--port <port>] [--account <id>] [--dispatch <command>] [--zolt] [--zolt-path <path>] [--auth-token <token>]
```

Commands:

- `install`: writes the OS service definition and starts the gateway.
- `start`: starts an installed service.
- `stop`: stops a running service.
- `restart`: restarts a service.
- `status`: prints current service status using the native OS service manager.
- `uninstall`: stops and removes the service definition.

This currently integrates with `systemd` (Linux) and `launchd` (macOS).
```

## Documentation

- [`USAGE.md`](USAGE.md) — command usage, flags, and environment variables.

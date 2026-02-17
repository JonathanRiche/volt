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

By default, Volt uses `~/.volt` as the workspace root (or `--home`).

Initialize workspace layout with:

```bash
volt init --home ~/.volt
```

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

## Documentation

- [`USAGE.md`](USAGE.md) — command usage, flags, and environment variables.

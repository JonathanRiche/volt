# volt

Volt is a lightweight Zig CLI that implements a subset of OpenClaw flows for local
std-IO execution and Telegram gateway setup/runtime.

## Quick build

```bash
zig build
```

Run the CLI:

```bash
zig build run -- --help
```

Volt can bundle a local `zolt` checkout so `--zolt` can run without a preinstalled system `zolt` binary. When bundling is enabled, Volt prefers:

1. local source via `-Dzolt-source=...` (or `../zig-ai` if present),
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

## Documentation

- [`USAGE.md`](USAGE.md) — command usage, flags, and environment variables.

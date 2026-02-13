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

Volt can bundle a local `zolt` checkout so `--zolt` can run without a preinstalled system `zolt` binary. By default, it looks for `../zig-ai` from the repo root and installs it next to `volt` during `zig build install`.

Options:

- `-Dwith-zolt=false` to skip bundling.
- `-Dzolt-source=<path>` to point at a different local zolt source checkout.
- `--zolt-path` flag or `VOLT_ZOLT_PATH` env var still override any bundled executable.

## Documentation

- [`USAGE.md`](USAGE.md) — command usage, flags, and environment variables.

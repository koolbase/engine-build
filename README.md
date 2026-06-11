# Koolbase Engine Build

Build pipeline for the custom Flutter engines that power **[Koolbase](https://koolbase.com) Code Push** — over-the-air Dart code updates for Flutter apps.

This repository builds patched Flutter engines, packages them, and publishes them to Koolbase's engine registry so the [Koolbase CLI](https://github.com/koolbase/koolbase-cli) can install a version-matched engine and build apps that support runtime patching.

> **Note:** This repo contains the *engine build and distribution* pipeline only. The runtime patch format, signing, delivery, and rollout logic are part of the Koolbase platform and are not included here.

## What it does

Koolbase Code Push applies Dart updates to a running Flutter app without a full app-store release. That requires a Flutter engine with a small patch hook compiled into the Dart VM. This repo automates building that engine:

1. Fetches the Flutter engine source at a pinned Flutter version
2. Applies the Koolbase patch (`patch_dart_cc.py`) to the Dart VM runtime
3. Builds the engine with `--no-prebuilt-dart-sdk` (so the patched VM is actually used)
4. Packages the engine with its host tools (`gen_snapshot`, `dart-sdk`, `const_finder`, `font-subset`)
5. Uploads the artifact to object storage and registers it with the Koolbase API

The approach builds on the engine-patching technique pioneered by the broader Flutter community.

## Supported versions

| Flutter | Platform | Arch  | Status |
|---------|----------|-------|--------|
| 3.22.3  | macOS    | arm64 | ✅ Published |
| 3.27.4  | macOS    | arm64 | 🚧 In progress |

Android (ELF) and iOS targets are planned. The engine's Flutter version must match the app's Flutter SDK version exactly.

## How it's built

Builds run via GitHub Actions (`.github/workflows/build.yml`) on macOS runners. The workflow is matrix-driven across Flutter versions, runs on manual dispatch and a weekly schedule, and is fully reproducible from the pinned Flutter engine tag.

A build takes roughly 30–40 minutes per engine variant.

## Using a Koolbase engine

You don't build engines yourself to use Koolbase — the CLI installs a pre-built one:

```sh
koolbase engine install 3.22.3
koolbase build macos --release --flutter-sdk /path/to/flutter-3.22.3
```

See the [Koolbase CLI](https://github.com/koolbase/koolbase-cli) and [docs](https://docs.koolbase.com) for the full workflow.

## License

See [LICENSE](LICENSE).

---

Built by [Koolbase](https://koolbase.com) — Backend as a Service for mobile developers.

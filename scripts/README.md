# Scripts

This directory contains helper scripts for code generation and BinExplore
distribution packaging.

## BinExplore publish scripts

The main entry point is:

```bash
scripts/publish-binexplore.sh
```

With no arguments, it publishes for the current machine RID.

Examples:

```bash
scripts/publish-binexplore.sh osx-arm64
scripts/publish-binexplore.sh osx-arm64 linux-x64 win-x64
scripts/publish-binexplore.sh all
NO_RESTORE=true scripts/publish-binexplore.sh all
```

OS-specific wrappers are also available:

```bash
scripts/publish-binexplore-macos.sh
scripts/publish-binexplore-linux.sh
scripts/publish-binexplore-windows.sh
```

Supported RIDs:

```text
osx-arm64
osx-x64
linux-x64
linux-arm64
win-x64
win-arm64
```

Generated outputs are written under:

```text
artifacts/binexplore/
```

Packaging by platform:

- macOS: `.app` bundle and `.zip`
- Linux: directory and `.tar.gz`
- Windows: directory and `.zip`

Useful environment variables:

- `NO_RESTORE=true`: skips `dotnet restore` during publish
- `CONFIGURATION=Release`: overrides the build configuration
- `BUNDLE_ID=org.b2r2.binexplore`: overrides the macOS bundle identifier
- `PUBLISH_ARCHIVES=false`: skips `.zip`/`.tar.gz` archive generation

## Other scripts

- `genOpcode.fsx`
- `intelVEXOpCodes.fsx`

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

## Intel parser generator (`IntelParserGen/`)

Generates the Intel opcode maps as straight-line F# code from
`InstructionTable`: `src/FrontEnd/Intel/LegacyOpcodeMap.fs` (legacy maps) and
`src/FrontEnd/Intel/VEXOpcodeMap.fs` (VEX and EVEX maps). The generated files
are checked in; rerun the generator whenever `Intel.fs`, `InstructionTable.fs`
or the generator changes, and commit the result.

```bash
dotnet build scripts/IntelParserGen -c Release \
  -p:NoOpcodeMaps=true -p:DefineConstants=NoOpcodeMaps
dotnet scripts/IntelParserGen/bin/Release/net10.0/IntelParserGen.dll \
  src/FrontEnd/Intel
```

`NoOpcodeMaps` builds the Intel project without the generated files, so the
generator can be built even when they are missing or broken.

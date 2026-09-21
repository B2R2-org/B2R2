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

## Intel parser generator

`IntelParserGen/` writes the Intel opcode maps as straight-line F# code:
`src/FrontEnd/Intel/DLegacy.fs` (the four legacy maps) and
`src/FrontEnd/Intel/DVex.fs` (the eight VEX and EVEX maps). It reads the
rows and chains of `InstructionTable`, which in turn come from the
`InstructionArrays` that autoparse extracts from the manual, so the tables
stay the single source of truth and the parser never reads them at run
time.

The generated files are checked in. Run the generator again whenever the
tables change (`src/FrontEnd/Intel/Intel.fs` or `InstructionTable.fs`),
then commit the regenerated files with the change:

```bash
dotnet build scripts/IntelParserGen -c Release \
  -p:NoDParser=true -p:DefineConstants=NoDParser
dotnet scripts/IntelParserGen/bin/Release/net10.0/DGen.dll src/FrontEnd/Intel
```

The first command builds the Intel project without the generated files
(`NoDParser`), which is what lets the generator be built when they are
missing or broken. Running the generator twice must give identical files;
`dotnet build`, `dotnet fslint src --strict` and `dotnet test` then verify
the result as for any other change.

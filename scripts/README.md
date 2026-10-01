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

## Intel decode table generator (`IntelTableGen/`)

`IntelTableGen/Intel.json` is the source of the Intel decoder's table: every
decode row of every opcode map, and every opcode with its description, one
per line. `IntelTableGen` generates `src/FrontEnd/Intel/InstructionArrays.fs`
(the rows, packed into primitive arrays) and `src/FrontEnd/Intel/Opcode.fs`
(the enum) from it. Both generated files are checked in and are never edited
by hand: to change the table, change `Intel.json` and regenerate.

```bash
dotnet build scripts/IntelTableGen -c Release
dotnet scripts/IntelTableGen/bin/Release/net10.0/IntelTableGen.dll \
  scripts/IntelTableGen/Intel.json src/FrontEnd/Intel
```

Then regenerate the opcode maps (below), since they are read from the table.

A row is spelled the way `InstructionCore` in `InstructionCore.fs` is: its
opcode byte and map, prefix and REX requirements, ModRM form, operands, and mode
support. An opcode has a `description` (the enum's doc comment; a list where the
manual gives one mnemonic several) and may list `aliases`, names that share its
enum value. Any object may carry a `note` saying why it is the way it is: an
erratum in the manual, an extension the manual does not cover, a decision. The
generator refuses a field it does not know, so a misspelt one stops the build
rather than being ignored. It also reports rows of one slot that differ only in
their operands, which the decoder cannot tell apart; the ones it prints today
are known.

The tool references no B2R2 project, so it builds however broken the files
it is about to replace are.

## Intel parser generator (`IntelParserGen/`)

Generates the Intel opcode maps as straight-line F# code from
`InstructionTable`: `src/FrontEnd/Intel/LegacyOpcodeMap.fs` (legacy maps) and
`src/FrontEnd/Intel/VEXOpcodeMap.fs` (VEX and EVEX maps). The generated files
are checked in; rerun the generator whenever `InstructionArrays.fs`,
`InstructionTable.fs` or the generator changes, and commit the result.

```bash
dotnet build scripts/IntelParserGen -c Release \
  -p:NoOpcodeMaps=true -p:DefineConstants=NoOpcodeMaps
dotnet scripts/IntelParserGen/bin/Release/net10.0/IntelParserGen.dll \
  src/FrontEnd/Intel
```

`NoOpcodeMaps` builds the Intel project without the generated files, so the
generator can be built even when they are missing or broken.

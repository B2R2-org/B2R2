# B2R2 Change Log

## 0.7.0 (2024-03-26)

### Added

- More instruction supports for Intel, AArch64, PPC, and RISCV.
- Support Intel's AT&T syntax.
- Support lazy loading of ELF metadata.
- Handle dwarf action `DW_CFA_same_value`
- Add a new rear-end module, Transformer, which allows users to transform
  binary code into another form.
- Add initial SPARC support.
- Add initial SH4 support.

### Changed

- Use .NET 8 (and F# 8): Our framework is not compatible with prior
  versions of .NET.
- Fix many lifting/parsing bugs for Intel, PPC, AArch64, and RISCV.
- Refactored many modules. Quite many modules/classes have been renamed.
- Improve XML documentation.
- Fix many bugs in the ELF parser.
- Add more unit tests.

## 0.6.0 (2022-06-29)

### Added
- More instruction supports for MIPS
- More instruction supports for Intel
- Added initial support for WASM (thanks to @kimdora)
- Added several more classes in the Core module

### Changed
- Now we use .NET 6 (and F# 6). Our framework is not compatible with .NET 5.
- Fixed MIPS exception frame parser
- Optimized ELF parser for loading callsite tables
- Fixed several bugs in Intel assembler
- Changed ConcEval's interface
- We now avoid using non-standard register sizes, such as `2<rt>` and `3<rt>`;
  we only use sizes multiple of 8 (e.g., 8, 16, 32, 64) or size 1. For those
  register variables whose size is non-standard, e.g., `FTOP` in Intel, we
  assign larger size for the variable.
- Fixed several bugs in Intel and MIPS lifters
- Fixed several bugs in BinFile module (ELF and PE)
- Fixed several bugs in the middle-end (such as tail-call detection logic, etc.)

## 0.5.0 (2021-10-22)

### Added
- Handle ELF exception frames
- Introduce new CFG recovery engine
- Introduce `BinaryPointer` type which allows accessing non-addressable region
  of binary
- Add few more instruction support for x86-64 and ARMv7
- Add a RearEnd.Launcher, which is a .NET CLI tool. You can now install B2R2 by
  typing `dotnet tool install -g B2R2.RearEnd.Launcher`
- Add support for AVR architecture

### Changed
- MiddleEnd has been largely rewritten
- Module and function names largely changed
- Hash-consing is now controlled with build macro `HASHCONS`
- MiddleEnd.ConcEval works with base address changes
- Local IR optimizer has been rewritten
- Optimized data-flow engine

## 0.4.0 (2020-05-02)

### Added
- Add support for Mach-O relocation.
- Add support for COFF object parsing.
- Add support for floating-point operations.
- Add several missing Intel instructions.
- Add a basic dataflow framework.
- Add a partial support for Intel assembler. We will fully implement Intel
  assembler in the next version.

### Changed
- Fix various liting/parsing bugs.
- Fix dominator algorithm bug.
- Fix various BinGraph bugs.
- Improve Web UI performance.
- Fix a zooming bug in the Web UI.
- Update OptParse version.
- Remove manually-encoded Intel constants, which will slightly slow down our
  front-end, but it will improve the maintanence cost.
- Clean up the REPL app, and make it more generic for future use.
- Split MiddleEnd from BinGraph.

## 0.3.1 (2020-01-11)

### Added
- Add boilerplate code for assembler.
- Add Nil to LowUIR to correctly handle cons cells.
- Handle delayed import directory table for PE files.
- Add basic EVM bytecode support.

### Changed
- Fix and refactor simple calculator language implementation.
- Fix Mach section parsing bug.
- Fix ARM translation errors.
- Remove assumption about callee names.
- Fix bitectors to generally handle arbitrary sizes.
- Fix several visualization issues.
- Rewrite completely the web user interface from scratch.

## 0.3.0 (2019-09-28)

### Added
- Add a demangler module for both Itanium and MS types.
- Add `GetNextAddrs` method to `Instruction` type.
- Add several CFG-related lenses to smoothly transform a certain graph into
  another form.
- Start supporting ARMv7 SIMD instructions.
- Add a simple REPL for LowUIR.
- Add a simple calculator language for BinExplorer.

### Changed
- Fix ARMv7 translation errors (close to stable now).
- Fix subtle errors in ELF parsing (GitHub issue #25)
- Fix visualization bugs.
- Redesign many parts in BinGraph modules and their APIs.
- Fix graph building logic to handle ARM/Thumb switching.
- Refactor WebUI modules.
- Update disassembly modules to be able to decompose assembly statements into
  pieces.

## 0.2.1 (2019-07-21)

### Added
- Add a draggable handle between WebUI panes.

### Changed
- Fix various ARMv7 parsing/lifting bugs (not yet stable, but getting there).
- Fix PE header parsing bugs (GitHub issue #23 and #24)
- Fix x86 parsing errors (GitHub issue #22)

## 0.2.0 (2019-07-11)

### Added
- Add a new style in the WebUI.
- Add a search feature in the WebUI.
- Add Mach-O fat file format support.
- Add FileViewer utility.
- Add a batch option to BinExplorer.
- Add a boilerplate assembler module.
- Add the conceval (concrete evaluation) module.

### Changed
- Rewrote BinFile modules.
- Fix bugs in the minimap handling of the WebUI.
- Clean up ROP gadget search.
- Fix a BitVector bug.
- Fix a IntervalSet bug.
- Fix various ARMv7 parsing and lifting bugs (not yet stable).
- Enable the use of external lifter.

## 0.1.1 (2019-03-22)

### Added
- Add IR/SSA-level CFG construction.
- Add boyer-moore search algorithm.
- Add support for several x86/64 instructions.

### Changed
- Fix various IR translation/parsing errors
- Clean up LowUIR side-effect types
- Update authors/contributors

## 0.1.0 (2019-02-22)

First public release.

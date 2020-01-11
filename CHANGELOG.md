# B2R2 Change Log

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

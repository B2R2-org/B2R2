# B2R2 Change Log

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

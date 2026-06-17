# Mach-O test fixtures

Each fixture is a minimal binary; the base executables are built with `clang`,
and the feature fixtures are hand-crafted to isolate one parser capability.

| Fixture | Purpose |
| --- | --- |
| `mach_x64` | Canonical x86-64 executable: metadata, sections, address space, symbols. |
| `mach_x64_stripped` | `mach_x64` with symbols stripped (defined functions gone). |
| `mach_arm64` | Minimal arm64 executable (ARM64 cpu type). |
| `mach_x64_reloc` | Classic relocations (MH_OBJECT): `TryGetRelocatedAddr`. |
| `mach_x64_chained` | Chained fixups (LC_DYLD_CHAINED_FIXUPS): rebase/bind. |
| `mach_x64_dyldinfo` | Legacy dyld info (LC_DYLD_INFO) rebase/bind opcodes. |
| `mach_x64_weakbind` | Weak bind entries. |
| `mach_x64_twolevel` | Two-level namespace bind (resolves the library name). |
| `mach_arm64e_chained` | arm64e chained fixups (authenticated pointers). |
| `mach_x64_exc` | C++ try/catch: DWARF CFI in `__eh_frame` + LSDA in `__gcc_except_tab`. |
| `mach_arm64_exc` | arm64 C++: Apple compact unwind (`__unwind_info`) + LSDA. |

The exception fixtures exercise the two Mach-O unwinding schemes: `__eh_frame`
DWARF CFI (x64, needs a register factory) and Apple compact unwind (arm64).

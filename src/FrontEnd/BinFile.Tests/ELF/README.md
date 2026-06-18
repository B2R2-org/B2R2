# ELF test fixtures

Each fixture is a minimal binary hand-built from a tiny source and compiled with
the relevant (cross-)toolchain, then zipped. They are intentionally small and
each one isolates a specific parser capability, mirroring the Mach fixtures.

## Per-architecture decode fixtures

Minimal dynamically-linked executables that exercise machine-type, endianness,
word-size, and architecture-specific relocation decoding.

| Fixture | ISA |
| --- | --- |
| `elf_x86` | i386, ELF32, little |
| `elf_arm32` | ARMv7 (ARM mode), ELF32, little |
| `elf_thumb` | ARMv7 (Thumb mode), ELF32, little |
| `elf_aarch64` | AArch64, ELF64, little |
| `elf_mips32` | MIPS, ELF32, big |
| `elf_mips32_le` | MIPS, ELF32, little |
| `elf_mips64` | MIPS, ELF64, big |

## x86-64 feature fixtures

| Fixture | Purpose |
| --- | --- |
| `elf_x64_exec` | Non-PIE `ET_EXEC`; canonical fixture, also reused by the address-space tests (has `.text`, `.rodata`, NOBITS `.bss`). |
| `elf_x64_pie` | PIE `ET_DYN` (carries `DT_DEBUG`): `IsPIE`/`IsBaseRelative`. |
| `elf_x64_so` | Shared library `ET_DYN` (no `DT_DEBUG`, no `PT_INTERP`); exported symbol. |
| `elf_x64_obj` | Relocatable object `ET_REL`: no program headers, relocation to an external symbol. |
| `elf_x64_stripped` | `elf_x64_exec` with `.symtab` stripped; imports survive. |
| `elf_x64_reloc` | Mixed dynamic relocations (JUMP_SLOT/GLOB_DAT/COPY) for the relocation API. |
| `elf_x64_nonx` | Executable stack (`GNU_STACK = RWX`): `IsNXEnabled = false`. |
| `elf_x64_eh_frame` | C++ try/catch: DWARF CFI in `.eh_frame` and an LSDA in `.gcc_except_table`. |
| `elf_x64_runpath` | Colon-separated `DT_RUNPATH` (`--enable-new-dtags`): `RunPath`. |
| `elf_x64_rpath` | Colon-separated legacy `DT_RPATH` (`--disable-new-dtags`): `RPath`. |

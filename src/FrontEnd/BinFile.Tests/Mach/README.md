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
| `mach_x64_rpath` | Two `LC_RPATH` load commands: runtime search paths (`RunPath`). |
| `mach_x64_trie_prefix` | A dylib exporting `_foo`, `_foobar` and `_foobarbaz`, so its export trie has nodes that are terminal and a parent at once. |
| `mach_x64_weakdylib` | `LC_LOAD_WEAK_DYLIB` ahead of `LC_LOAD_DYLIB`: a dylib ordinal counts both. |
| `mach_fat_x64_arm64` | Universal binary (`FAT_MAGIC`) with an x86-64 slice and an arm64 one. |
| `mach_fat64_x64_arm64` | The same two slices behind a `FAT_MAGIC_64` header, whose table uses 64-bit offsets. |
| `mach_x64_notext` | A data-only relocatable object with no `__text` section. |
| `mach_x64_unixthread` | `LC_UNIXTHREAD` entry point (x86-64 thread state). |
| `mach_arm64_unixthread` | `LC_UNIXTHREAD` entry point (arm64 thread state). |
| `mach_i386_dyldinfo` | 32-bit `LC_DYLD_INFO_ONLY`: rebase and bind over four-byte pointers. |
| `mach_i386_reloc` | 32-bit relocations x86-64 never produces: scattered, PC-relative, plain external. |
| `mach_arm32_thumb` | ARMv7 mixing A32 and T32, with `LC_DATA_IN_CODE` and an absolute symbol. |
| `mach_x64_extreloc` | A non-PIE dylib relocated through the `LC_DYSYMTAB` external and local tables. |
| `mach_x64_multichain` | A fixup page holding two chains, reached through `DYLD_CHAINED_PTR_START_MULTI`. |
| `mach_x64_linkeropt` | An `MH_OBJECT` naming what it needs linked with `LC_LINKER_OPTION`, the way clang's autolinking writes it, rather than with `LC_LOAD_DYLIB`. |
| `mach_x64_fileset` | An `MH_FILESET` container, as a kernel collection is: two images named by `LC_FILESET_ENTRY`, sharing one `__LINKEDIT`, plus a segment occupying no virtual memory. |

The exception fixtures exercise the two Mach-O unwinding schemes: `__eh_frame`
DWARF CFI (x64, needs a register factory) and Apple compact unwind (arm64).

## The fixtures that clang cannot build

Ten fixtures are written out by [`make_fixtures.py`](make_fixtures.py),
because no current toolchain produces them. An assembler always lays down
`__text` even when nothing goes in it and ld64 keeps the empty section, so a
data-only object cannot be compiled; ld64 stopped emitting `LC_UNIXTHREAD` long
ago; no SDK targets i386 or armv7 any more, which rules out 32-bit dyld info,
scattered relocations and Thumb marking; and a linker reaches for the
`LC_DYSYMTAB` relocation tables or a multi-chain fixup page only in
combinations it no longer emits. A fileset is built by `kmutil` out of a whole
kernel and its kexts, which no build of this repository has to hand, and the
real ones run to tens of megabytes. Autolinking writes `LC_LINKER_OPTION` only
for the frameworks and libraries a module map names, so pinning down every
form it can take takes a hand-written object rather than a compiled one. Each function in the script says what its
fixture is for.

```bash
python3 make_fixtures.py           # rewrite the ten archives
python3 make_fixtures.py --check   # confirm the archives match the script
```

The rest are built with `clang` and `lipo`:

```bash
clang -arch x86_64 -o t.x64 t.c && clang -arch arm64 -o t.arm64 t.c
lipo -create t.x64 t.arm64 -output mach_fat_x64_arm64
lipo -create -fat64 t.x64 t.arm64 -output mach_fat64_x64_arm64
clang -dynamiclib -o mach_x64_trie_prefix p.c \
      -install_name /usr/lib/libprefix.dylib -arch x86_64
clang -o mach_x64_weakdylib w.c -weak-la -lb -L. -arch x86_64
```

In the last one the weak load has to come first on the command line, because
ld64 emits the dylib load commands in the order it is given them and the point
of the fixture is that the weak one takes ordinal 1.

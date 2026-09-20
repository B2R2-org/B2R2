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

The exception fixtures exercise the two Mach-O unwinding schemes: `__eh_frame`
DWARF CFI (x64, needs a register factory) and Apple compact unwind (arm64).

## The fixtures that clang cannot build

`mach_x64_notext` is written out by hand. An assembler always emits `__text` as
its initial section, and ld64 keeps the empty section in whatever it links, so
no compiler invocation produces a Mach-O without one; the file below is the
smallest object that has a `__DATA,__data` section and nothing else.

```python
import struct
name16 = lambda s: s.encode() + b'\0' * (16 - len(s))
data, strtab = struct.pack('<4I', 1, 2, 3, 4), b'\0_g_table\0'
sizeofcmds = 72 + 80 + 24
dataoff = 32 + sizeofcmds
symoff, stroff = dataoff + len(data), dataoff + len(data) + 16
open('mach_x64_notext', 'wb').write(
    struct.pack('<I2i5I', 0xFEEDFACF, 0x01000007, 3, 1, 2, sizeofcmds,
                0x2000, 0)
    + struct.pack('<2I', 0x19, 152) + name16('')
    + struct.pack('<4Q2i2I', 0, 16, dataoff, 16, 7, 7, 1, 0)
    + name16('__data') + name16('__DATA')
    + struct.pack('<2Q8I', 0, 16, dataoff, 3, 0, 0, 0, 0, 0, 0)
    + struct.pack('<2I', 0x2, 24)
    + struct.pack('<4I', symoff, 1, stroff, len(strtab))
    + data + struct.pack('<IBBhQ', 1, 0x0F, 1, 0, 0) + strtab)
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

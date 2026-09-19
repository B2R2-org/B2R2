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

## MIPS relocation fixtures

The per-architecture MIPS fixtures above carry no relocation sections at all:
the classic MIPS ABI fills the GOT from `.MIPS.stubs` and `DT_MIPS_GOTSYM`
rather than from explicit entries. Two other builds do produce them — the MIPS
PLT ABI (`-mno-shared -mplt`) emits a real `.rel.plt`, and a shared library
emits local `R_MIPS_REL32` entries in `.rel.dyn`.

| Fixture | Purpose |
| --- | --- |
| `elf_mips32_plt` | MIPS PLT ABI: `.rel.plt` with `R_MIPS_JUMP_SLOT`, plus an `R_MIPS_COPY` in `.rel.dyn`. |
| `elf_mips32_so` | Shared library: local `R_MIPS_REL32`, whose addends live in the slots they relocate (REL, not RELA). |
| `elf_mips64_so` | The n64 counterpart, whose `r_info` packs `R_MIPS_REL32` with `R_MIPS_64` into an 8-bit primary type field. |

They were built with:

```
mipsel-linux-gnu-gcc       t.c  -o elf_mips32_plt -mno-shared -mplt
mipsel-linux-gnu-gcc       so.c -o elf_mips32_so  -shared -fPIC
mips64el-linux-gnuabi64-gcc so.c -o elf_mips64_so  -shared -fPIC
```

## Relocation fixtures for the remaining architectures

One fixture per architecture whose relocation kinds B2R2 classifies, each
picked so that a single binary covers as many of the three families (`S + A`,
`S`, `B + A`) as its toolchain emits. Shared libraries are used where an
executable would carry too few.

| Fixture | Kinds it carries |
| --- | --- |
| `elf_riscv64` | `R_RISCV_RELATIVE`, `R_RISCV_64`, `R_RISCV_JUMP_SLOT` |
| `elf_ppc32_so` | `R_PPC_RELATIVE`, `R_PPC_ADDR32`, `R_PPC_GLOB_DAT`, `R_PPC_JMP_SLOT` |
| `elf_ppc64_so` | `R_PPC64_RELATIVE`, `R_PPC64_ADDR64`, `R_PPC64_JMP_SLOT` |
| `elf_sh4_so` | `R_SH_RELATIVE`, `R_SH_GLOB_DAT`, `R_SH_JMP_SLOT` |
| `elf_s390x` | `R_390_RELATIVE`, `R_390_GLOB_DAT`, `R_390_JMP_SLOT` |
| `elf_m68k_so` | `R_68K_RELATIVE`, `R_68K_GLOB_DAT`, `R_68K_JMP_SLOT` |
| `elf_parisc` | `R_PARISC_IPLT`, `R_PARISC_COPY` |
| `elf_parisc_so` | `R_PARISC_DIR32` (the one case whose symbol and addend are both non-zero), `R_PARISC_PLABEL32` |

They were built from the same two sources as the MIPS fixtures:

```
riscv64-linux-gnu-gcc   exe.c -o elf_riscv64
powerpc-linux-gnu-gcc   so.c  -o elf_ppc32_so  -shared -fPIC
powerpc64-linux-gnu-gcc so.c  -o elf_ppc64_so  -shared -fPIC
sh4-linux-gnu-gcc       so.c  -o elf_sh4_so    -shared -fPIC
s390x-linux-gnu-gcc     exe.c -o elf_s390x
m68k-linux-gnu-gcc      so.c  -o elf_m68k_so   -shared -fPIC
hppa-linux-gnu-gcc      exe.c -o elf_parisc
hppa-linux-gnu-gcc      so.c  -o elf_parisc_so -shared -fPIC
```

Four more architectures keep their relocations somewhere other than a shared
library. AVR and BPF are linked statically, so only an object file carries any;
both also use kinds that encode an address into an instruction field rather
than into a slot, and those stay unresolved on purpose.

| Fixture | Kinds it carries |
| --- | --- |
| `elf_sparc64_so` | `R_SPARC_RELATIVE`, `R_SPARC_GLOB_DAT`, `R_SPARC_JMP_SLOT` |
| `elf_alpha_so` | `R_ALPHA_RELATIVE`, `R_ALPHA_GLOB_DAT`, `R_ALPHA_JMP_SLOT` |
| `elf_avr_obj` | `R_AVR_16`, plus the `LO8_LDI`/`HI8_LDI`/`CALL` field kinds |
| `elf_bpf_obj` | `R_BPF_64_ABS64`, plus the `64_64`/`64_32` field kinds |

```
sparc64-linux-gnu-gcc so.c -o elf_sparc64_so -shared -fPIC \
                                             -Wl,-z,max-page-size=0x2000
alpha-linux-gnu-gcc   so.c -o elf_alpha_so   -shared -fPIC
avr-gcc -c so.c -o elf_avr_obj -mmcu=atmega128
bpf-gcc -c so.c -o elf_bpf_obj
```

## The 32-bit SPARC fixture

SPARC has three machine types and only one instruction set: `EM_SPARCV9` is the
64-bit one, while `EM_SPARC` and `EM_SPARC32PLUS` are 32-bit, the latter being
V9 with its wider registers made visible to a 32-bit word. A toolchain asked
for `-m32` emits `EM_SPARC32PLUS`, so that is what this fixture carries; plain
`EM_SPARC` is easier to state as a bare header in the tests than to build.

| Fixture | Purpose |
| --- | --- |
| `elf_sparc32_so` | ELF32 big-endian `EM_SPARC32PLUS`, with an `R_SPARC_JMP_SLOT` and the PLT entry it relocates in place |

There is no 32-bit libc for the sparc64 cross-toolchain, so it is linked
without one, which leaves `ext` as the whole of its PLT.

```
sparc64-linux-gnu-gcc -m32 so.c -o elf_sparc32_so -shared -fPIC -nostdlib
```

## The PowerPC64 glink fixtures

Neither PowerPC64 ABI puts code in `.plt`, which is NOBITS in both: a call site
reaches a glink stub instead, one per PLT entry, starting 32 bytes past
`DT_PPC64_GLINK`. The two ABIs write that stub differently, so one fixture each
is needed. `elf_ppc64_so` above is the ELFv1 half of the pair.

| Fixture | What its glink stubs look like |
| --- | --- |
| `elf_ppc64_so` | ELFv1: `li r0, <index>` then a branch, 8 bytes apart, and a `.opd` of function descriptors |
| `elf_ppc64le_so` | ELFv2: the branch alone, 4 bytes apart, no `.opd` |

```
powerpc64le-linux-gnu-gcc so.c -o elf_ppc64le_so -shared -fPIC
```

## The ifunc fixture

An ifunc is the one relocation that names neither a symbol nor a datum: the
slot holds a resolver the loader calls to learn the address. None of the
fixtures above carries one, and a resolver defined in the file itself is what
tells an internal function apart from an imported one.

| Fixture | Kinds it carries |
| --- | --- |
| `elf_riscv64_ifunc` | `R_RISCV_IRELATIVE` in `.rela.plt`, beside an ordinary `R_RISCV_JUMP_SLOT` |

```
riscv64-linux-gnu-gcc ifunc.c -o elf_riscv64_ifunc
```

```c
static int real_f(void) { return 42; }
static void *resolve_f(void) { return (void *)real_f; }
int f(void) __attribute__((ifunc("resolve_f")));
int main(void) { return f(); }
```

Linked statically there is no dynamic linker to fill a lazy `.plt`, and lld
puts the ifunc stubs in a section of their own instead, `.iplt`, with their
relocations in `.rela.dyn`. Each stub keeps the 16-byte lazy shape even so, a
jump through the slot with a push and a branch behind it, yet carries no PLT0
header to announce it. GNU ld names that section `.plt` on x86-64, so lld is
what this fixture needs.

| Fixture | Kinds it carries |
| --- | --- |
| `elf_x64_iplt` | Two `R_X86_64_IRELATIVE` in `.rela.dyn`, their stubs in `.iplt` |

```
clang -fuse-ld=lld -static -nostdlib iplt.c -o elf_x64_iplt
```

```c
static int real_f(void) { return 42; }
static void *resolve_f(void) { return (void *)real_f; }
int f(void) __attribute__((ifunc("resolve_f")));

static int real_g(void) { return 43; }
static void *resolve_g(void) { return (void *)real_g; }
int g(void) __attribute__((ifunc("resolve_g")));

void _start(void) { f(); g(); }
```

## x86-64 feature fixtures

| Fixture | Purpose |
| --- | --- |
| `elf_x64_exec` | Non-PIE `ET_EXEC`; canonical fixture, also reused by the address-space tests (has `.text`, `.rodata`, NOBITS `.bss`). |
| `elf_x64_pie` | PIE `ET_DYN` (carries `DT_DEBUG`): `IsPIE`/`IsBaseRelative`. |
| `elf_x64_so` | Shared library `ET_DYN` (no `DT_DEBUG`, no `PT_INTERP`); exported symbol. |
| `elf_x64_obj` | Relocatable object `ET_REL`: no program headers, relocation to an external symbol. |
| `elf_x64_stripped` | `elf_x64_exec` with `.symtab` stripped; imports survive. |
| `elf_x64_reloc` | Mixed dynamic relocations (JUMP_SLOT/GLOB_DAT/COPY) for the relocation API. |
| `elf_x64_relr` | PIE linked with `-z pack-relative-relocs`: every relative relocation packed into a `.relr.dyn` bitmap, none left in `.rela.dyn`. |
| `elf_x64_nosec` | `elf_x64_relr` with its section header table removed, so PT_DYNAMIC and PT_LOAD are the only routes to its relocations. |
| `elf_x64_sysvhash` | Section-header stripped and linked `--hash-style=sysv`, so DT_HASH rather than the string table gives the dynamic symbol count. |
| `elf_x64_nonx` | Executable stack (`GNU_STACK = RWX`): `IsNXEnabled = false`. |
| `elf_x64_eh_frame` | C++ try/catch: DWARF CFI in `.eh_frame` and an LSDA in `.gcc_except_table`. |
| `elf_x64_runpath` | Colon-separated `DT_RUNPATH` (`--enable-new-dtags`): `RunPath`. |
| `elf_x64_rpath` | Colon-separated legacy `DT_RPATH` (`--disable-new-dtags`): `RPath`. |

The RELR fixture was built so that its three entries cover every encoding the
format has: a leading address entry, a bitmap, and a second bitmap that the
cursor reaches only after skipping a whole word of bits.

```
gcc relr.c -o elf_x64_relr -fPIE -pie -Wl,-z,pack-relative-relocs
```

`elf_x64_nosec` is that same binary with its section header table removed,
which is what a `sstrip`-style tool leaves behind and what the PT_DYNAMIC
fallback exists for. It still runs.

```
llvm-objcopy --strip-sections elf_x64_relr elf_x64_nosec
```

`elf_x64_sysvhash` is the same source linked with the old hash table instead of
the GNU one, then stripped the same way. It exists because the two hash styles
lead to different ways of sizing the dynamic symbol table: DT_HASH states the
count, while a GNU-hashed binary leaves it to be inferred from where the string
table starts.

```
gcc relr.c -o sysv_hash -Wl,--hash-style=sysv
llvm-objcopy --strip-sections sysv_hash elf_x64_sysvhash
```

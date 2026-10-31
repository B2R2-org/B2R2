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

## The -fno-plt fixture

Built with `-fno-plt`, a call to a function that the loader may interpose on
skips the PLT and goes straight through the GOT slot of the function, which a
GLOB_DAT relocation fills. A shared library calling an exported function of
its own does so too, and the slot then names a function defined in the very
file that calls through it. `-z now` puts that slot under RELRO, so what the
loader writes there stays.

| Fixture | Purpose |
| --- | --- |
| `elf_x64_noplt` | `entry` calls `helper` through `call *helper@GOTPCREL(%rip)`, whose slot carries an `R_X86_64_GLOB_DAT` bound to `helper` of the same library |

```
gcc -O2 -fPIC -fno-plt -shared -nostdlib -Wl,-z,now noplt.c -o elf_x64_noplt
```

```c
int helper(int x) { return x + 1; }
int entry(int x) { return helper(x) * 2; }
```

## The jump table fixture

A switch whose default is unreachable leaves holes in its jump table, and
clang fills each hole with the end of the function: a label with no code of
its own, so it lands on the padding before the next function. Such a dummy
entry sits between real ones, which is what tells it apart from the end of the
table.

| Fixture | Purpose |
| --- | --- |
| `elf_x64_jmptbl` | `pick` jumps through a six-entry table whose entries 1 and 3 are dummies pointing to the padding between `pick` and `next` |

```
clang -O2 -fPIC -fuse-ld=lld -static -nostdlib jmptbl.c -o elf_x64_jmptbl
```

```c
volatile int input;

__attribute__((noinline)) int pick(int x) {
  switch (x) {
  case 0: asm volatile("nop"); return 10;
  case 2: asm volatile("pause"); return 30;
  case 4: asm volatile("lfence"); return 50;
  case 5: asm volatile("mfence"); return 60;
  default: __builtin_unreachable();
  }
}

__attribute__((noinline)) int next(int x) { return x * 3; }

void _start(void) { input = next(pick(input)); }
```

## The nested jump table fixture

A switch nested in a case of another switch on the same variable needs no range
check of its own: the outer switch already bounds the values that reach it. GCC
then indexes the inner table with the variable as it is, folding the smallest
case into the table address instead of subtracting it. The address the code
computes thus lies a few entries before the inner table, here inside the outer
one.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_nestedjmptbl` | `pick` jumps through an eleven-entry table, and its cases 4 to 9 jump again through a six-entry table indexed by the same register, whose computed address is four entries early, inside the first table |

```
gcc -m32 -O1 -fPIE -fuse-ld=lld -static -nostdlib nested.c \
    -o elf_x86_nestedjmptbl
```

```c
volatile int input;

__attribute__((noinline)) int pick(unsigned op) {
  switch (op) {
  case 0: asm volatile("nop"); return 1;
  case 1: asm volatile("pause"); return 2;
  case 2: asm volatile("lfence"); return 3;
  case 3: asm volatile("mfence"); return 4;
  case 4: case 5: case 6: case 7: case 8: case 9:
    asm volatile("sfence");
    switch (op) {
    case 4: asm volatile("nop; nop"); return 5;
    case 5: asm volatile("pause; pause"); return 6;
    case 6: asm volatile("lfence; lfence"); return 7;
    case 7: asm volatile("mfence; mfence"); return 8;
    case 8: asm volatile("sfence; sfence"); return 9;
    case 9: asm volatile("nop; pause"); return 10;
    default: __builtin_unreachable();
    }
  case 10: asm volatile("nop; lfence"); return 11;
  default: return 0;
  }
}

void _start(void) { input = pick(input); }
```

The unreachable default of the inner switch is what lets GCC drop its range
check. Without it, GCC subtracts 4 and checks the result, and the address the
code computes is that of the table itself.

## The same-register jump table fixture

Two hand-written functions that each switch twice on the same register, where
the second table does start at the address its code computes, unlike the one of
the nested fixture above. `checked` reaches its second switch from case 2
alone, yet checks the range itself, so its table still starts at case 0.
`overread` keeps its two tables next to each other, so reading on past the end
of the first one, before that end is known, leads to the second jump.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_samevarjmptbl` | `checked` and `overread` each jump through a table whose index register also indexes the table they jump through first, and both tables start where the code computes them |

```
gcc -m32 -fuse-ld=lld -static -nostdlib samevar.s -o elf_x86_samevarjmptbl
```

```asm
        .intel_syntax noprefix
        .text

        .globl  checked
        .type   checked, @function
checked:
        mov     eax, DWORD PTR [esp+4]
        lea     ecx, [eax+1]
        cmp     ecx, 3
        ja      .Lc_zero
        jmp     DWORD PTR [checked_outer+ecx*4]
.Lc_o0: mov     eax, 1
        ret
.Lc_o1: mov     eax, 2
        ret
.Lc_o2: mov     eax, 3
        ret
.Lc_o3: cmp     eax, 3
        ja      .Lc_zero
        jmp     DWORD PTR [checked_inner+eax*4]
.Lc_i0: mov     eax, 4
        ret
.Lc_i1: mov     eax, 5
        ret
.Lc_i2: mov     eax, 6
        ret
.Lc_i3: mov     eax, 7
        ret
.Lc_zero:
        xor     eax, eax
        ret
        .size   checked, .-checked

        .globl  overread
        .type   overread, @function
overread:
        mov     eax, DWORD PTR [esp+4]
        cmp     eax, 2
        ja      .Lr_zero
        jmp     DWORD PTR [overread_outer+eax*4]
.Lr_o0: mov     eax, 1
        ret
.Lr_o1: mov     eax, 2
        ret
.Lr_o2: mov     eax, 3
        ret
.Lr_loop:
        jmp     DWORD PTR [overread_inner+eax*4]
.Lr_i0: mov     edx, 4
        jmp     .Lr_loop
.Lr_i1: mov     eax, 5
        ret
.Lr_zero:
        xor     eax, eax
        ret
        .size   overread, .-overread

        .globl  _start
        .type   _start, @function
_start:
        push    0
        call    checked
        call    overread
        add     esp, 4
        ret
        .size   _start, .-_start

        .section .rodata
        .p2align 2
overread_outer:
        .long   .Lr_o0, .Lr_o1, .Lr_o2
overread_inner:
        .long   .Lr_i0, .Lr_i1
        .long   0
checked_outer:
        .long   .Lc_o0, .Lc_o1, .Lc_o2, .Lc_o3
checked_inner:
        .long   .Lc_i0, .Lc_i1, .Lc_i2, .Lc_i3
        .long   0
```

The zero after each pair of tables stops any table that runs on into it, as
address zero lies in no function.

## The range check jump table fixture

Three hand-written functions whose first switch checks its range with a jump
that the two fixtures above do not use, each laid out like one of them.
`strict` and `taken` follow `checked`, but `strict` leaves through `jae` and
`taken` reaches its table through `jb`, the branch the check takes. `nested`
follows the nested fixture, folding case 4 into the address of its second
table, behind the signed checks `js` and `jge`.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_jccjmptbl` | `strict`, `taken` and `nested` each switch twice on one register, the first time behind a range check that is strict, taken, or signed |

```
gcc -m32 -fuse-ld=lld -static -nostdlib jcc.s -o elf_x86_jccjmptbl
```

```asm
        .intel_syntax noprefix
        .text

        .globl  strict
        .type   strict, @function
strict:
        mov     eax, DWORD PTR [esp+4]
        lea     ecx, [eax+1]
        cmp     ecx, 4
        jae     .Ls_zero
        jmp     DWORD PTR [strict_outer+ecx*4]
.Ls_o0: mov     eax, 1
        ret
.Ls_o1: mov     eax, 2
        ret
.Ls_o2: mov     eax, 3
        ret
.Ls_o3: cmp     eax, 3
        ja      .Ls_zero
        jmp     DWORD PTR [strict_inner+eax*4]
.Ls_i0: mov     eax, 4
        ret
.Ls_i1: mov     eax, 5
        ret
.Ls_i2: mov     eax, 6
        ret
.Ls_i3: mov     eax, 7
        ret
.Ls_zero:
        xor     eax, eax
        ret
        .size   strict, .-strict

        .globl  taken
        .type   taken, @function
taken:
        mov     eax, DWORD PTR [esp+4]
        lea     ecx, [eax+1]
        cmp     ecx, 4
        jb      .Lt_switch
        xor     eax, eax
        ret
.Lt_switch:
        jmp     DWORD PTR [taken_outer+ecx*4]
.Lt_o0: mov     eax, 1
        ret
.Lt_o1: mov     eax, 2
        ret
.Lt_o2: mov     eax, 3
        ret
.Lt_o3: cmp     eax, 3
        ja      .Lt_zero
        jmp     DWORD PTR [taken_inner+eax*4]
.Lt_i0: mov     eax, 4
        ret
.Lt_i1: mov     eax, 5
        ret
.Lt_i2: mov     eax, 6
        ret
.Lt_i3: mov     eax, 7
        ret
.Lt_zero:
        xor     eax, eax
        ret
        .size   taken, .-taken

        .globl  nested
        .type   nested, @function
nested:
        mov     eax, DWORD PTR [esp+4]
        test    eax, eax
        js      .Ln_zero
        cmp     eax, 11
        jge     .Ln_zero
        jmp     DWORD PTR [nested_outer+eax*4]
.Ln_o0: mov     eax, 1
        ret
.Ln_o1: mov     eax, 2
        ret
.Ln_o2: mov     eax, 3
        ret
.Ln_o3: mov     eax, 4
        ret
.Ln_inner:
        jmp     DWORD PTR [nested_inner-16+eax*4]
.Ln_i4: mov     eax, 5
        ret
.Ln_i5: mov     eax, 6
        ret
.Ln_i6: mov     eax, 7
        ret
.Ln_i7: mov     eax, 8
        ret
.Ln_i8: mov     eax, 9
        ret
.Ln_i9: mov     eax, 10
        ret
.Ln_o10:
        mov     eax, 11
        ret
.Ln_zero:
        xor     eax, eax
        ret
        .size   nested, .-nested

        .globl  _start
        .type   _start, @function
_start:
        push    0
        call    strict
        call    taken
        call    nested
        add     esp, 4
        ret
        .size   _start, .-_start

        .section .rodata
        .p2align 2
strict_outer:
        .long   .Ls_o0, .Ls_o1, .Ls_o2, .Ls_o3
strict_inner:
        .long   .Ls_i0, .Ls_i1, .Ls_i2, .Ls_i3
        .long   0
taken_outer:
        .long   .Lt_o0, .Lt_o1, .Lt_o2, .Lt_o3
taken_inner:
        .long   .Lt_i0, .Lt_i1, .Lt_i2, .Lt_i3
        .long   0
nested_outer:
        .long   .Ln_o0, .Ln_o1, .Ln_o2, .Ln_o3
        .long   .Ln_inner, .Ln_inner, .Ln_inner
        .long   .Ln_inner, .Ln_inner, .Ln_inner
        .long   .Ln_o10
nested_inner:
        .long   .Ln_i4, .Ln_i5, .Ln_i6, .Ln_i7, .Ln_i8, .Ln_i9
        .long   0
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
| `elf_x64_soname` | A shared library announcing a `DT_SONAME` of its own, beside the `DT_NEEDED` it carries: `SharedObjectName` and `DependencyNames`. |
| `elf_x64_xindex` | `elf_x64_exec` rewritten to use the extended numbering, so `e_shnum`, `e_phnum` and `e_shstrndx` all carry their escape value. |

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

`elf_x64_soname` is the one fixture whose `DT_SONAME` differs from its file
name, so that the name a library announces cannot be confused with the name it
is stored under. It calls a libc function, which is what gives it the
`DT_NEEDED` beside it.

```
gcc -shared -fPIC so.c -o elf_x64_soname -Wl,-soname,libfoo.so.1
```

`elf_x64_xindex` is `elf_x64_exec` with the three header fields that can
overflow sixteen bits set to the escape the ELF specification gives them, and
the real values moved into `sh_size`, `sh_link` and `sh_info` of the initial
section header, where a reader is meant to find them. A file with more than
0xff00 sections is what forces this in practice, and one of those is far too
large to keep here; readelf reads the rewritten file as it reads the original.

```python
b = bytearray(open('elf_x64_exec', 'rb').read())
shoff = struct.unpack_from('<Q', b, 0x28)[0]
struct.pack_into('<Q', b, shoff + 0x20, struct.unpack_from('<H', b, 0x3c)[0])
struct.pack_into('<I', b, shoff + 0x28, struct.unpack_from('<H', b, 0x3e)[0])
struct.pack_into('<I', b, shoff + 0x2c, struct.unpack_from('<H', b, 0x38)[0])
struct.pack_into('<H', b, 0x3c, 0)       # e_shnum, the count moving to sh_size
struct.pack_into('<H', b, 0x3e, 0xffff)  # e_shstrndx = SHN_XINDEX
struct.pack_into('<H', b, 0x38, 0xffff)  # e_phnum = PN_XNUM
open('elf_x64_xindex', 'wb').write(bytes(b))
```

## The extended symbol index fixture

`st_shndx` is sixteen bits wide, and the values from `SHN_LORESERVE` (0xff00)
up are reserved, so a symbol defined in a section numbered above that cannot
say which. It carries `SHN_XINDEX` there instead, and the number itself waits
at the symbol's own index of a `SHT_SYMTAB_SHNDX` table whose `sh_link` names
the symbol table. The section count is then past what `e_shnum` holds too, so
such a file uses the extended numbering as well.

| Fixture | Purpose |
| --- | --- |
| `elf_x64_shndx` | A relocatable object of 65282 sections whose `high_fn` is defined in the last of them |

A real one is easy to compile and far too large to keep: 65400 one-line
functions built with `-ffunction-sections` give a 13 MB object that still
zips to 1.4 MB, where this hand-built one zips to 12 KB. The saving is in the
filler: sections 6 through 0xff00 are empty `SHT_PROGBITS` headers that all
share one name, `.pad`, `sh_name` being an offset that nothing requires to
differ. What surrounds them is the smallest object that can carry a symbol
table:

| Index | Section | What it holds |
| --- | --- | --- |
| 0 | — | `sh_size` = 65282 and `sh_link` = 2, the extended count and name index |
| 1 | `.text` | `mov eax, 42; ret`, which `low_fn` names by an ordinary index |
| 2 | `.shstrtab` | the seven section names |
| 3 | `.strtab` | `low_fn` and `high_fn` |
| 4 | `.symtab` | three entries, the third with `st_shndx` = `SHN_XINDEX` |
| 5 | `.symtab_shndx` | three words, the third being 0xff01 |
| 6..0xff00 | `.pad` | nothing |
| 0xff01 | `.text.high` | the same two instructions, which `high_fn` names |


## The core dump fixture

Notes reach a reader two ways, and only a core dump takes the second one on
its own. A linked binary describes each note twice, once in a `PT_NOTE`
segment and once in an `SHT_NOTE` section, and a relocatable object describes
them in sections alone, having no segments. A core dump is the opposite case:
the section headers it carries name none of its notes, so the segment is the
only route to them. It is also the only file that carries the `CORE` notes
themselves, `NT_PRSTATUS` for each thread and `NT_FILE` for the mappings.

| Fixture | Purpose |
| --- | --- |
| `elf_x64_core` | An `ET_CORE` dump stopped by SIGILL: 8 notes from 3 vendors, 15 mapped-file entries |

The dumped program is one line, `int main(void) { __builtin_trap(); }`, and
gdb runs it so that the trap leaves a process to dump. Clearing
`coredump_filter` first is what keeps the result small: gdb honours it, and
without it the anonymous pages make a 642 KB dump where this one is 26 KB.

```
gcc -O2 -o corevictim c.c
gdb ./corevictim -batch -ex run \
    -ex 'shell echo 0 > /proc/$(pgrep -n corevictim)/coredump_filter' \
    -ex 'generate-core-file elf_x64_core'
```

The paths in `NT_FILE` are those of the machine that dumped it, so the fixture
names `/home/sangkilc/Develop/B2R2/corevictim` alongside the system libc and
loader. The other GNU notes are covered by fixtures that already exist:
`elf_x64_exec` carries a `.note.gnu.property` with the x86 IBT and SHSTK bits,
`elf_x64_nosec` carries a build ID reachable through its segment alone, and
`elf_x64_obj` carries a property note in a section alone.

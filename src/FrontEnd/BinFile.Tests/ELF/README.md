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

## The phi jump table fixture

A hand-written function that reaches its first switch from two blocks, each of
which computes the index and checks its range on its own, as Clang does when it
copies the check into both predecessors of the switch. The switch thus reads a
phi of the two indices, which neither check reads. The tables are laid out like
those of `strict`.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_phijmptbl` | `dup` switches twice on one register, the first time on a phi of two copies of the index, each behind a range check of its own |

```
gcc -m32 -fuse-ld=lld -static -nostdlib phi.s -o elf_x86_phijmptbl
```

```asm
        .intel_syntax noprefix
        .text

        .globl  dup
        .type   dup, @function
dup:
        mov     eax, DWORD PTR [esp+4]
        cmp     DWORD PTR [esp+8], 0
        je      .Ld_other
        lea     ecx, [eax+1]
        cmp     ecx, 3
        jbe     .Ld_switch
        jmp     .Ld_zero
.Ld_other:
        lea     ecx, [eax+1]
        cmp     ecx, 3
        ja      .Ld_zero
.Ld_switch:
        jmp     DWORD PTR [dup_outer+ecx*4]
.Ld_o0: mov     eax, 1
        ret
.Ld_o1: mov     eax, 2
        ret
.Ld_o2: mov     eax, 3
        ret
.Ld_o3: cmp     eax, 3
        ja      .Ld_zero
        jmp     DWORD PTR [dup_inner+eax*4]
.Ld_i0: mov     eax, 4
        ret
.Ld_i1: mov     eax, 5
        ret
.Ld_i2: mov     eax, 6
        ret
.Ld_i3: mov     eax, 7
        ret
.Ld_zero:
        xor     eax, eax
        ret
        .size   dup, .-dup

        .globl  _start
        .type   _start, @function
_start:
        push    0
        push    0
        call    dup
        add     esp, 8
        ret
        .size   _start, .-_start

        .section .rodata
        .p2align 2
dup_outer:
        .long   .Ld_o0, .Ld_o1, .Ld_o2, .Ld_o3
dup_inner:
        .long   .Ld_i0, .Ld_i1, .Ld_i2, .Ld_i3
        .long   0
```

## The bypassed jump table fixture

Two hand-written functions whose switch has no range check, though one of the
two ways into it checks the index: for zero, as GCC does when it compares the
index with the one of the previous iteration. The other way in leaves the
index unchecked, so nothing bounds the table.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_bypassjmptbl` | `other` reaches its switch through a check of the index and through one of the second argument; `skip` reaches it through a check of the index and by falling through with an index from the second argument |

```
gcc -m32 -fuse-ld=lld -static -nostdlib bypass.s -o elf_x86_bypassjmptbl
```

```asm
        .intel_syntax noprefix
        .text

        .globl  other
        .type   other, @function
other:
        mov     eax, DWORD PTR [esp+4]
        test    eax, eax
        je      .Lo_switch
        cmp     DWORD PTR [esp+8], 0
        jne     .Lo_switch
        xor     eax, eax
        ret
.Lo_switch:
        jmp     DWORD PTR [other_table+eax*4]
.Lo_c0: mov     eax, 1
        ret
.Lo_c1: mov     eax, 2
        ret
.Lo_c2: mov     eax, 3
        ret
.Lo_c3: mov     eax, 4
        ret
        .size   other, .-other

        .globl  skip
        .type   skip, @function
skip:
        mov     eax, DWORD PTR [esp+4]
        test    eax, eax
        je      .Ls_switch
        mov     eax, DWORD PTR [esp+8]
.Ls_switch:
        jmp     DWORD PTR [skip_table+eax*4]
.Ls_c0: mov     eax, 1
        ret
.Ls_c1: mov     eax, 2
        ret
.Ls_c2: mov     eax, 3
        ret
.Ls_c3: mov     eax, 4
        ret
        .size   skip, .-skip

        .globl  _start
        .type   _start, @function
_start:
        push    0
        push    0
        call    other
        call    skip
        add     esp, 8
        ret
        .size   _start, .-_start

        .section .rodata
        .p2align 2
other_table:
        .long   .Lo_c0, .Lo_c1, .Lo_c2, .Lo_c3
        .long   0
skip_table:
        .long   .Ls_c0, .Ls_c1, .Ls_c2, .Ls_c3
        .long   0
```

## The gap jump table fixture

A hand-written function whose second switch lies in dead code, after its last
`ret`, so that only a gap analysis recovers it. One case of that switch jumps
into the middle of a block that the function reaches, as Clang does at `-Oz`
to share the code after two `push`es of a small constant. The table of the
dead switch comes first, so that the table of the live one bounds it.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_gapjmptbl` | `gap` reaches its first switch; case 1 of its second, dead switch jumps into the middle of a block that the first one exits to |

```
gcc -m32 -fuse-ld=lld -static -nostdlib gap.s -o elf_x86_gapjmptbl
```

```asm
        .intel_syntax noprefix
        .text

        .globl  gap
        .type   gap, @function
gap:
        mov     eax, DWORD PTR [esp+4]
        cmp     eax, 3
        ja      .Lg_join
        jmp     DWORD PTR [gap_live+eax*4]
.Lg_l0: mov     eax, 1
        ret
.Lg_l1: mov     eax, 2
        ret
.Lg_l2: mov     eax, 3
        ret
.Lg_l3: mov     eax, 4
        ret
.Lg_join:
        push    0x3e
.Lg_mid:
        pop     eax
        ret
.Lg_dead:
        mov     eax, DWORD PTR [esp+8]
        cmp     eax, 3
        ja      .Lg_d0
        jmp     DWORD PTR [gap_dead+eax*4]
.Lg_d0: mov     eax, 5
        ret
.Lg_d1: push    0x75
        jmp     .Lg_mid
.Lg_d2: mov     eax, 6
        ret
.Lg_d3: mov     eax, 7
        ret
        .size   gap, .-gap

        .globl  _start
        .type   _start, @function
_start:
        push    0
        push    0
        call    gap
        add     esp, 8
        ret
        .size   _start, .-_start

        .section .rodata
        .p2align 2
gap_dead:
        .long   .Lg_d0, .Lg_d1, .Lg_d2, .Lg_d3
        .long   0
gap_live:
        .long   .Lg_l0, .Lg_l1, .Lg_l2, .Lg_l3
        .long   0
```

## The overrun jump table fixture

A hand-written function whose switch has no range check, so its table is read
past its last entry. The word after the table points to the last byte of a
`jmp` whose displacement ends in `0xff`, followed by the padding `nop` that
starts with `66 2e`. From that byte, the code decodes as a jump through `esi`
plus `0x2e`, and `esi` still holds the address of the table, so that jump
reads a table that starts within the first one. Clang's x86-64 code lays out
the same bytes when the table of the next function follows.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_overrunjmptbl` | `pick` jumps through a twelve-entry table, after which a word points into `pick`, where the bytes decode as a jump through the middle of that table |

```
gcc -m32 -fuse-ld=lld -static -nostdlib overrun.s -o elf_x86_overrunjmptbl
```

```asm
        .intel_syntax noprefix
        .text

        .globl  pick
        .type   pick, @function
pick:
        mov     eax, DWORD PTR [esp+4]
        mov     esi, OFFSET pick_table
        mov     eax, DWORD PTR [esi+eax*4]
        jmp     eax
.Lp_c0: mov     eax, 1
        ret
.Lp_c1: mov     eax, 2
        ret
.Lp_c2: mov     eax, 3
        ret
.Lp_c3: mov     eax, 4
        ret
.Lp_c4: mov     eax, 5
        ret
.Lp_c5: mov     eax, 6
        ret
.Lp_c6: mov     eax, 7
        ret
.Lp_c7: mov     eax, 8
        ret
.Lp_c8: mov     eax, 9
        ret
.Lp_c9: mov     eax, 10
        ret
.Lp_c10:
        mov     eax, 11
        ret
.Lp_c11:
        .byte   0xe9
        .long   .Lp_c0 - (.Lp_c11 + 5)
        .byte   0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
        .size   pick, .-pick

        .globl  _start
        .type   _start, @function
_start:
        push    0
        call    pick
        add     esp, 4
        ret
        .size   _start, .-_start

        .section .rodata
        .p2align 2
pick_table:
        .long   .Lp_c0, .Lp_c1, .Lp_c2, .Lp_c3, .Lp_c4, .Lp_c5
        .long   .Lp_c6, .Lp_c7, .Lp_c8, .Lp_c9, .Lp_c10, .Lp_c11
        .long   .Lp_c11 + 4
        .long   0
```

## The rebuilt jump table fixture

A hand-written function with two switches whose tables lie next to each other.
The first switch has no range check, so its table is read past its two
entries, into the second table, whose first entry is the block of the second
switch. Code reaches that block only after a call, so a recovery that does not
yet know the call to return reaches the second switch through the first table
alone, while the next recovery reaches it through the call.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_rebuildjmptbl` | `f` jumps through a two-entry table without a range check, right after which lies the table of a second switch that only the code after a call to `g` reaches |

```
gcc -m32 -fuse-ld=lld -static -nostdlib rebuild.s -o elf_x86_rebuildjmptbl
```

```asm
        .intel_syntax noprefix
        .text

        .globl  f
        .type   f, @function
f:
        mov     eax, DWORD PTR [esp+4]
        cmp     DWORD PTR [esp+8], 0
        jne     .Lf_call
        jmp     DWORD PTR [f_first+eax*4]
.Lf_t0: mov     eax, 1
        ret
.Lf_t1: mov     eax, 2
        ret
.Lf_call:
        call    g
.Lf_loop:
        mov     eax, DWORD PTR [esp+8]
        cmp     eax, 1
        ja      .Lf_out
        jmp     DWORD PTR [f_second+eax*4]
.Lf_s1: mov     eax, 3
        ret
.Lf_out:
        xor     eax, eax
        ret
        .size   f, .-f

        .globl  g
        .type   g, @function
g:
        ret
        .size   g, .-g

        .globl  _start
        .type   _start, @function
_start:
        push    0
        push    0
        call    f
        add     esp, 8
        ret
        .size   _start, .-_start

        .section .rodata
        .p2align 2
f_first:
        .long   .Lf_t0, .Lf_t1
f_second:
        .long   .Lf_loop, .Lf_s1
        .long   0
```

## The dead jump table fixture

A hand-written function whose table holds seven entries, while the check in
front of its jump admits only five. Clang emits such a table at `-O0` when a
switch sits in a loop whose condition keeps the last cases out, and the
switch, whose default is unreachable, checks nothing itself. The last two
entries lead to dead cases, yet they belong to the table.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_deadjmptbl` | `dead` jumps through a seven-entry table behind a check that admits five entries |

```
gcc -m32 -fuse-ld=lld -static -nostdlib dead.s -o elf_x86_deadjmptbl
```

```asm
        .intel_syntax noprefix
        .text

        .globl  dead
        .type   dead, @function
dead:
        mov     eax, DWORD PTR [esp+4]
        cmp     eax, 5
        jae     .Ld_out
        jmp     DWORD PTR [dead_table+eax*4]
.Ld_c0: mov     eax, 1
        ret
.Ld_c1: mov     eax, 2
        ret
.Ld_c2: mov     eax, 3
        ret
.Ld_c3: mov     eax, 4
        ret
.Ld_c4: mov     eax, 5
        ret
.Ld_c5: mov     eax, 6
        ret
.Ld_c6: mov     eax, 7
        ret
.Ld_out:
        xor     eax, eax
        ret
        .size   dead, .-dead

        .globl  _start
        .type   _start, @function
_start:
        push    0
        call    dead
        add     esp, 4
        ret
        .size   _start, .-_start

        .section .rodata
        .p2align 2
dead_table:
        .long   .Ld_c0, .Ld_c1, .Ld_c2, .Ld_c3, .Ld_c4, .Ld_c5, .Ld_c6
        .long   0
```

## The split jump table fixture

A hand-written function with two switches, neither with a range check. The
second table is followed by a word that points one byte into the
`mov eax, 0x909090` of its first case. From there, the bytes decode as three
`nop`s and an `add bl, al` that swallows the `ret`, and run on into the last
case of the first switch, so reaching that case splits the code made from the
word.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_splitjmptbl` | `f` jumps through a five-entry and a two-entry table; the word after the second points into the middle of a case, from which the code runs on into the last case of the first |

```
gcc -m32 -fuse-ld=lld -static -nostdlib split.s -o elf_x86_splitjmptbl
```

```asm
        .intel_syntax noprefix
        .text

        .globl  f
        .type   f, @function
f:
        mov     eax, DWORD PTR [esp+4]
        cmp     DWORD PTR [esp+8], 0
        jne     .Lf_u
        jmp     DWORD PTR [f_t+eax*4]
.Lf_u:  jmp     DWORD PTR [f_u+eax*4]
.Lf_t0: mov     eax, 1
        ret
.Lf_t1: mov     eax, 2
        ret
.Lf_t2: mov     eax, 3
        ret
.Lf_t3: mov     eax, 4
        ret
.Lf_u1: mov     eax, 5
        ret
.Lf_u0: mov     eax, 0x909090
        ret
.Lf_t4: mov     eax, 6
        ret
        .size   f, .-f

        .globl  _start
        .type   _start, @function
_start:
        push    0
        push    0
        call    f
        add     esp, 8
        ret
        .size   _start, .-_start

        .section .rodata
        .p2align 2
f_u:
        .long   .Lf_u0, .Lf_u1
        .long   .Lf_u0 + 1
        .long   0
f_t:
        .long   .Lf_t0, .Lf_t1, .Lf_t2, .Lf_t3, .Lf_t4
        .long   0
```

## The unpadded jump table fixture

A hand-written counterpart of the jump table fixture, without the padding after
`pick`: a function that Clang emits may end right on the boundary the next one
is aligned to, leaving no room for any. The holes still point to the end of
`pick`, which is now where `next` begins.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_nopadjmptbl` | `pick` jumps through a five-entry table whose entries 1 and 3 are dummies pointing to `next`, which begins right where `pick` ends |

```
gcc -m32 -fuse-ld=lld -static -nostdlib nopad.s -o elf_x86_nopadjmptbl
```

```asm
        .intel_syntax noprefix
        .text

        .globl  pick
        .type   pick, @function
pick:
        mov     eax, DWORD PTR [esp+4]
        jmp     DWORD PTR [pick_t+eax*4]
.Lp_c0: mov     eax, 10
        ret
.Lp_c2: mov     eax, 30
        ret
.Lp_c4: mov     eax, 50
        ret
.Lp_end:
        .size   pick, .-pick

        .globl  next
        .type   next, @function
next:
        mov     eax, DWORD PTR [esp+4]
        lea     eax, [eax+eax*2]
        ret
        .size   next, .-next

        .globl  _start
        .type   _start, @function
_start:
        push    0
        call    pick
        mov     DWORD PTR [esp], eax
        call    next
        add     esp, 4
        ret
        .size   _start, .-_start

        .section .rodata
        .p2align 2
pick_t:
        .long   .Lp_c0, .Lp_end, .Lp_c2, .Lp_end, .Lp_c4
        .long   0
```

## The cold jump table fixture

A hand-written function whose table sends one case to a cold part below the
function, the way GCC splits off the unlikely code of a function at `-O2`. The
cold part has its own FDE, which starts mid-frame: it carries on the frame of
`pick` from the jump. GNU as would move a frame state set at the very start of
an FDE into a CIE of its own, so a `.cfi_escape` keeps it in the FDE, where
GCC-built binutils binaries have it.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_coldjmptbl` | `pick` jumps through a four-entry table whose entry 1 points to a cold part below `pick`, whose FDE starts mid-frame |

```
gcc -m32 -fuse-ld=lld -static -nostdlib cold.s -o elf_x86_coldjmptbl
```

```asm
        .intel_syntax noprefix
        .text
        .cfi_startproc
        .cfi_escape 0x0e, 0x10
.Lp_c1: ud2
        .cfi_endproc

        .globl  pick
        .type   pick, @function
pick:
        .cfi_startproc
        sub     esp, 12
        .cfi_def_cfa_offset 16
        mov     eax, DWORD PTR [esp+16]
        jmp     DWORD PTR [pick_t+eax*4]
.Lp_c0: mov     eax, 10
        jmp     .Lp_ret
.Lp_c2: mov     eax, 30
        jmp     .Lp_ret
.Lp_c3: mov     eax, 40
.Lp_ret:
        add     esp, 12
        .cfi_def_cfa_offset 4
        ret
        .cfi_endproc
        .size   pick, .-pick

        .globl  _start
        .type   _start, @function
_start:
        push    0
        call    pick
        add     esp, 4
        ret
        .size   _start, .-_start

        .section .rodata
        .p2align 2
pick_t:
        .long   .Lp_c0, .Lp_c1, .Lp_c2, .Lp_c3
        .long   0
```

## The frameless cold part fixture

Hand-written functions that run without a frame of their own and jump to cold
parts, the way GCC splits off the unlikely code of a leaf function at `-O2`.
Such a part starts at the frame state of the CIE, so its FDE restates nothing
and looks like that of a function; only its place tells it apart. GCC emits
the FDE of a cold part right after that of its function, but GNU ld places
`.text.unlikely` ahead of `.text`, so the part lies below the function, as in
GCC-built binutils binaries. lld would place it after `.text` instead. `pick`
leaves its cold part unnamed, as a stripped binary does, while `clamp.cold`
keeps the symbol that GCC gives it.

| Fixture | Purpose |
| --- | --- |
| `elf_x64_framelesscold` | `pick` jumps to its cold part on a range check and through entry 1 of its four-entry table; `clamp` jumps to `clamp.cold` on a condition and without one |

```
gcc -fuse-ld=bfd -static -nostdlib framelesscold.s -o elf_x64_framelesscold
```

```asm
        .intel_syntax noprefix
        .text

        .globl  die
        .type   die, @function
die:
        .cfi_startproc
        ud2
        .cfi_endproc
        .size   die, .-die

        .globl  pick
        .type   pick, @function
pick:
        .cfi_startproc
        lea     eax, [rdi-1]
        cmp     eax, 3
        ja      .Lp_cold
        lea     rcx, [rip+pick_t]
        movsxd  rax, DWORD PTR [rcx+rax*4]
        add     rax, rcx
        jmp     rax
.Lp_c0: mov     eax, 10
        ret
.Lp_c2: mov     eax, 30
        ret
.Lp_c3: mov     eax, 40
        ret
        .cfi_endproc
        .section .text.unlikely
        .cfi_startproc
.Lp_cold:
        push    rax
        .cfi_def_cfa_offset 16
        call    die
        .cfi_endproc
        .text
        .size   pick, .-pick

        .globl  clamp
        .type   clamp, @function
clamp:
        .cfi_startproc
        test    edi, edi
        js      clamp.cold
        cmp     edi, 100
        jg      .Lc_big
        mov     eax, edi
        ret
.Lc_big:
        jmp     clamp.cold
        .cfi_endproc
        .section .text.unlikely
        .cfi_startproc
        .type   clamp.cold, @function
clamp.cold:
        mov     eax, -1
        ret
        .cfi_endproc
        .text
        .size   clamp, .-clamp
        .section .text.unlikely
        .size   clamp.cold, .-clamp.cold

        .text
        .globl  _start
        .type   _start, @function
_start:
        .cfi_startproc
        mov     edi, 2
        call    pick
        mov     edi, 7
        call    clamp
        ret
        .cfi_endproc
        .size   _start, .-_start

        .section .rodata
        .p2align 2
pick_t:
        .long   .Lp_c0-pick_t, .Lp_cold-pick_t, .Lp_c2-pick_t, .Lp_c3-pick_t
        .long   0
```

## The folded jump table fixture

Hand-written functions that switch on a register whose range a conditional
jump has already checked, calling a function in between, through a table whose
address has case 4 folded in, as GCC does. The computed address therefore lies
four entries before the table, within the table that precedes it: one of the
same function in `samefn`, and one of another function in `nfn` and `nfn2`,
which follow and precede the owner of that table, `tfn` and `tfn2`.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_foldjmptbl` | `samefn`, `nfn` and `nfn2` each jump through a table whose computed address lies in the last four entries of the table before it, of their own function or of another one |

```
gcc -m32 -fuse-ld=lld -static -nostdlib fold.s -o elf_x86_foldjmptbl
```

```asm
        .intel_syntax noprefix
        .text

        .globl  helper
        .type   helper, @function
helper:
        ret
        .size   helper, .-helper

        .globl  samefn
        .type   samefn, @function
samefn:
        push    esi
        mov     esi, DWORD PTR [esp+8]
        mov     eax, DWORD PTR [esp+12]
        cmp     eax, 7
        ja      .Ls_check
        jmp     DWORD PTR [same_a+eax*4]
.Ls_a0: mov     ecx, 1
        jmp     .Ls_check
.Ls_a1: mov     ecx, 2
        jmp     .Ls_check
.Ls_a2: mov     ecx, 3
        jmp     .Ls_check
.Ls_a3: mov     ecx, 4
        jmp     .Ls_check
.Ls_a4: mov     ecx, 5
        jmp     .Ls_check
.Ls_a5: mov     ecx, 6
        jmp     .Ls_check
.Ls_a6: mov     ecx, 7
        jmp     .Ls_check
.Ls_a7: mov     ecx, 8
.Ls_check:
        lea     eax, [esi-4]
        cmp     eax, 5
        ja      .Ls_zero
        call    helper
        jmp     DWORD PTR [same_b-16+esi*4]
.Ls_b4: mov     eax, 4
        pop     esi
        ret
.Ls_b5: mov     eax, 5
        pop     esi
        ret
.Ls_b6: mov     eax, 6
        pop     esi
        ret
.Ls_b7: mov     eax, 7
        pop     esi
        ret
.Ls_b8: mov     eax, 8
        pop     esi
        ret
.Ls_b9: mov     eax, 9
        pop     esi
        ret
.Ls_zero:
        xor     eax, eax
        pop     esi
        ret
        .size   samefn, .-samefn

        .globl  tfn
        .type   tfn, @function
tfn:
        mov     eax, DWORD PTR [esp+4]
        cmp     eax, 7
        ja      .Lt_zero
        jmp     DWORD PTR [cross_t+eax*4]
.Lt_0: mov     eax, 1
        ret
.Lt_1: mov     eax, 2
        ret
.Lt_2: mov     eax, 3
        ret
.Lt_3: mov     eax, 4
        ret
.Lt_4: mov     eax, 5
        ret
.Lt_5: mov     eax, 6
        ret
.Lt_6: mov     eax, 7
        ret
.Lt_7: mov     eax, 8
        ret
.Lt_zero:
        xor     eax, eax
        ret
        .size   tfn, .-tfn

        .globl  nfn
        .type   nfn, @function
nfn:
        push    esi
        mov     esi, DWORD PTR [esp+8]
        lea     eax, [esi-4]
        cmp     eax, 5
        ja      .Ln_zero
        call    helper
        jmp     DWORD PTR [cross_n-16+esi*4]
.Ln_4: mov     eax, 4
        pop     esi
        ret
.Ln_5: mov     eax, 5
        pop     esi
        ret
.Ln_6: mov     eax, 6
        pop     esi
        ret
.Ln_7: mov     eax, 7
        pop     esi
        ret
.Ln_8: mov     eax, 8
        pop     esi
        ret
.Ln_9: mov     eax, 9
        pop     esi
        ret
.Ln_zero:
        xor     eax, eax
        pop     esi
        ret
        .size   nfn, .-nfn

        .globl  nfn2
        .type   nfn2, @function
nfn2:
        push    esi
        mov     esi, DWORD PTR [esp+8]
        lea     eax, [esi-4]
        cmp     eax, 5
        ja      .Ln2_zero
        call    helper
        jmp     DWORD PTR [cross_n2-16+esi*4]
.Ln2_4: mov     eax, 4
        pop     esi
        ret
.Ln2_5: mov     eax, 5
        pop     esi
        ret
.Ln2_6: mov     eax, 6
        pop     esi
        ret
.Ln2_7: mov     eax, 7
        pop     esi
        ret
.Ln2_8: mov     eax, 8
        pop     esi
        ret
.Ln2_9: mov     eax, 9
        pop     esi
        ret
.Ln2_zero:
        xor     eax, eax
        pop     esi
        ret
        .size   nfn2, .-nfn2

        .globl  tfn2
        .type   tfn2, @function
tfn2:
        mov     eax, DWORD PTR [esp+4]
        cmp     eax, 7
        ja      .Lt2_zero
        jmp     DWORD PTR [cross_t2+eax*4]
.Lt2_0: mov     eax, 1
        ret
.Lt2_1: mov     eax, 2
        ret
.Lt2_2: mov     eax, 3
        ret
.Lt2_3: mov     eax, 4
        ret
.Lt2_4: mov     eax, 5
        ret
.Lt2_5: mov     eax, 6
        ret
.Lt2_6: mov     eax, 7
        ret
.Lt2_7: mov     eax, 8
        ret
.Lt2_zero:
        xor     eax, eax
        ret
        .size   tfn2, .-tfn2

        .globl  _start
        .type   _start, @function
_start:
        push    3
        push    5
        call    samefn
        call    tfn
        call    nfn
        call    nfn2
        call    tfn2
        add     esp, 8
        ret
        .size   _start, .-_start

        .section .rodata
        .p2align 2
same_a:
        .long   .Ls_a0, .Ls_a1, .Ls_a2, .Ls_a3
        .long   .Ls_a4, .Ls_a5, .Ls_a6, .Ls_a7
same_b:
        .long   .Ls_b4, .Ls_b5, .Ls_b6, .Ls_b7, .Ls_b8, .Ls_b9
        .long   0
cross_t:
        .long   .Lt_0, .Lt_1, .Lt_2, .Lt_3
        .long   .Lt_4, .Lt_5, .Lt_6, .Lt_7
cross_n:
        .long   .Ln_4, .Ln_5, .Ln_6, .Ln_7, .Ln_8, .Ln_9
        .long   0
cross_t2:
        .long   .Lt2_0, .Lt2_1, .Lt2_2, .Lt2_3
        .long   .Lt2_4, .Lt2_5, .Lt2_6, .Lt2_7
cross_n2:
        .long   .Ln2_4, .Ln2_5, .Ln2_6, .Ln2_7, .Ln2_8, .Ln2_9
        .long   0
```

## The relocated jump table fixture

A table of absolute addresses in a position-independent executable needs a
relocation for each entry, which the loader applies when it picks the base.
lld leaves such a slot zero in the file, so only the relocation tells where the
entry points. Conversely, a word that has no relocation is never rebased, so it
cannot point into the code, whatever number it holds. `-z notext` lets the
table stay in `.rodata`, which the dynamic relocations would otherwise rule
out.

| Fixture | Purpose |
| --- | --- |
| `elf_x64_reloctbl` | `pick` jumps through a four-entry table at 0x310 whose entries only `R_X86_64_RELATIVE` relocations fill, and right after it lies a word without a relocation holding 0x1356, the address of the `ret` of case 1 |

```
clang -fPIE -pie -nostdlib -fuse-ld=lld -Wl,-z,notext reloc.s \
    -o elf_x64_reloctbl
```

```asm
        .intel_syntax noprefix
        .text

        .globl  _start
        .type   _start, @function
_start:
        xor     edi, edi
        call    pick
        ud2
        .size   _start, .-_start

        .globl  pick
        .type   pick, @function
pick:
        lea     rax, [rip + table]
        jmp     QWORD PTR [rax + rdi*8]
.Lcase0:
        mov     eax, 10
        ret
.Lcase1:
        mov     eax, 20
        ret
.Lcase2:
        mov     eax, 30
        ret
.Lcase3:
        mov     eax, 40
        ret
        .size   pick, .-pick

        .globl  next
        .type   next, @function
next:
        lea     eax, [rdi + rdi*2]
        ret
        .size   next, .-next

        .section .rodata
        .p2align 3
table:
        .quad   .Lcase0
        .quad   .Lcase1
        .quad   .Lcase2
        .quad   .Lcase3
        .quad   0x1356
```

## The indirect call fixture

Hand-written functions whose indirect calls only the call frame information
can tell apart, as GCC writes it with asynchronous unwind tables: a row at
every instruction that moves the stack pointer. The code after a call that
returns runs as deep in the frame as the call, less what the callee pops, so
the depth the rows give that code tells whether and how the call returns.
`joined` and `padded` push two words for a callee that never returns, and the
code after the call, past nops in `padded`, runs with them gone, where a
branch around the call lands. `popped` and `unpopped` call callees that
return, the first popping the word it pushed and the second popping nothing
although its call looks like an sret call. `last` ends its frame with a call
that pushes nothing, so `_start` follows it at the depth the call runs.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_indcall` | `joined`, `padded` and `last` end with a call that never returns, which only their frames tell; `popped` and `unpopped` return from callees that pop one word and none |

```
gcc -m32 -fuse-ld=lld -static -nostdlib indcall.s -o elf_x86_indcall
```

```asm
        .intel_syntax noprefix
        .text

        .globl  joined
        .type   joined, @function
joined:
        .cfi_startproc
        mov     eax, DWORD PTR [esp+4]
        mov     edx, DWORD PTR [esp+8]
        test    edx, edx
        je      .Lj_done
        push    edx
        .cfi_def_cfa_offset 8
        push    edx
        .cfi_def_cfa_offset 12
        call    DWORD PTR [eax]
.Lj_done:
        .cfi_def_cfa_offset 4
        xor     eax, eax
        ret
        .cfi_endproc
        .size   joined, .-joined

        .globl  popped
        .type   popped, @function
popped:
        .cfi_startproc
        mov     eax, DWORD PTR [esp+4]
        push    DWORD PTR [esp+8]
        .cfi_def_cfa_offset 8
        call    DWORD PTR [eax]
        .cfi_def_cfa_offset 4
        ret
        .cfi_endproc
        .size   popped, .-popped

        .globl  unpopped
        .type   unpopped, @function
unpopped:
        .cfi_startproc
        sub     esp, 8
        .cfi_def_cfa_offset 12
        mov     eax, DWORD PTR [esp+12]
        lea     edx, [esp]
        push    edx
        .cfi_def_cfa_offset 16
        call    DWORD PTR [eax]
        add     esp, 8
        .cfi_def_cfa_offset 8
        add     esp, 4
        .cfi_def_cfa_offset 4
        ret
        .cfi_endproc
        .size   unpopped, .-unpopped

        .globl  padded
        .type   padded, @function
padded:
        .cfi_startproc
        mov     eax, DWORD PTR [esp+4]
        mov     edx, DWORD PTR [esp+8]
        test    edx, edx
        je      .Lp_done
        push    edx
        .cfi_def_cfa_offset 8
        push    edx
        .cfi_def_cfa_offset 12
        call    DWORD PTR [eax]
        .byte   0x8d, 0xb4, 0x26, 0x00, 0x00, 0x00, 0x00
        .byte   0x8d, 0x76, 0x00
.Lp_done:
        .cfi_def_cfa_offset 4
        xor     eax, eax
        ret
        .cfi_endproc
        .size   padded, .-padded

        .globl  last
        .type   last, @function
last:
        .cfi_startproc
        mov     eax, DWORD PTR [esp+4]
        call    DWORD PTR [eax]
        .cfi_endproc
        .size   last, .-last

        .globl  _start
        .type   _start, @function
_start:
        .cfi_startproc
        push    0
        .cfi_def_cfa_offset 8
        push    0
        .cfi_def_cfa_offset 12
        call    joined
        call    popped
        call    unpopped
        call    padded
        add     esp, 8
        .cfi_def_cfa_offset 4
        ret
        .cfi_endproc
        .size   _start, .-_start
```

## The conditional tail call fixture

Hand-written functions whose conditional jumps to the entry of a function only
the call frame information can tell apart. `maybe` jumps to `bump` before it
moves the stack pointer, so it calls `bump` as its tail, as Clang does.
`framed` jumps back to `framed.cold` with a word still pushed, which
`framed.cold` pops before it returns for `framed`, as GCC splits off the cold
part of a function, names it with a symbol of its own, and places it before
the hot part. `countdown` jumps back to its own entry on a condition and
`drain` without one, both of which loop.

| Fixture | Purpose |
| --- | --- |
| `elf_x64_condtail` | `maybe` calls `bump` as its tail on a condition; `framed` jumps to `framed.cold` with its frame open; `countdown` and `drain` loop back to their entries |

```
gcc -fuse-ld=lld -static -nostdlib condtail.s -o elf_x64_condtail
```

```asm
        .intel_syntax noprefix
        .text

        .globl  bump
        .type   bump, @function
bump:
        .cfi_startproc
        lea     eax, [rdi+1]
        ret
        .cfi_endproc
        .size   bump, .-bump

        .globl  maybe
        .type   maybe, @function
maybe:
        .cfi_startproc
        test    edi, edi
        jne     bump
        xor     eax, eax
        ret
        .cfi_endproc
        .size   maybe, .-maybe

        .type   framed.cold, @function
framed.cold:
        .cfi_startproc
        .cfi_def_cfa_offset 16
        .cfi_offset rbx, -16
        lea     eax, [rbx+1]
        pop     rbx
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   framed.cold, .-framed.cold

        .globl  framed
        .type   framed, @function
framed:
        .cfi_startproc
        push    rbx
        .cfi_def_cfa_offset 16
        .cfi_offset rbx, -16
        mov     ebx, edi
        test    ebx, ebx
        jne     framed.cold
        xor     eax, eax
        pop     rbx
        .cfi_def_cfa_offset 8
        ret
        .cfi_endproc
        .size   framed, .-framed

        .globl  countdown
        .type   countdown, @function
countdown:
        .cfi_startproc
        dec     edi
        jne     countdown
        xor     eax, eax
        ret
        .cfi_endproc
        .size   countdown, .-countdown

        .globl  drain
        .type   drain, @function
drain:
        .cfi_startproc
        test    edi, edi
        je      .Ldrained
        dec     edi
        jmp     drain
.Ldrained:
        xor     eax, eax
        ret
        .cfi_endproc
        .size   drain, .-drain

        .globl  _start
        .type   _start, @function
_start:
        .cfi_startproc
        mov     edi, 1
        call    maybe
        mov     edi, 1
        call    framed
        mov     edi, 3
        call    countdown
        mov     edi, 3
        call    drain
        ret
        .cfi_endproc
        .size   _start, .-_start
```

## The conditionally non-returning fixtures

Hand-written functions around libc's `error`, which never returns when its
first argument, the status, is non-zero. `wrap` passes its own first argument
on as the status, so it returns on the same condition, and `_start` calls it
with a zero status and then with one. `tailwrap` jumps to `error` with the
arguments it got, whereas `die` sets the status to one before it jumps. `pick`
passes its first argument on one path and its second on the other.

The rest call `exit` themselves, as gnulib's `error_tail` does, and return
only once they find their argument zero. `tail` keeps the status it gets in
ECX across a call, as Clang passes it, and `fail` calls it with one, whereas
`check` takes the status on the stack, as GCC passes it. `assure` is the other
way around, returning only once its argument is non-zero. The x86-64 fixture
has `wrap`, `_start` and `tail` alone, passing the status in a register. Both
link against the libc of the host without its start files, so that `error`
and `exit` are imports.

| Fixture | Purpose |
| --- | --- |
| `elf_x86_condnoret` | `wrap`, `tailwrap`, `die` and `pick` call `error` with a status taken from their own stack arguments or set to one; `tail`, `check` and `assure` call `exit` depending on their argument |
| `elf_x64_condnoret` | `wrap` calls `error` with the status it takes in RDI; `tail` calls `exit` unless that status is zero |

```
gcc -m32 -fuse-ld=lld -nostdlib -no-pie condnoret.s /usr/lib32/libc.so.6 \
    -o elf_x86_condnoret
gcc -fuse-ld=lld -nostdlib -no-pie condnoret64.s \
    /lib/x86_64-linux-gnu/libc.so.6 -o elf_x64_condnoret
```

```asm
        .intel_syntax noprefix
        .text

        .globl  _start
        .type   _start, @function
_start:
        push    0
        push    0
        call    wrap
        add     esp, 8
        push    0
        push    1
        call    wrap
        .size   _start, .-_start

        .globl  wrap
        .type   wrap, @function
wrap:
        push    DWORD PTR [esp+8]
        push    0
        push    DWORD PTR [esp+12]
        call    error@PLT
        add     esp, 12
        ret
        .size   wrap, .-wrap

        .globl  tailwrap
        .type   tailwrap, @function
tailwrap:
        jmp     error@PLT
        .size   tailwrap, .-tailwrap

        .globl  die
        .type   die, @function
die:
        mov     DWORD PTR [esp+4], 1
        jmp     error@PLT
        .size   die, .-die

        .globl  pick
        .type   pick, @function
pick:
        mov     eax, DWORD PTR [esp+12]
        test    eax, eax
        je      .Lp_b
        push    0
        push    0
        push    DWORD PTR [esp+12]
        call    error@PLT
        add     esp, 12
        ret
.Lp_b:
        push    0
        push    0
        push    DWORD PTR [esp+16]
        call    error@PLT
        add     esp, 12
        ret
        .size   pick, .-pick

        .globl  tail
        .type   tail, @function
tail:
        push    esi
        mov     esi, ecx
        push    0
        call    fflush@PLT
        add     esp, 4
        test    esi, esi
        jne     .Lt_exit
        pop     esi
        ret
.Lt_exit:
        push    esi
        call    exit@PLT
        .size   tail, .-tail

        .globl  fail
        .type   fail, @function
fail:
        mov     ecx, 1
        call    tail
        .size   fail, .-fail

        .globl  check
        .type   check, @function
check:
        mov     eax, DWORD PTR [esp+4]
        test    eax, eax
        je      .Lc_ret
        push    eax
        call    exit@PLT
.Lc_ret:
        ret
        .size   check, .-check

        .globl  assure
        .type   assure, @function
assure:
        cmp     DWORD PTR [esp+4], 0
        jne     .La_ret
        push    1
        call    exit@PLT
.La_ret:
        ret
        .size   assure, .-assure
```

```asm
        .intel_syntax noprefix
        .text

        .globl  _start
        .type   _start, @function
_start:
        sub     rsp, 8
        xor     edi, edi
        xor     esi, esi
        call    wrap
        mov     edi, 1
        xor     esi, esi
        call    wrap
        .size   _start, .-_start

        .globl  wrap
        .type   wrap, @function
wrap:
        sub     rsp, 8
        mov     rdx, rsi
        xor     esi, esi
        xor     eax, eax
        call    error@PLT
        add     rsp, 8
        ret
        .size   wrap, .-wrap

        .globl  tail
        .type   tail, @function
tail:
        push    rbx
        mov     ebx, edi
        xor     edi, edi
        call    fflush@PLT
        test    ebx, ebx
        je      .Lt_ret
        mov     edi, ebx
        call    exit@PLT
.Lt_ret:
        pop     rbx
        ret
        .size   tail, .-tail
```

## The shared conditionally non-returning fixture

Hand-written functions that reach one call to libc's `error` from two paths
each, which set the status before they reach it, so the block of the call sets
none of its own, as when a compiler merges the calls of several paths. Both
paths of `both` pass one, so the call never returns. `late` passes one on the
path it takes first, but zero on a path that only its jump table opens, so the
call returns once the table is read. `late` also ends the code, so what follows
it is the PLT stub of `error`, an import.

| Fixture | Purpose |
| --- | --- |
| `elf_x64_sharednoret` | `both` and `late` call `error` from a block that sets no status, reached from paths that pass one or, through the jump table of `late`, zero; `late` sits right before the PLT |

```
gcc -fuse-ld=lld -nostdlib -no-pie sharednoret.s \
    /lib/x86_64-linux-gnu/libc.so.6 -o elf_x64_sharednoret
```

```asm
        .intel_syntax noprefix
        .text

        .globl  _start
        .type   _start, @function
_start:
        xor     edi, edi
        call    both
        xor     edi, edi
        xor     esi, esi
        call    late
        hlt
        .size   _start, .-_start

        .globl  both
        .type   both, @function
both:
        test    edi, edi
        jne     .Lb_jmp
        mov     edi, 1
        xor     esi, esi
.Lb_call:
        call    error@PLT
        ret
.Lb_jmp:
        mov     edi, 1
        xor     esi, esi
        jmp     .Lb_call
        .size   both, .-both

        .globl  late
        .type   late, @function
late:
        test    esi, esi
        jne     .Ll_tbl
        mov     edi, 1
        xor     esi, esi
.Ll_call:
        call    error@PLT
        ret
.Ll_tbl:
        jmp     QWORD PTR [late_t+rdi*8]
.Ll_c0:
        xor     edi, edi
        xor     esi, esi
        jmp     .Ll_call
.Ll_c1:
        ret
        .size   late, .-late

        .section .rodata
        .p2align 3
late_t:
        .quad   .Ll_c0, .Ll_c1
        .quad   0
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

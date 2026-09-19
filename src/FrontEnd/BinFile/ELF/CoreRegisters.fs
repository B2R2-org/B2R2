(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*)

namespace B2R2.FrontEnd.BinFile.ELF

open System
open B2R2
open B2R2.FrontEnd.BinLifter

/// Provides the layout of the general register block that a core dump writes
/// into each of its NT_PRSTATUS notes. The block is an elf_gregset_t, whose
/// slots the kernel fixes per architecture in an order that follows no
/// numbering of the ISA, so reading it takes a table naming every slot and
/// saying how wide it is.
[<RequireQualifiedAccess>]
module internal CoreRegisters =
  /// Names the x86-64 slots, which follow the kernel's user_regs_struct.
  let private x64 =
    [| "R15"
       "R14"
       "R13"
       "R12"
       "RBP"
       "RBX"
       "R11"
       "R10"
       "R9"
       "R8"
       "RAX"
       "RCX"
       "RDX"
       "RSI"
       "RDI"
       "OrigRAX"
       "RIP"
       "CS"
       "EFLAGS"
       "RSP"
       "SS"
       "FSBase"
       "GSBase"
       "DS"
       "ES"
       "FS"
       "GS" |]

  /// Names the i386 slots, which are those of x86-64 in neither the registers
  /// they hold nor the places they hold them.
  let private x86 =
    [| "EBX"
       "ECX"
       "EDX"
       "ESI"
       "EDI"
       "EBP"
       "EAX"
       "DS"
       "ES"
       "FS"
       "GS"
       "OrigEAX"
       "EIP"
       "CS"
       "EFLAGS"
       "ESP"
       "SS" |]

  /// Names the AArch64 slots, which are the user_pt_regs of the kernel.
  let private aarch64 =
    [| for i in 0 .. 30 do yield $"x{i}"
       yield "sp"
       yield "pc"
       yield "pstate" |]

  /// Names the ARM32 slots, which are the sixteen general registers in order,
  /// then the status register and the syscall argument that r0 overwrote.
  let private arm32 =
    [| for i in 0 .. 8 do yield $"r{i}"
       yield "sb"
       yield "sl"
       yield "fp"
       yield "ip"
       yield "sp"
       yield "lr"
       yield "pc"
       yield "cpsr"
       yield "orig_r0" |]

  /// Names the RISCV64 slots, which are the program counter and then x1 to
  /// x31 in order, called by the ABI names that B2R2 prints them with.
  let private riscv64 =
    [| yield "pc"
       yield "ra"
       yield "sp"
       yield "gp"
       yield "tp"
       for i in 0 .. 2 do yield $"t{i}"
       yield "s0"
       yield "s1"
       for i in 0 .. 7 do yield $"a{i}"
       for i in 2 .. 11 do yield $"s{i}"
       for i in 3 .. 6 do yield $"t{i}" |]

  /// Names the PowerPC slots, which are the thirty-two general registers and
  /// then the whole of pt_regs, with four slots of padding to close it.
  let private ppc =
    [| for i in 0 .. 31 do yield $"r{i}"
       yield "iar"
       yield "msr"
       yield "orig_r3"
       yield "ctr"
       yield "lr"
       yield "xer"
       yield "ccr"
       yield "softe"
       yield "trap"
       yield "dar"
       yield "dsisr"
       yield "result"
       for _ in 1 .. 4 do yield "" |]

  /// Names the s390x slots together with their widths. The two halves of the
  /// PSW and the sixteen general registers are words, but the sixteen access
  /// registers are half as wide, which makes this the one layout whose slots
  /// are not all one size.
  let private s390x =
    [| yield "PSWMask", 8
       yield "PSWAddr", 8
       for i in 0 .. 15 do yield $"R{i}", 8
       for i in 0 .. 15 do yield $"ACR{i}", 4
       yield "OrigR2", 8 |]

  /// Names the MIPS general registers, which the kernel dumps in the order
  /// the ISA numbers them.
  let private mipsRegisters =
    [| "r0"
       "at"
       "v0"
       "v1"
       "a0"
       "a1"
       "a2"
       "a3"
       "t0"
       "t1"
       "t2"
       "t3"
       "t4"
       "t5"
       "t6"
       "t7"
       "s0"
       "s1"
       "s2"
       "s3"
       "s4"
       "s5"
       "s6"
       "s7"
       "t8"
       "t9"
       "k0"
       "k1"
       "gp"
       "sp"
       "fp"
       "ra" |]

  /// Names the MIPS slots of an o32 dump. Six slots the kernel leaves unset
  /// open the block, which is what puts the general registers at six rather
  /// than at zero. An unnamed slot is one this reader passes over.
  let private mips32 =
    [| for _ in 1 .. 6 do yield ""
       yield! mipsRegisters
       yield "lo"
       yield "hi"
       yield "pc"
       yield "badvaddr"
       yield "status"
       yield "cause"
       yield "" |]

  /// Names the MIPS slots of an n64 dump, which hold the same registers as an
  /// o32 one but start at zero and pad at the end instead.
  let private mips64 =
    [| yield! mipsRegisters
       yield "lo"
       yield "hi"
       yield "pc"
       yield "badvaddr"
       yield "status"
       yield "cause"
       for _ in 1 .. 7 do yield "" |]

  /// Names the SuperH slots, which are the pt_regs of the kernel.
  let private sh4 =
    [| for i in 0 .. 15 do yield $"r{i}"
       yield "pc"
       yield "pr"
       yield "sr"
       yield "gbr"
       yield "mach"
       yield "macl"
       yield "tra" |]

  /// Names the PA-RISC general registers, gr0 holding the flags word.
  let private pariscRegisters =
    [| "flags"
       "r1"
       "rp"
       "r3"
       "r4"
       "r5"
       "r6"
       "r7"
       "r8"
       "r9"
       "r10"
       "r11"
       "r12"
       "r13"
       "r14"
       "r15"
       "r16"
       "r17"
       "r18"
       "r19"
       "r20"
       "r21"
       "r22"
       "r23"
       "r24"
       "r25"
       "r26"
       "dp"
       "ret0"
       "ret1"
       "sp"
       "r31" |]

  /// Names the PA-RISC slots. The general and space registers open the block,
  /// then the two instruction address queues, then the control registers in
  /// an order of the kernel's own, and sixteen unset slots close it.
  let private hppa =
    [| yield! pariscRegisters
       for i in 0 .. 7 do yield $"sr{i}"
       yield "iaoq0"
       yield "iaoq1"
       yield "iasq0"
       yield "iasq1"
       yield "sar"
       yield "iir"
       yield "isr"
       yield "ior"
       yield "ipsw"
       yield "cr0"
       for i in 24 .. 31 do yield $"cr{i}"
       yield "cr8"
       yield "cr9"
       yield "cr12"
       yield "cr13"
       yield "cr10"
       yield "cr15"
       for _ in 1 .. 16 do yield "" |]

  /// Names the m68k slots together with their widths. The status register
  /// shares a slot with the stack adjustment and the format vector with the
  /// padding, both being half a slot wide.
  let private m68k =
    [| for i in 1 .. 7 do yield $"d{i}", 4
       for i in 0 .. 6 do yield $"a{i}", 4
       yield "d0", 4
       yield "usp", 4
       yield "orig_d0", 4
       yield "stkadj", 2
       yield "sr", 2
       yield "pc", 4
       yield "fmtvec", 2
       yield "", 2 |]

  /// Names the Alpha slots, which the kernel rearranges out of pt_regs into
  /// the numbering order of the ISA before it writes them: the thirty-one
  /// general registers, the program counter, and the thread's unique value.
  let private alpha =
    [| for i in 0 .. 30 do yield $"r{i}"
       yield "pc"
       yield "uniq" |]

  /// Names the SPARC V9 slots, which are the four register windows the trap
  /// saved and then the trap state itself.
  let private sparc64 =
    [| for i in 0 .. 7 do yield $"%%g{i}"
       for i in 0 .. 7 do yield $"%%o{i}"
       for i in 0 .. 7 do yield $"%%l{i}"
       for i in 0 .. 7 do yield $"%%i{i}"
       yield "%tstate"
       yield "pc"
       yield "npc"
       yield "y" |]

  /// Pairs every name with the width of a word of the class, which is what
  /// all but the s390x layout gives each of its slots.
  let private ofWords cls names =
    let width = WordSize.toByteWidth cls
    names |> Array.map (fun name -> name, width)

  /// Marks a MIPS file built for the n32 ABI, whose registers are twice as
  /// wide as the ELF32 class of the file would otherwise say.
  let [<Literal>] private MipsAbi2 = 0x20u

  /// Returns the slots of the general register block in the order that the
  /// machine lays them out, or none for a machine whose layout this reader
  /// does not know. The class has to agree as well as the machine: the x32
  /// ABI puts the x86-64 registers in an ELF32 file, and the MIPS n32 ABI
  /// puts n64 registers in one, which its own flag is what gives away.
  let tryFindLayout machine cls flags =
    match machine, cls with
    | MachineType.EM_X86_64, WordSize.Bit64 ->
      Some(ofWords cls x64)
    | MachineType.EM_386, WordSize.Bit32 ->
      Some(ofWords cls x86)
    | MachineType.EM_AARCH64, WordSize.Bit64 ->
      Some(ofWords cls aarch64)
    | MachineType.EM_ARM, WordSize.Bit32 ->
      Some(ofWords cls arm32)
    | MachineType.EM_RISCV, WordSize.Bit64 ->
      Some(ofWords cls riscv64)
    | MachineType.EM_PPC, WordSize.Bit32 ->
      Some(ofWords cls ppc)
    | MachineType.EM_PPC64, WordSize.Bit64 ->
      Some(ofWords cls ppc)
    | MachineType.EM_S390, WordSize.Bit64 ->
      Some s390x
    | MachineType.EM_SH, WordSize.Bit32 ->
      Some(ofWords cls sh4)
    | MachineType.EM_PARISC, WordSize.Bit32 ->
      Some(ofWords cls hppa)
    | MachineType.EM_68K, WordSize.Bit32 ->
      Some m68k
    | MachineType.EM_ALPHA, WordSize.Bit64 ->
      Some(ofWords cls alpha)
    | MachineType.EM_SPARCV9, WordSize.Bit64 ->
      Some(ofWords cls sparc64)
    | MachineType.EM_MIPS, WordSize.Bit64 ->
      Some(ofWords cls mips64)
    | MachineType.EM_MIPS, WordSize.Bit32 when flags &&& MipsAbi2 = 0u ->
      Some(ofWords cls mips32)
    | _, _ ->
      None

  let private readValue (reader: IBinReader) (block: byte[]) offset width =
    let span = ReadOnlySpan(block, offset, width)
    if width = 4 then uint64 (reader.ReadUInt32(span, 0))
    else reader.ReadUInt64(span, 0)

  /// Reads the general registers out of the block that a prstatus note holds,
  /// pairing every slot with the name it goes by. The block runs past the
  /// registers into the floating-point flag and the padding, and a dump may
  /// hold fewer slots than the layout names, so what fits is what is read. A
  /// slot the layout leaves unnamed is one the kernel keeps without filling,
  /// and it is passed over once its width has moved the cursor along.
  let read reader (layout: (string * int)[]) (block: byte[]) =
    let ends = Array.scan (fun off (_, width) -> off + width) 0 layout
    let isRead i = ends[i + 1] <= block.Length && fst layout[i] <> ""
    Array.init layout.Length id
    |> Array.filter isRead
    |> Array.map (fun i ->
      fst layout[i], readValue reader block ends[i] (snd layout[i]))

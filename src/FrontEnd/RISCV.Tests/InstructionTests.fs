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


namespace B2R2.FrontEnd.RISCV.Tests

open System
open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.RISCV
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins where control can go after an instruction, which is what a CFG is
/// built from. The RV64 encodings come from a gcc -O2 riscv64 build of
/// coreutils ls, and the RV32 ones from a clang -Oz riscv32 build of binutils
/// objdump, whose outlined functions are called through t0.
[<TestClass>]
type InstructionTests() =
  static let parserOf wordSize =
    let isa = ISA(Architecture.RISCV, Endian.Little, wordSize)
    Parser(isa, BinReader.Init Endian.Little) :> IInstructionParsable

  static let parser64 = parserOf WordSize.Bit64

  static let parser32 = parserOf WordSize.Bit32

  static let parseWith (parser: IInstructionParsable) addr hex =
    let bytes = ByteArray.ofHexString hex
    parser.Parse(ReadOnlySpan bytes, addr)

  static let parse64 addr hex = parseWith parser64 addr hex

  static let parse32 addr hex = parseWith parser32 addr hex

  static let nexts (ins: IInstruction) = ins.GetNextInstrAddrs()

  [<TestMethod>]
  member _.``[RISCV64] a conditional branch also falls through``() =
    let ins = parse64 0x50f4UL "639bd700" (* bne a5, a3, 0x510a *)
    Assert.AreEqual<bool>(true, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0x50f8UL; 0x510aUL |], nexts ins)

  [<TestMethod>]
  member _.``[RISCV64] a compressed branch also falls through``() =
    let ins = parse64 0x4f7aUL "11c1" (* c.beqz a0, 0x4f7e *)
    Assert.AreEqual<bool>(true, ins.IsCondBranch)
    CollectionAssert.AreEqual([| 0x4f7cUL; 0x4f7eUL |], nexts ins)

  (* The low bit of funct3 negates the condition, as the low bit of a
     condition code does on Intel. *)
  [<TestMethod>]
  member _.``[RISCV64] a branch on a negated condition jumps on false``() =
    let onTrue hex = (parse64 0x1000UL hex).IsCJmpOnTrue
    Assert.AreEqual<bool>(true, onTrue "63050900") (* beq s2, zero, 0x100a *)
    Assert.AreEqual<bool>(false, onTrue "639bd700") (* bne a5, a3, 0x1016 *)
    Assert.AreEqual<bool>(true, onTrue "634a0500") (* blt a0, zero, 0x1014 *)
    Assert.AreEqual<bool>(false, onTrue "63540500") (* bge a0, zero, 0x1008 *)
    Assert.AreEqual<bool>(true, onTrue "63e6e700") (* bltu a5, a4, 0x100c *)
    Assert.AreEqual<bool>(false, onTrue "63f4aa00") (* bgeu s5, a0, 0x1008 *)
    Assert.AreEqual<bool>(true, onTrue "11c1") (* c.beqz a0, 0x1004 *)
    Assert.AreEqual<bool>(false, onTrue "e5f9") (* c.bnez a1, 0xff0 *)

  [<TestMethod>]
  member _.``[RISCV64] a jump that links nothing goes to its target only``() =
    let jumps =
      [ 0x5268UL, "6f10e014", 0x63b6UL (* jal zero, 0x63b6 *)
        0x4feaUL, "39a0", 0x4ff8UL (* c.j 0x4ff8 *) ]
    for addr, hex, target in jumps do
      let ins = parse64 addr hex
      Assert.AreEqual<bool>(false, ins.IsCall, hex)
      CollectionAssert.AreEqual([| target |], nexts ins, hex)

  [<TestMethod>]
  member _.``[RISCV64] a call returns to the next instruction``() =
    let ins = parse64 0x4f6eUL "eff03fea" (* jal ra, 0x4e10 *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    CollectionAssert.AreEqual([| 0x4f72UL; 0x4e10UL |], nexts ins)

  [<TestMethod>]
  member _.``[RISCV32] a compressed call returns to the next instruction``() =
    let ins = parse32 0x11fbeUL "493f" (* c.jal 0x11f50 *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    CollectionAssert.AreEqual([| 0x11fc0UL; 0x11f50UL |], nexts ins)

  (* x5 is a link as much as x1 is, which code calls through where x1 has to
     survive, and returns through, as the outlined functions of LLVM do. *)
  [<TestMethod>]
  member _.``[RISCV32] a call through t0 returns through t0``() =
    let call = parse32 0x12258UL "ef22b20d" (* jal t0, 0x34b32 *)
    Assert.AreEqual<bool>(true, call.IsCall)
    CollectionAssert.AreEqual([| 0x1225cUL; 0x34b32UL |], nexts call)
    let ret = parse32 0x18dbeUL "8282" (* c.jr t0 *)
    Assert.AreEqual<bool>(true, ret.IsRET)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ret)

  [<TestMethod>]
  member _.``[RISCV64] an indirect call returns to the next instruction``() =
    let ins = parse64 0x505cUL "8297" (* c.jalr a5 *)
    Assert.AreEqual<bool>(true, ins.IsCall)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
    CollectionAssert.AreEqual([| 0x505eUL |], nexts ins)

  [<TestMethod>]
  member _.``[RISCV64] a return has no static next address``() =
    let ins = parse64 0x4f9eUL "8280" (* c.jr ra *)
    Assert.AreEqual<bool>(true, ins.IsRET)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  [<TestMethod>]
  member _.``[RISCV64] an indirect jump has no static next address``() =
    let ins = parse64 0x527aUL "8287" (* c.jr a5 *)
    Assert.AreEqual<bool>(false, ins.IsRET)
    Assert.AreEqual<bool>(true, ins.IsIndirectBranch)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  (* A PLT entry keeps the address after its jump in t1, which tells the lazy
     resolver which entry jumped, so the jump is no call: the function it
     reaches returns to the caller of the entry. *)
  [<TestMethod>]
  member _.``[RISCV64] a jump that keeps its address in t1 is no call``() =
    let ins = parse64 0x47f8UL "67030e00" (* jalr t1, 0(t3) *)
    Assert.AreEqual<bool>(false, ins.IsCall)
    Assert.AreEqual<bool>(false, ins.IsRET)
    CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins)

  (* EBREAK returns, if at all, to the instruction itself, so control never
     reaches the next one, which glibc leaves after the call that never
     returns in _start, and GCC after __builtin_trap. *)
  [<TestMethod>]
  member _.``[RISCV64] a breakpoint has no next address``() =
    let traps =
      [ "0290" (* c.ebreak *)
        "73001000" (* ebreak *) ]
    for hex in traps do
      let ins = parse64 0x6744UL hex
      Assert.AreEqual<bool>(true, ins.IsTerminator null, hex)
      CollectionAssert.AreEqual(Array.empty<Addr>, nexts ins, hex)

  [<TestMethod>]
  member _.``[RISCV64] a system call ends a block and falls through``() =
    let ins = parse64 0x1000UL "73000000" (* ecall *)
    Assert.AreEqual<bool>(true, ins.IsTerminator null)
    CollectionAssert.AreEqual([| 0x1004UL |], nexts ins)

  [<TestMethod>]
  member _.``[RISCV64] a nop falls through``() =
    let nops =
      [ "13000000", 0x4800UL (* nop *)
        "0100", 0x47feUL (* c.nop *) ]
    for hex, next in nops do
      let ins = parse64 0x47fcUL hex
      Assert.AreEqual<bool>(true, ins.IsNop, hex)
      CollectionAssert.AreEqual([| next |], nexts ins, hex)

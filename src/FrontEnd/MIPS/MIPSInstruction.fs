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

namespace B2R2.FrontEnd.MIPS

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for a MIPS instruction used by our
/// disassembler and lifter.
type MIPSInstruction (addr, numBytes, insInfo, wordSize) =
  inherit Instruction (addr, numBytes, wordSize)

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override this.IsBranch () =
    match this.Info.Opcode with
    | Opcode.B | Opcode.BAL | Opcode.BEQ | Opcode.BGEZ | Opcode.BGEZAL
    | Opcode.BGTZ | Opcode.BLEZ | Opcode.BLTZ | Opcode.BNE
    | Opcode.JALR | Opcode.JALRHB | Opcode.JR | Opcode.JRHB
    | Opcode.J | Opcode.JAL | Opcode.BC1F | Opcode.BC1T -> true
    | _ -> false

  override _.IsModeChanging () = false

  member this.HasConcJmpTarget () =
    match this.Info.Operands with
    | OneOperand (OpAddr _)
    | TwoOperands (_, OpAddr _)
    | ThreeOperands (_, _, OpAddr _)
    | OneOperand (OpImm _) -> true
    | _ -> false

  override this.IsDirectBranch () =
    this.IsBranch () && this.HasConcJmpTarget ()

  override this.IsIndirectBranch () =
    this.IsBranch () && (not <| this.HasConcJmpTarget ())

  override this.IsCondBranch () =
    match this.Info.Opcode with
    | Opcode.BEQ | Opcode.BLTZ | Opcode.BLEZ | Opcode.BGTZ | Opcode.BGEZ
    | Opcode.BGEZAL | Opcode.BNE | Opcode.BC1F | Opcode.BC1T -> true
    | _ -> false

  override this.IsCJmpOnTrue () =
    match this.Info.Opcode with
    | Opcode.BEQ | Opcode.BLTZ | Opcode.BLEZ | Opcode.BGTZ | Opcode.BGEZ
    | Opcode.BGEZAL | Opcode.BC1T -> true
    | _ -> false

  override this.IsCall () =
    match this.Info.Opcode with
    | Opcode.BAL | Opcode.BGEZAL | Opcode.JALR | Opcode.JALRHB | Opcode.JAL ->
      true
    | _ -> false

  override this.IsRET () =
    match this.Info.Opcode with
    | Opcode.JR ->
      match this.Info.Operands with
      | OneOperand (OpReg Register.R31) -> true
      | _ -> false
    | _ -> false

  override this.IsInterrupt () =
    match this.Info.Opcode with
    | Opcode.SYSCALL | Opcode.WAIT -> true
    | _ -> false

  override this.IsExit () =
    match this.Info.Opcode with
    | Opcode.DERET | Opcode.ERET | Opcode.ERETNC -> true
    | _ -> false

  override this.IsTerminator () =
       this.IsBranch ()
    || this.IsInterrupt ()
    || this.IsExit ()

  override this.DirectBranchTarget (addr: byref<Addr>) =
    if this.IsBranch () then
      match this.Info.Operands with
      | OneOperand (OpAddr (Relative offset)) ->
        addr <- (int64 this.Address + offset) |> uint64
        true
      | TwoOperands (_, OpAddr (Relative offset)) ->
        addr <- (int64 this.Address + offset) |> uint64
        true
      | ThreeOperands (_, _,OpAddr (Relative offset)) ->
        addr <- (int64 this.Address + offset) |> uint64
        true
      | OneOperand (OpImm (imm)) ->
        addr <- imm
        true
      | _ -> false
    else false

  override this.IndirectTrampolineAddr (_addr: byref<Addr>) =
    if this.IsIndirectBranch () then Terminator.futureFeature ()
    else false

  override this.Immediate (v: byref<int64>) =
    match this.Info.Operands with
    | OneOperand (OpImm (c))
    | TwoOperands (OpImm (c), _)
    | TwoOperands (_, OpImm (c))
    | ThreeOperands (OpImm (c), _, _)
    | ThreeOperands (_, OpImm (c), _)
    | ThreeOperands (_, _, OpImm (c))
    | FourOperands (OpImm (c), _, _, _)
    | FourOperands (_, OpImm (c), _, _)
    | FourOperands (_, _, OpImm (c), _)
    | FourOperands (_, _, _, OpImm (c)) -> v <- int64 c; true
    | _ -> false

  override _.GetNextInstrAddrs () = Terminator.futureFeature ()

  override _.InterruptNum (_num: byref<int64>) = Terminator.futureFeature ()

  override this.IsNop () =
    this.Info.Opcode = Opcode.NOP

  override this.Translate builder =
    let builder = builder :?> LowUIRBuilder
    (Lifter.translate this.Info numBytes builder).Stream.ToStmts ()

  override this.TranslateToList builder =
    let builder = builder :?> LowUIRBuilder
    (Lifter.translate this.Info numBytes builder).Stream

  override this.Disasm builder =
    Disasm.disasm this.Info builder
    builder.ToString ()

  override this.Disasm () =
    let builder = StringDisasmBuilder (false, null, wordSize)
    Disasm.disasm this.Info builder
    builder.ToString ()

  override this.Decompose builder =
    Disasm.disasm this.Info builder
    builder.ToAsmWords ()

  override _.IsInlinedAssembly () = false

  override _.Equals (_) = Terminator.futureFeature ()

  override _.GetHashCode () = Terminator.futureFeature ()

// vim: set tw=80 sts=2 sw=2:

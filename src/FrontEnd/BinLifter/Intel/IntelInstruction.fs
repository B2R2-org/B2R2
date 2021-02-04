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

namespace B2R2.FrontEnd.BinLifter.Intel

open B2R2
open B2R2.FrontEnd.BinLifter

module private Dummy =
  let ctxt = ParsingContext.Init ()
  let helper = DisasmHelper ()

/// The internal representation for an Intel instruction used by our
/// disassembler and lifter.
type IntelInstruction (addr, len, insInfo, wordSz) =
  inherit Instruction (addr, len, wordSz)

  /// Basic instruction info.
  member __.Info with get(): InsInfo = insInfo

  override __.NextParsingContext with get() = Dummy.ctxt

  override __.AuxParsingContext with get() = None

  override __.IsBranch () =
    Helper.isBranch __.Info.Opcode

  member __.HasConcJmpTarget () =
    match __.Info.Operands with
    | OneOperand (OprDirAddr _) -> true
    | _ -> false

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () =
    match __.Info.Opcode with
    | Opcode.JA | Opcode.JB | Opcode.JBE | Opcode.JCXZ | Opcode.JECXZ
    | Opcode.JG | Opcode.JL | Opcode.JLE | Opcode.JNB | Opcode.JNL | Opcode.JNO
    | Opcode.JNP | Opcode.JNS | Opcode.JNZ | Opcode.JO | Opcode.JP
    | Opcode.JRCXZ | Opcode.JS | Opcode.JZ | Opcode.LOOP | Opcode.LOOPE
    | Opcode.LOOPNE -> true
    | _ -> false

  override __.IsCJmpOnTrue () =
    __.IsCondBranch ()
    && match __.Info.Opcode with
       | Opcode.JA | Opcode.JB | Opcode.JBE | Opcode.JCXZ | Opcode.JECXZ
       | Opcode.JG | Opcode.JL | Opcode.JLE | Opcode.JO | Opcode.JP
       | Opcode.JRCXZ | Opcode.JS | Opcode.JZ | Opcode.LOOP | Opcode.LOOPE ->
         true
       | _ -> false

  override __.IsCall () =
    match __.Info.Opcode with
    | Opcode.CALLFar | Opcode.CALLNear -> true
    | _ -> false

  override __.IsRET () =
    match __.Info.Opcode with
    | Opcode.RETFar | Opcode.RETFarImm | Opcode.RETNear | Opcode.RETNearImm ->
      true
    | _ -> false

  override __.IsInterrupt () =
    match __.Info.Opcode with
    | Opcode.INT | Opcode.INT3 | Opcode.INTO | Opcode.SYSCALL | Opcode.SYSENTER
      -> true
    | _ -> false

  override __.IsExit () =
    match __.Info.Opcode with
    (* Compiler sometimes inserts HLT in user-level code to raise a fault. *)
    | Opcode.HLT
    (* Invalid OP exceptions usually don't return from the handler. *)
    | Opcode.UD2
    | Opcode.SYSEXIT | Opcode.SYSRET
    | Opcode.IRET | Opcode.IRETW | Opcode.IRETD | Opcode.IRETQ -> true
    | _ -> false

  override __.IsBBLEnd () =
       __.IsBranch ()
    || __.IsInterrupt ()
    || __.IsExit ()

  override __.DirectBranchTarget (addr: byref<Addr>) =
    if __.IsBranch () then
      match __.Info.Operands with
      | OneOperand (OprDirAddr (Absolute (_))) -> Utils.futureFeature ()
      | OneOperand (OprDirAddr (Relative offset)) ->
        addr <- (int64 __.Address + offset) |> uint64
        true
      | _ -> false
    else false

  override __.IndirectTrampolineAddr (addr: byref<Addr>) =
    if __.IsIndirectBranch () then
      match __.Info.Operands with
      | OneOperand (OprMem (None, None, Some disp, _)) ->
        addr <- uint64 disp; true
      | OneOperand (OprMem (Some Register.RIP, None, Some disp, _)) ->
        addr <- __.Address + uint64 __.Length + uint64 disp
        true
      | _ -> false
    else false

  member private __.AddBranchTargetIfExist addrs =
    match __.DirectBranchTarget () |> Utils.tupleToOpt with
    | None -> addrs
    | Some target ->
      Seq.singleton (target, ArchOperationMode.NoMode) |> Seq.append addrs

  override __.GetNextInstrAddrs () =
    let acc =
      Seq.singleton (__.Address + uint64 __.Length, ArchOperationMode.NoMode)
    if __.IsCall () then acc |> __.AddBranchTargetIfExist
    elif __.IsDirectBranch () || __.IsIndirectBranch () then
      if __.IsCondBranch () then acc |> __.AddBranchTargetIfExist
      else __.AddBranchTargetIfExist Seq.empty
    elif __.Info.Opcode = Opcode.HLT then Seq.empty
    elif __.Info.Opcode = Opcode.UD2 then Seq.empty
    else acc

  override __.InterruptNum (num: byref<int64>) =
    if __.Info.Opcode = Opcode.INT then
      match __.Info.Operands with
      | OneOperand (OprImm (n, _)) ->
        num <- n
        true
      | _ -> false
    else false

  override __.IsNop () =
    __.Info.Opcode = Opcode.NOP

  override __.Translate ctxt =
    Lifter.translate __.Info len ctxt

  override __.Disasm (showAddr, resolveSymbol, disasmHelper) =
    let helper = if resolveSymbol then disasmHelper else Dummy.helper
    let builder = DisasmStringBuilder ()
    Disasm.disasm showAddr wordSz helper __.Info addr len builder
    builder.Finalize ()

  override __.Disasm () =
    let builder = DisasmStringBuilder ()
    Disasm.disasm false wordSz Dummy.helper __.Info addr len builder
    builder.Finalize ()

  override __.Decompose (showAddr) =
    let builder = DisasmWordBuilder (8)
    Disasm.disasm showAddr wordSz Dummy.helper __.Info addr len builder
    builder.Finalize ()

// vim: set tw=80 sts=2 sw=2:

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
open System.Text

/// The internal representation for an Intel instruction used by our
/// disassembler and lifter.
type IntelInstruction (addr, len, insInfo, wordSz) =
  inherit Instruction (addr, len, wordSz)

  let defaultCtxt = ParsingContext.Init ()
  let dummyHelper = DisasmHelper ()

  /// Basic instruction info.
  member val Info: InsInfo = insInfo

  override __.NextParsingContext with get() = defaultCtxt

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
       __.IsDirectBranch ()
    || __.IsIndirectBranch ()
    || __.Info.Opcode = Opcode.HLT
    || __.Info.Opcode = Opcode.INT
    || __.Info.Opcode = Opcode.INT3
    || __.Info.Opcode = Opcode.INTO
    || __.Info.Opcode = Opcode.SYSCALL
    || __.Info.Opcode = Opcode.SYSENTER
    || __.Info.Opcode = Opcode.SYSEXIT
    || __.Info.Opcode = Opcode.SYSRET
    || __.Info.Opcode = Opcode.UD2

  override __.DirectBranchTarget (addr: byref<Addr>) =
    if __.IsBranch () then
      match __.Info.Operands with
      | OneOperand (OprDirAddr (Absolute (_))) -> failwith "Implement" // XXX
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
      | OneOperand (OprImm n) ->
        num <- n
        true
      | _ -> false
    else false

  override __.IsNop () =
    __.Info.Opcode = Opcode.NOP

  override __.Translate ctxt =
    Lifter.translate __.Info addr len ctxt

  member private __.StrBuilder _ (str: string) (sb: StringBuilder) =
    sb.Append str

  override __.Disasm (showAddr, resolveSymbol, disasmHelper) =
    let helper = if resolveSymbol then disasmHelper else dummyHelper
    StringBuilder ()
    |> Disasm.disasm showAddr wordSz helper __.Info addr len __.StrBuilder
    |> fun sb -> sb.ToString ()

  override __.Disasm () =
    StringBuilder ()
    |> Disasm.disasm false wordSz dummyHelper __.Info addr len __.StrBuilder
    |> fun sb -> sb.ToString ()

  member private __.WordBuilder kind str (acc: AsmWordBuilder) =
    acc.Append ({ AsmWordKind = kind; AsmWordValue = str })

  override __.Decompose (showAddr) =
    AsmWordBuilder (8)
    |> Disasm.disasm showAddr wordSz dummyHelper __.Info addr len __.WordBuilder
    |> fun b -> b.Finish ()

// vim: set tw=80 sts=2 sw=2:

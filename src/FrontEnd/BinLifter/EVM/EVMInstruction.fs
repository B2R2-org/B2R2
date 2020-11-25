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

namespace B2R2.FrontEnd.BinLifter.EVM

open B2R2
open B2R2.FrontEnd.BinLifter
open System.Text

/// The internal representation for a EVM instruction used by our
/// disassembler and lifter.
type EVMInstruction (addr, numBytes, insInfo, wordSize) =
  inherit Instruction (addr, numBytes, wordSize)

  let defaultCtxt = ParsingContext.Init ()

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override __.NextParsingContext = defaultCtxt

  override __.AuxParsingContext with get() = None

  override __.IsBranch () =
    match __.Info.Opcode with
    | Opcode.JUMP
    | Opcode.JUMPI -> true
    | _ -> false

  member __.HasConcJmpTarget () = false

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () =
    match __.Info.Opcode with
    | Opcode.JUMPI -> true
    | _ -> false

  override __.IsCJmpOnTrue () =
    match __.Info.Opcode with
    | Opcode.JUMPI -> true
    | _ -> false

  override __.IsCall () = false

  override __.IsRET () =
    match __.Info.Opcode with
    | Opcode.REVERT
    | Opcode.RETURN -> true
    | _ -> false

  override __.IsInterrupt () = Utils.futureFeature ()

  member private __.IsHaltingInstruction () =
    __.Info.Opcode = Opcode.REVERT
    || __.Info.Opcode = Opcode.RETURN
    || __.Info.Opcode = Opcode.SELFDESTRUCT
    || __.Info.Opcode = Opcode.INVALID
    || __.Info.Opcode = Opcode.STOP

  override __.IsExit () =
    __.IsDirectBranch ()
    || __.IsIndirectBranch ()
    || __.Info.Opcode = Opcode.REVERT
    || __.Info.Opcode = Opcode.RETURN
    || __.Info.Opcode = Opcode.SELFDESTRUCT
    || __.Info.Opcode = Opcode.INVALID
    || __.Info.Opcode = Opcode.STOP

  override __.DirectBranchTarget (addr: byref<Addr>) = false

  override __.IndirectTrampolineAddr (addr: byref<Addr>) =
    // FIXME
    false

  override __.GetNextInstrAddrs () =
    let fallthrough = __.Address + uint64 __.Length
    let acc = Seq.singleton (fallthrough, ArchOperationMode.NoMode)
    if __.IsHaltingInstruction () then Seq.empty
    else acc

  override __.InterruptNum (num: byref<int64>) = Utils.futureFeature ()

  override __.IsNop () = false

  override __.Translate ctxt =
    Lifter.translate __.Info ctxt

  member private __.StrBuilder _ (str: string) (acc: StringBuilder) =
    acc.Append (str)

  override __.Disasm (showAddr, _resolveSymbol, _fileInfo) =
    StringBuilder ()
    |> Disasm.disasm showAddr __.Info __.StrBuilder
    |> fun acc -> acc.ToString ()

  override __.Disasm () =
    StringBuilder ()
    |> Disasm.disasm false __.Info __.StrBuilder
    |> fun acc -> acc.ToString ()

  member private __.WordBuilder kind str (acc: AsmWordBuilder) =
    acc.Append ({ AsmWordKind = kind; AsmWordValue = str })

  override __.Decompose (showAddr) =
    AsmWordBuilder (8)
    |> Disasm.disasm showAddr __.Info __.WordBuilder
    |> fun b -> b.Finish ()

// vim: set tw=80 sts=2 sw=2:

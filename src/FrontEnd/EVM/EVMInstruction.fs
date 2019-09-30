(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Seung Il Jung <sijung@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.FrontEnd.EVM

open B2R2

/// The internal representation for a EVM instruction used by our
/// disassembler and lifter.
type EVMInstruction (addr, numBytes, insInfo, wordSize) =
  inherit FrontEnd.Instruction (addr, numBytes, wordSize)

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override __.IsBranch () =
    match __.Info.Opcode with
    | Opcode.JUMP -> true
    | _ -> false

  member __.HasConcJmpTarget () = false

  override __.IsDirectBranch () =
    __.IsBranch () && __.HasConcJmpTarget ()

  override __.IsIndirectBranch () =
    __.IsBranch () && (not <| __.HasConcJmpTarget ())

  override __.IsCondBranch () =
    match __.Info.Opcode with
    | Opcode.JUMP -> true
    | _ -> false

  override __.IsCJmpOnTrue () =
    match __.Info.Opcode with
    | Opcode.JUMP -> true
    | _ -> false

  override __.IsCall () =
    match __.Info.Opcode with
    | Opcode.JUMP -> true
    | _ -> false

  override __.IsRET () = false // XXX

  override __.IsInterrupt () = Utils.futureFeature ()

  override __.IsExit () = // FIXME
    __.IsDirectBranch () ||
    __.IsIndirectBranch ()

  override __.DirectBranchTarget (addr: byref<Addr>) = false

  override __.IndirectTrampolineAddr (addr: byref<Addr>) =
    // FIXME
    false

  override __.GetNextInstrAddrs () =
    let fallthrough = __.Address + uint64 __.Length
    let acc = Seq.singleton (fallthrough, ArchOperationMode.NoMode)
    // FIXME
    acc

  override __.InterruptNum (num: byref<int64>) = Utils.futureFeature ()

  override __.IsNop () = false

  override __.Translate ctxt =
    Lifter.translate __.Info ctxt

  override __.Disasm (showAddr, _resolveSymbol, _fileInfo) =
    Disasm.disasm showAddr __.Info

  override __.Disasm () =
    Disasm.disasm false __.Info

  override __.Decompose () =
    [||] // FIXME

// vim: set tw=80 sts=2 sw=2:

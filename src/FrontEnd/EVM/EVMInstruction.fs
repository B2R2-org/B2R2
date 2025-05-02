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

namespace B2R2.FrontEnd.EVM

open B2R2
open B2R2.FrontEnd.BinLifter

/// The internal representation for a EVM instruction used by our
/// disassembler and lifter.
type EVMInstruction (addr, numBytes, insInfo, wordSize) =
  inherit Instruction (addr, numBytes, wordSize)

  /// Basic instruction information.
  member val Info: InsInfo = insInfo

  override this.IsBranch () =
    match this.Info.Opcode with
    | Opcode.JUMP
    | Opcode.JUMPI -> true
    | _ -> false

  override _.IsModeChanging () = false

  member _.HasConcJmpTarget () = false

  override this.IsDirectBranch () =
    this.IsBranch () && this.HasConcJmpTarget ()

  override this.IsIndirectBranch () =
    this.IsBranch () && (not <| this.HasConcJmpTarget ())

  override this.IsCondBranch () =
    match this.Info.Opcode with
    | Opcode.JUMPI -> true
    | _ -> false

  override this.IsCJmpOnTrue () =
    match this.Info.Opcode with
    | Opcode.JUMPI -> true
    | _ -> false

  override _.IsCall () = false

  override this.IsRET () =
    match this.Info.Opcode with
    | Opcode.RETURN -> true
    | _ -> false

  override _.IsInterrupt () = Terminator.futureFeature ()

  override this.IsExit () =
    this.Info.Opcode = Opcode.REVERT
    || this.Info.Opcode = Opcode.RETURN
    || this.Info.Opcode = Opcode.SELFDESTRUCT
    || this.Info.Opcode = Opcode.INVALID
    || this.Info.Opcode = Opcode.STOP

  override this.IsTerminator () =
    this.IsDirectBranch ()
    || this.IsIndirectBranch ()
    || this.Info.Opcode = Opcode.REVERT
    || this.Info.Opcode = Opcode.RETURN
    || this.Info.Opcode = Opcode.SELFDESTRUCT
    || this.Info.Opcode = Opcode.INVALID
    || this.Info.Opcode = Opcode.STOP

  override _.DirectBranchTarget (_addr: byref<Addr>) = false

  override _.IndirectTrampolineAddr (_addr: byref<Addr>) = false

  override _.Immediate _ = false

  override this.GetNextInstrAddrs () =
    let fallthrough = this.Address + uint64 this.Length
    let acc = [| (fallthrough, ArchOperationMode.NoMode) |]
    if this.IsExit () then [||]
    else acc

  override _.InterruptNum (_num: byref<int64>) = Terminator.futureFeature ()

  override _.IsNop () = false

  override this.Translate builder =
    (Lifter.translate this.Info builder).Stream.ToStmts ()

  override this.TranslateToList builder =
    (Lifter.translate this.Info builder).Stream

  override this.Disasm builder =
    Disasm.disasm this.Info builder
    builder.ToString ()

  override this.Disasm () =
    let builder = StringDisasmBuilder (false, null, WordSize.Bit256)
    Disasm.disasm this.Info builder
    builder.ToString ()

  override this.Decompose builder =
    Disasm.disasm this.Info builder
    builder.ToAsmWords ()

  override _.IsInlinedAssembly () = false

  override _.Equals _ = Terminator.futureFeature ()

  override _.GetHashCode () = Terminator.futureFeature ()

// vim: set tw=80 sts=2 sw=2:

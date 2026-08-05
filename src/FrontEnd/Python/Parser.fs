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
namespace B2R2.FrontEnd.Python

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter

/// Represents a parser for Python instructions.
type PythonParser(binFile: IBinFile, reader) =
  let binFile = binFile :?> PythonBinFile

  (* One object per version, bundling everything that depends on which
     version's Opcode enum the raw opcode value belongs to. Instruction holds
     one of these instead of matching on opcodes itself. *)
  let semantics310 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python310.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python310.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python310.Semantics.isBranch ins
        member _.IsCondBranch ins = Python310.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python310.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python310.Semantics.isCall ins
        member _.IsRET ins = Python310.Semantics.isRET ins
        member _.IsExit ins = Python310.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python310.Opcode.NOP
        member _.HasFlag ins = Python310.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python310.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python310.Semantics.branchTarget ins ft n }

  let semantics312 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python312.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python312.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python312.Semantics.isBranch ins
        member _.IsCondBranch ins = Python312.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python312.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python312.Semantics.isCall ins
        member _.IsRET ins = Python312.Semantics.isRET ins
        member _.IsExit ins = Python312.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python312.Opcode.NOP
        member _.HasFlag ins = Python312.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python312.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python312.Semantics.branchTarget ins ft n }

  (* Adding a version means adding its directory and one entry here, and
     touching nothing another version's author also edits. *)
  let parse span addr =
    match binFile.Version with
    | PythonVersion.Python310 ->
      Python310.Parsing.parse semantics310 span reader binFile addr
    | PythonVersion.Python312 ->
      Python312.Parsing.parse semantics312 span reader binFile addr
    | v ->
      failwithf "Unsupported Python version for parsing: %A" v

  interface IInstructionParsable with
    member _.MaxInstructionSize = 4

    member _.InstructionAlignment = 1

    member _.Parse(span: ByteSpan, addr: Addr) =
      try parse span addr :> IInstruction
      with e when not (Terminator.isCritical e) -> raise ParsingFailureException

    member _.Parse(_bs: byte[], _addr: Addr) =
      Terminator.futureFeature () :> IInstruction

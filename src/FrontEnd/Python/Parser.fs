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
  let semantics300 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python300.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python300.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python300.Semantics.isBranch ins
        member _.IsCondBranch ins = Python300.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python300.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python300.Semantics.isCall ins
        member _.IsRET ins = Python300.Semantics.isRET ins
        member _.IsExit ins = Python300.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python300.Opcode.NOP
        member _.HasFlag ins = Python300.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python300.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python300.Semantics.branchTarget ins ft n }

  let semantics301 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python301.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python301.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python301.Semantics.isBranch ins
        member _.IsCondBranch ins = Python301.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python301.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python301.Semantics.isCall ins
        member _.IsRET ins = Python301.Semantics.isRET ins
        member _.IsExit ins = Python301.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python301.Opcode.NOP
        member _.HasFlag ins = Python301.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python301.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python301.Semantics.branchTarget ins ft n }

  let semantics302 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python302.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python302.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python302.Semantics.isBranch ins
        member _.IsCondBranch ins = Python302.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python302.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python302.Semantics.isCall ins
        member _.IsRET ins = Python302.Semantics.isRET ins
        member _.IsExit ins = Python302.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python302.Opcode.NOP
        member _.HasFlag ins = Python302.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python302.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python302.Semantics.branchTarget ins ft n }

  let semantics303 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python303.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python303.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python303.Semantics.isBranch ins
        member _.IsCondBranch ins = Python303.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python303.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python303.Semantics.isCall ins
        member _.IsRET ins = Python303.Semantics.isRET ins
        member _.IsExit ins = Python303.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python303.Opcode.NOP
        member _.HasFlag ins = Python303.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python303.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python303.Semantics.branchTarget ins ft n }

  let semantics304 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python304.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python304.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python304.Semantics.isBranch ins
        member _.IsCondBranch ins = Python304.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python304.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python304.Semantics.isCall ins
        member _.IsRET ins = Python304.Semantics.isRET ins
        member _.IsExit ins = Python304.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python304.Opcode.NOP
        member _.HasFlag ins = Python304.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python304.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python304.Semantics.branchTarget ins ft n }

  let semantics305 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python305.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python305.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python305.Semantics.isBranch ins
        member _.IsCondBranch ins = Python305.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python305.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python305.Semantics.isCall ins
        member _.IsRET ins = Python305.Semantics.isRET ins
        member _.IsExit ins = Python305.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python305.Opcode.NOP
        member _.HasFlag ins = Python305.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python305.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python305.Semantics.branchTarget ins ft n }

  let semantics306 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python306.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python306.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python306.Semantics.isBranch ins
        member _.IsCondBranch ins = Python306.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python306.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python306.Semantics.isCall ins
        member _.IsRET ins = Python306.Semantics.isRET ins
        member _.IsExit ins = Python306.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python306.Opcode.NOP
        member _.HasFlag ins = Python306.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python306.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python306.Semantics.branchTarget ins ft n }

  let semantics307 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python307.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python307.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python307.Semantics.isBranch ins
        member _.IsCondBranch ins = Python307.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python307.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python307.Semantics.isCall ins
        member _.IsRET ins = Python307.Semantics.isRET ins
        member _.IsExit ins = Python307.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python307.Opcode.NOP
        member _.HasFlag ins = Python307.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python307.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python307.Semantics.branchTarget ins ft n }

  let semantics308 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python308.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python308.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python308.Semantics.isBranch ins
        member _.IsCondBranch ins = Python308.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python308.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python308.Semantics.isCall ins
        member _.IsRET ins = Python308.Semantics.isRET ins
        member _.IsExit ins = Python308.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python308.Opcode.NOP
        member _.HasFlag ins = Python308.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python308.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python308.Semantics.branchTarget ins ft n }

  let semantics309 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python309.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python309.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python309.Semantics.isBranch ins
        member _.IsCondBranch ins = Python309.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python309.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python309.Semantics.isCall ins
        member _.IsRET ins = Python309.Semantics.isRET ins
        member _.IsExit ins = Python309.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python309.Opcode.NOP
        member _.HasFlag ins = Python309.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python309.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python309.Semantics.branchTarget ins ft n }

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

  let semantics311 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python311.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python311.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python311.Semantics.isBranch ins
        member _.IsCondBranch ins = Python311.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python311.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python311.Semantics.isCall ins
        member _.IsRET ins = Python311.Semantics.isRET ins
        member _.IsExit ins = Python311.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python311.Opcode.NOP
        member _.HasFlag ins = Python311.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python311.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python311.Semantics.branchTarget ins ft n }

  let semantics313 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python313.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python313.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python313.Semantics.isBranch ins
        member _.IsCondBranch ins = Python313.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python313.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python313.Semantics.isCall ins
        member _.IsRET ins = Python313.Semantics.isRET ins
        member _.IsExit ins = Python313.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python313.Opcode.NOP
        member _.HasFlag ins = Python313.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python313.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python313.Semantics.branchTarget ins ft n }

  let semantics314 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python314.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python314.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python314.Semantics.isBranch ins
        member _.IsCondBranch ins = Python314.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python314.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python314.Semantics.isCall ins
        member _.IsRET ins = Python314.Semantics.isRET ins
        member _.IsExit ins = Python314.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python314.Opcode.NOP
        member _.HasFlag ins = Python314.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python314.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python314.Semantics.branchTarget ins ft n }

  let semantics315 =
    { new IInstructionSemantics with
        member _.Lift(ins, bld) = Python315.Lifter.translate binFile ins bld
        member _.Disasm(ins, bld) = Python315.Disasm.disasm ins bld; bld
        member _.IsBranch ins = Python315.Semantics.isBranch ins
        member _.IsCondBranch ins = Python315.Semantics.isCondBranch ins
        member _.IsCJmpOnTrue ins = Python315.Semantics.isCJmpOnTrue ins
        member _.IsCall ins = Python315.Semantics.isCall ins
        member _.IsRET ins = Python315.Semantics.isRET ins
        member _.IsExit ins = Python315.Semantics.isExit ins
        member _.IsNop ins = ins.Opcode = int Python315.Opcode.NOP
        member _.HasFlag ins = Python315.Semantics.hasFlag ins
        member _.SuperHasExplicitArgs ins =
          Python315.Semantics.superHasExplicitArgs ins
        member _.BranchTarget(ins, ft, n) =
          Python315.Semantics.branchTarget ins ft n }

  (* Adding a version means adding its directory and one entry here, and
     touching nothing another version's author also edits. *)
  let parse span addr =
    match binFile.Version with
    | PythonVersion.Python300 ->
      Python300.Parsing.parse semantics300 span reader binFile addr
    | PythonVersion.Python301 ->
      Python301.Parsing.parse semantics301 span reader binFile addr
    | PythonVersion.Python302 ->
      Python302.Parsing.parse semantics302 span reader binFile addr
    | PythonVersion.Python303 ->
      Python303.Parsing.parse semantics303 span reader binFile addr
    | PythonVersion.Python304 ->
      Python304.Parsing.parse semantics304 span reader binFile addr
    | PythonVersion.Python305 ->
      Python305.Parsing.parse semantics305 span reader binFile addr
    | PythonVersion.Python306 ->
      Python306.Parsing.parse semantics306 span reader binFile addr
    | PythonVersion.Python307 ->
      Python307.Parsing.parse semantics307 span reader binFile addr
    | PythonVersion.Python308 ->
      Python308.Parsing.parse semantics308 span reader binFile addr
    | PythonVersion.Python309 ->
      Python309.Parsing.parse semantics309 span reader binFile addr
    | PythonVersion.Python310 ->
      Python310.Parsing.parse semantics310 span reader binFile addr
    | PythonVersion.Python311 ->
      Python311.Parsing.parse semantics311 span reader binFile addr
    | PythonVersion.Python312 ->
      Python312.Parsing.parse semantics312 span reader binFile addr
    | PythonVersion.Python313 ->
      Python313.Parsing.parse semantics313 span reader binFile addr
    | PythonVersion.Python314 ->
      Python314.Parsing.parse semantics314 span reader binFile addr
    | PythonVersion.Python315 ->
      Python315.Parsing.parse semantics315 span reader binFile addr
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

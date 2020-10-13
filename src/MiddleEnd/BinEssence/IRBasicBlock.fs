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

namespace B2R2.MiddleEnd.BinEssenceNS

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph

/// A basic block that consists of IR (LowUIR) statements. It contains all the
/// InstructionInfo of the basic block.
type IRBasicBlock (instrs: InstructionInfo [], point: ProgramPoint) =
  inherit BasicBlock (point)

  let mutable hasIndirectBranch = false

  /// Does this block has indirect branch? This flag will be set after building
  /// an SCFG.
  member __.HasIndirectBranch
    with get () = hasIndirectBranch and set (v) = hasIndirectBranch <- v

  /// The first instruction of the basic block.
  member __.FirstInstruction =
    if Array.isEmpty instrs then raise DummyDataAccessException
    else instrs.[0].Instruction

  /// The last instruction of the basic block.
  member __.LastInstruction =
    if Array.isEmpty instrs then raise DummyDataAccessException
    else instrs.[Array.length instrs - 1].Instruction

  member __.LastInsInfo =
    if Array.isEmpty instrs then raise DummyDataAccessException
    else instrs.[Array.length instrs - 1]

  /// The address range of the basic block. Even if the block contains a partial
  /// IR statements of an instruction, we include the instruction to compute the
  /// range.
  override __.Range =
    let lastAddr = __.LastInstruction.Address + uint64 __.LastInstruction.Length
    AddrRange (__.PPoint.Address, lastAddr)

  override __.IsFakeBlock () = Array.isEmpty instrs

  override __.ToVisualBlock () =
    __.GetIRStatements ()
    |> Array.concat
    |> Array.map (fun stmt ->
      [| { AsmWordKind = AsmWordKind.String
           AsmWordValue = BinIR.LowUIR.Pp.stmtToString stmt } |])

  /// Get an array of IR statements of a basic block.
  member __.GetIRStatements () = instrs |> Array.map (fun i -> i.Stmts)

  /// Get an array of instructions that corresponds to each statement in the
  /// IRStatements.
  member __.GetInstructions () = instrs |> Array.map (fun i -> i.Instruction)

  /// Get the array of InstructionInfo of the basic block.
  member __.GetInsInfos () = instrs

  /// Get the last IR statement of the bblock.
  member __.GetLastStmt () =
    let stmts = instrs.[instrs.Length - 1].Stmts
    stmts.[stmts.Length - 1]

  override __.ToString () =
    if instrs.Length = 0 then "IRBBLK(Dummy)"
    else "IRBBLK(" + __.PPoint.Address.ToString("X") + ")"

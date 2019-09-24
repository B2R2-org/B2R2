(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Sang Kil Cha <sangkilc@kaist.ac.kr>

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

namespace B2R2.BinGraph

open B2R2
open B2R2.FrontEnd

/// A basic block that consists of IR (LowUIR) statements. It contains all the
/// InsIRPairs of the basic block.
type IRBasicBlock (pairs: InsIRPair [], point: ProgramPoint) =
  inherit BasicBlock()

  /// The first instruction of the basic block.
  member __.FirstInstruction =
    if Array.isEmpty pairs then raise DummyDataAccessException
    else fst pairs.[0]

  /// The last instruction of the basic block.
  member __.LastInstruction =
    if Array.isEmpty pairs then raise DummyDataAccessException
    else fst pairs.[Array.length pairs - 1]

  /// The position of the basic block.
  override __.PPoint = point

  /// The address range of the basic block. Even if the block contains a partial
  /// IR statements of an instruction, we include the instruction to compute the
  /// range.
  override __.Range =
    let lastAddr = __.LastInstruction.Address + uint64 __.LastInstruction.Length
    AddrRange (__.PPoint.Address, lastAddr)

  override __.IsFakeBlock () = Array.isEmpty pairs

  override __.ToVisualBlock () =
    __.GetIRStatements ()
    |> Array.concat
    |> Array.map (fun stmt ->
      [| { AsmWordKind = AsmWordKind.String
           AsmWordValue = BinIR.LowUIR.Pp.stmtToString stmt } |])

  /// Get an array of IR statements of a basic block.
  member __.GetIRStatements () = pairs |> Array.map snd

  /// Get an array of instructions that corresponds to each statement in the
  /// IRStatements.
  member __.GetInstructions () = pairs |> Array.map fst

  /// Get the array of InstrIRPairs of the basic block.
  member __.GetPairs () = pairs

  /// Get the last IR statement of the bblock.
  member __.GetLastStmt () =
    let stmts = snd pairs.[pairs.Length - 1]
    stmts.[stmts.Length - 1]

  override __.ToString () =
    if pairs.Length = 0 then "IRBBLK(Dummy)"
    else "IRBBLK(" + __.PPoint.Address.ToString("X") + ")"

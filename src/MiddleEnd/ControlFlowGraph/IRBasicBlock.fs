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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR
open B2R2.MiddleEnd.BinGraph

/// A basic block that consists of IR (LowUIR) statements. It contains all the
/// InstructionInfo of the basic block. We say an IRBasicBlock is a fake block
/// if it contains no instruction, i.e., when the instrs is [||].
[<AbstractClass>]
type IRBasicBlock (instrs: InstructionInfo [], ppoint: ProgramPoint) =
  inherit BasicBlock (ppoint)

  /// The first instruction of the basic block.
  member __.FirstInstruction with get() =
    if Array.isEmpty instrs then raise DummyDataAccessException
    else instrs.[0].Instruction

  /// The first InstructionInfo of the basic block.
  member __.FirstInsInfo with get() =
    if Array.isEmpty instrs then raise DummyDataAccessException
    else instrs.[0]

  /// The last instruction of the basic block.
  member __.LastInstruction with get() =
    if Array.isEmpty instrs then raise DummyDataAccessException
    else instrs.[Array.length instrs - 1].Instruction

  /// The last InstructionInfo of the basic block.
  member __.LastInsInfo with get() =
    if Array.isEmpty instrs then raise DummyDataAccessException
    else instrs.[Array.length instrs - 1]

  /// Get an array of IR statements of a basic block.
  member __.IRStatements with get() = instrs |> Array.map (fun i -> i.Stmts)

  /// Get an array of instructions that corresponds to each statement in the
  /// IRStatements.
  member __.Instructions
    with get() = instrs |> Array.map (fun i -> i.Instruction)

  /// Get the array of InstructionInfo of the basic block.
  member __.InsInfos with get() = instrs

  /// Get the last IR statement of the bblock.
  member __.LastStmt with get() =
    let stmts = instrs.[instrs.Length - 1].Stmts
    stmts.[stmts.Length - 1]

  /// The address range of the basic block. Even if the block contains a partial
  /// IR statements of an instruction, we include the instruction to compute the
  /// range.
  override __.Range =
    let lastAddr = __.LastInstruction.Address + uint64 __.LastInstruction.Length
    AddrRange (__.PPoint.Address, lastAddr)

  override __.ToVisualBlock () =
    __.IRStatements
    |> Array.concat
    |> Array.map (fun stmt ->
      [| { AsmWordKind = AsmWordKind.String
           AsmWordValue = LowUIR.Pp.stmtToString stmt } |])

  /// Fake block info, which exists only for a fake block.
  abstract FakeBlockInfo: FakeBlockInfo with get, set

  /// Unique identifier for IRBasicBlocks, which is a tuple of bbl's address and
  /// caller's address. Note the bbl's address many not exist for fake blocks,
  /// and the caller's address only exists for fake blocks. So we use dummy
  /// values in such cases, but the uniqueness is still guaranteed.
  abstract UniqueID: Addr * Addr

  /// Return the system call (at the end) instruction information if exists. If
  /// the block does not ends with a syscall this will return NoSyscallTail.
  abstract SyscallTail: SyscallTailInfo with get, set

/// Regular IRBasicBlock; a basic block with IR statements.
type RegularIRBasicBlock (instrs, ppoint) =
  inherit IRBasicBlock (instrs, ppoint)

  let mutable syscallTail = NoSyscallTail

  do assert (not (Array.isEmpty instrs))
     let stmts = instrs.[instrs.Length - 1].Stmts
     match Array.tryLast stmts with
     | Some ({ S = LowUIR.SideEffect SysCall }) ->
       syscallTail <- UnknownSyscallTail
     | _ -> ()

  override __.IsFakeBlock () = false

  override __.ToString () =
    "IRBBLK(" + String.u64ToHexNoPrefix __.PPoint.Address + ")"

  override __.FakeBlockInfo
    with get() = Utils.impossible () and set(_) = Utils.impossible ()

  override __.UniqueID with get() = (ppoint.Address, 0UL)

  override __.SyscallTail
    with get() = syscallTail and set(v) = syscallTail <- v

/// Fake IRBasicBlock. We create a fake block when there is a function call, and
/// thus, a fake block represents a function. Note, fake blocks do not uniquely
/// represent a function. That is, when there are multiple function calls to the
/// same function, we create a fake block for each of the call sites.
type FakeIRBasicBlock (ppoint, callSiteAddr, ?isTailCall, ?isIndCall) =
  inherit IRBasicBlock ([||], ppoint)

  let mutable info =
    { CallSite = callSiteAddr
      UnwindingBytes = 0UL
      FrameDistance = None
      GetPCThunkInfo = NoGetPCThunk
      IsPLT = false
      IsTailCall = defaultArg isTailCall false
      IsIndirectCall = defaultArg isIndCall false }

  override __.IsFakeBlock () = true

  override __.FakeBlockInfo with get() = info and set(i) = info <- i

  override __.ToString () = "IRBBLK(Dummy)"

  override __.UniqueID with get() = (ppoint.Address, callSiteAddr)

  override __.SyscallTail
    with get() = Utils.impossible () and set(_) = Utils.impossible ()

[<RequireQualifiedAccess>]
module IRBasicBlock =
  let initRegular instrs ppoint =
    RegularIRBasicBlock (instrs, ppoint) :> IRBasicBlock

  let initCallBlock callee callSiteAddr isTailCall =
    FakeIRBasicBlock (ProgramPoint (callee, 0), callSiteAddr, isTailCall)
    :> IRBasicBlock

  let initIndirectCallBlock callSiteAddr =
    FakeIRBasicBlock (ProgramPoint.GetFake (), callSiteAddr, false, true)
    :> IRBasicBlock

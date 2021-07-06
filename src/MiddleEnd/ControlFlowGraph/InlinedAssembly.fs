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
open B2R2.FrontEnd.BinInterface

type InlinedAssemblyTypes =
  | JumpAfterLock
  | NotInlinedAssembly

module InlinedAssemblyPattern =

  let private jumpAfterLockPattern =
    [| 0x64uy; 0x83uy; 0x3cuy; 0x25uy; 0x18uy; 0x00uy; 0x00uy; 0x00uy; 0x00uy;
      0x74uy; 0x01uy; 0xf0uy |]

  let private checkJumpAfterLock hdl targetBlkAddr =
    BinHandle.ReadBytes (hdl, targetBlkAddr - 12UL, 12) = jumpAfterLockPattern

  let checkInlinedAssemblyPattern hdl targetBlkAddr =
    if checkJumpAfterLock hdl targetBlkAddr then JumpAfterLock
    else NotInlinedAssembly

type InlinedAssembly (addr, len, wordSize, stmts) =
  inherit Instruction (addr, len, wordSize)

  override __.IsBranch () = false

  override __.IsModeChanging () = false

  override __.IsDirectBranch () = false

  override __.IsIndirectBranch () = false

  override __.IsCondBranch () = false

  override __.IsCJmpOnTrue () = false

  override __.IsCall () = false

  override __.IsRET () = false

  override __.IsInterrupt () = false

  override __.IsExit () = false

  override __.IsBBLEnd () = false

  override __.IsNop () = false

  override __.DirectBranchTarget _ = false

  override __.IndirectTrampolineAddr _ = false

  override __.Immediate _ = false

  override __.GetNextInstrAddrs () =
    let ftAddr = addr + uint64 len
    Seq.singleton (ftAddr, ArchOperationMode.NoMode)

  override __.InterruptNum _ = false

  override __.Translate _ = stmts

  override __.Disasm (showAddr, resolveSymbol, disasmHelper) =
    Utils.futureFeature ()

  override __.Disasm () = Utils.futureFeature ()

  override __.Decompose _ = Utils.futureFeature ()

  override __.IsInlinedAssembly () = true

  static member Init addr len wordSize stmts =
    InlinedAssembly (addr, len, wordSize, stmts) :> Instruction

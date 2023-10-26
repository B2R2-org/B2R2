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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter

/// Sometimes, inlined assembly creates branches that jump into the middle of an
/// instruction. For example, the following pattern is commonly found in Libc.
///
/// 41af15: 64 83 3c 25 18 00 00 00 00    cmpl  $0x0,%fs:0x18
/// 41af1e: 74 01                         je    41af21 <arena_get2.part.0+0x4a1>
/// 41af20: f0 48 ff 0d c0 57 0a 00       lock decq 0xa57c0(%rip)
///
/// We call the above code pattern as the "jump-after-lock" pattern.
type InlinedAssemblyTypes =
  /// The jump-after-lock pattern that spans multiple instruction addresses.
  | JumpAfterLock of addrs: Addr list
  /// No known pattern.
  | NotInlinedAssembly

module InlinedAssemblyPattern =

  let private computeJumpAfterLockAddrs (hdl: BinHandle) targetBlkAddr =
    [ ([| 0x64uy; 0x83uy; 0x3cuy; 0x25uy; 0x18uy;
          0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x74uy; 0x01uy; 0xf0uy |], 9UL, 2UL)
      ([| 0x65uy; 0x83uy; 0x3Duy; 0x0Cuy;
          0x00uy; 0x00uy; 0x00uy; 0x00uy; 0x74uy; 0x01uy; 0xf0uy |], 8UL, 2UL) ]
    |> List.tryPick (fun (pattern, cmpLen, jeLen) ->
      let len = uint64 pattern.Length
      if targetBlkAddr >= len then
        let ins1Addr = targetBlkAddr - len
        let ins2Addr = ins1Addr + cmpLen
        let ins3Addr = ins2Addr + jeLen
        let bs = hdl.ReadBytes (targetBlkAddr - len, pattern.Length)
        if bs = pattern then Some [ ins1Addr; ins2Addr; ins3Addr ]
        else None
      else None)

  let checkInlinedAssemblyPattern hdl targetBlkAddr =
    match computeJumpAfterLockAddrs hdl targetBlkAddr with
    | Some addrs -> JumpAfterLock addrs
    | _ -> NotInlinedAssembly

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
    [| (ftAddr, ArchOperationMode.NoMode) |]

  override __.InterruptNum _ = false

  override __.Translate _ = stmts

  override __.TranslateToList _ = System.Collections.Generic.List stmts

  override __.Disasm (_, _) = Utils.futureFeature ()

  override __.Disasm () = Utils.futureFeature ()

  override __.Decompose _ = Utils.futureFeature ()

  override __.IsInlinedAssembly () = true

  static member Init addr len wordSize stmts =
    InlinedAssembly (addr, len, wordSize, stmts) :> Instruction

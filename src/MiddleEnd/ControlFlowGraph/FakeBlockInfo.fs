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

/// Is this a get-pc-thunk function?
type GetPCThunkInfo =
  /// It is not a get-pc-thunk.
  | NoGetPCThunk
  /// It is a get-pc-thunk, and the register wlil be assigned after this
  /// function.
  | YesGetPCThunk of RegisterID

module GetPCThunkInfo =
  let isGetPCThunk = function
    | YesGetPCThunk _ -> true
    | _ -> false

/// IRBasicBlock can be either a fake block or a regular block. FakeBlockInfo
/// exists only for fake blocks.
type FakeBlockInfo = {
  /// Call site address, i.e., the call instruction's address.
  CallSite: Addr
  /// How many bytes of the stack does this function unwind when return?
  UnwindingBytes: int64
  /// What is the distance between the caller's stack frame (activation record)
  /// and the callee's stack frame? If the distance is always constant, we
  /// remember the value here.
  FrameDistance: int option
  /// If this fake block represents a "get_pc" thunk, then return the register
  /// ID holding the current PC value after this function returns.
  GetPCThunkInfo: GetPCThunkInfo
  /// Is this fake block points to a PLT entry?
  IsPLT: bool
  /// Is this fake block represents a tail call? So, this fake block is
  /// connected with a regular jump edge, not with a call edge.
  IsTailCall: bool
  /// Is the caller invoke this fake block as an indirect call?
  IsIndirectCall: bool
}

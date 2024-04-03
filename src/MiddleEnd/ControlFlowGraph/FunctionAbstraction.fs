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

/// An abstract information about a function to be used in an intra-procedural
/// CFG. This exists per function call, not per function definition. Therefore,
/// one function can have multiple `FunctionAbstraction` instances.
[<AllowNullLiteral>]
type FunctionAbstraction (callSiteAddr,
                          retPoint,
                          unwindings,
                          frameDist,
                          isPLT,
                          isFromTailCall,
                          isFromIndCall,
                          isSyscall) =
  let mutable unwindings = unwindings
  let mutable frameDist = frameDist
  let mutable isPLT = isPLT
  let mutable isSyscall = isSyscall

  new (callSiteAddr, retPoint, isFromTailCall, isFromIndCall) =
    FunctionAbstraction (callSiteAddr,
                         retPoint,
                         0L,
                         None,
                         false,
                         isFromTailCall,
                         isFromIndCall,
                         false)

  new (info: FunctionAbstraction) =
    FunctionAbstraction (info.CallSite,
                         info.ReturnPoint,
                         info.UnwindingBytes,
                         info.FrameDistance,
                         info.IsPLT,
                         info.IsFromTailCall,
                         info.IsFromIndirectCall,
                         info.IsSysCall)

  /// Call site address, i.e., the call instruction's address, of this function.
  member _.CallSite with get(): Addr = callSiteAddr

  /// Where does this function returns to? (i.e., the fall-through address of
  /// the caller).
  member _.ReturnPoint with get(): ProgramPoint = retPoint

  /// How many bytes of the stack does this function unwind when return?
  member _.UnwindingBytes with get() = unwindings and set(v) = unwindings <- v

  /// What is the distance between the caller's stack frame (activation record)
  /// and this function's stack frame? If the distance is always constant, we
  /// remember the value here.
  member _.FrameDistance with get() = frameDist and set(v) = frameDist <- v

  /// Is this a PLT entry?
  member _.IsPLT with get(): bool = isPLT and set(v) = isPLT <- v

  /// Does the caller invoke this function through a tail call?
  member _.IsFromTailCall with get(): bool = isFromTailCall

  /// Does the caller invoke this function through an indirect call?
  member _.IsFromIndirectCall with get(): bool = isFromIndCall

  /// Is this a system call? This is possible when a `call` instruction is used
  /// to make a system call. For example, in x86, `call dword ptr [GS:0x10]`
  /// will be a system call.
  member _.IsSysCall with get() = isSyscall and set(v) = isSyscall <- v

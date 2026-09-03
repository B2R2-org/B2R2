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

namespace B2R2.MiddleEnd.Executor

open B2R2
open B2R2.ABI
open B2R2.FrontEnd

/// Represents the calling-convention information passed to a call hook.
type CallContext =
  { /// Address of the call instruction.
    CallSite: Addr
    /// Concrete target address selected for hook dispatch.
    Target: Addr
    /// Fall-through address after the call instruction.
    ReturnAddress: Addr
    /// Word type for the current binary.
    WordType: RegType
    /// Endian used by the current binary.
    Endian: Endian
    /// Register IDs for the first calling-convention arguments. Empty when the
    /// ABI passes every integer argument on the stack.
    ArgumentRegisters: RegisterID[]
    /// Register ID used for the function return value.
    ReturnRegister: RegisterID }
with
  /// Builds the context for a hook that stands in for the call at the given
  /// site, whose callee returns to the given address.
  static member Create(hdl: BinHandle, callSite, target, returnAddress) =
    let cc = hdl.Conventions.Calling
    (* The argument slots the ABI itself declares: one that passes its
       argument on the stack, as x86 cdecl passes every one of them,
       contributes no register here, so a hook reads that argument from the
       stack. *)
    let argumentRegisters =
      cc.IntArgs
      |> Array.choose (function
        | ArgLocation.Reg rid -> Some rid
        | _ -> None)
    { CallSite = callSite
      Target = target
      ReturnAddress = returnAddress
      WordType = hdl.ISA.WordSize |> WordSize.toRegType
      Endian = hdl.ISA.Endian
      ArgumentRegisters = argumentRegisters
      ReturnRegister = cc.IntReturnRegister }

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

namespace B2R2.MiddleEnd.ControlFlowAnalysis

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd

/// Represents the builder for an external function, which is responsible for
/// storing auxiliary information about the function, such as caller
/// information.
type ExternalFnCFGBuilder<'FnCtx, 'GlCtx>
  public(hdl: BinHandle, reference, name, noretStatus) =

  let entryPoint = (reference: ExternalFunctionReference).ReferenceAddress

  let callers = HashSet<Addr>()

  /// What callers know about this function never changes, as nothing builds it.
  let calleeInfo =
    { Status = noretStatus
      Unwinding = 0
      Clobbered = Set.ofSeq (ClobberedRegisters.ofCallingConvention hdl)
      IsExternal = true }

  /// Returns the location in this binary that refers to the external function.
  /// An import trampoline is executable code, whereas a relocation slot is
  /// non-executable data containing the loader's resolved function address.
  member _.ExternalReference = reference

  interface ICFGBuildable<'FnCtx, 'GlCtx> with
    member _.BuilderState with get() = Finished

    member _.EntryPoint with get(): Addr = entryPoint

    member _.NextFunctionAddress with get() = None and set(_) = ()

    member _.Context with get() = Terminator.impossible ()

    member _.CalleeInfo with get() = calleeInfo

    member _.Callers with get() = callers

    member _.DelayedBuilderRequests with get() = Terminator.impossible ()

    member _.HasJumpTable with get() = false

    member _.Activation
      with get() = Deactivated
       and set(_) = Terminator.impossible ()

    member _.IsExternal with get() = true

    member _.Authorize() = ()

    member _.Stop() = ()

    member _.ForceFinish _ = ()

    member _.StartVerifying() = ()

    member _.Finalize() = ()

    member _.ReInitialize() = ()

    member _.Invalidate() = ()

    member _.Build _ = Terminator.impossible ()

    member _.Reset _ = ()

    member _.MakeNew _ = Terminator.impossible ()

    member _.ToFunction() =
      Function(entryPoint, name, noretStatus, callers, [||], true)

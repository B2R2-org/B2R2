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

/// The builder for an external function, which is responsible storing auxiliary
/// information about the function, such as caller information.
type ExternalFnCFGBuilder<'FnCtx,
                          'GlCtx when 'FnCtx :> IResettable
                                  and 'FnCtx: (new: unit -> 'FnCtx)
                                  and 'GlCtx: (new: unit -> 'GlCtx)>
  public (hdl: BinHandle,
          entryPoint,
          name,
          noretStatus) =

  let ctx =
    { FunctionAddress = entryPoint
      FunctionName = name
      FunctionMode = ArchOperationMode.NoMode
      BinHandle = hdl
      Vertices = Dictionary ()
      AbsVertices = Dictionary ()
      CFG = null
      BBLFactory = BBLFactory (hdl, null)
      NonReturningStatus = noretStatus
      CallTable = CallTable ()
      VisitedPPoints = HashSet ()
      ActionQueue = CFGActionQueue ()
      UserContext = new 'FnCtx ()
      IsExternal = true
      ManagerChannel = null
      ThreadID = -1 }

  interface ICFGBuildable<'FnCtx, 'GlCtx> with
    member __.BuilderState with get() = Finished

    member __.EntryPoint with get(): Addr = entryPoint

    member __.Mode with get() = Utils.impossible ()

    member __.Context with get() = ctx

    member __.IsExternal with get() = true

    member __.Authorize () = ()

    member __.Stop () = ()

    member __.Finalize () = ()

    member __.Invalidate () = ()

    member __.Build _ = Utils.impossible ()

    member __.Reset () = ()

    member __.MakeNew _ = Utils.impossible ()

    member __.ToFunction () =
      Function (entryPoint, name, ctx.NonReturningStatus, HashSet (), true)

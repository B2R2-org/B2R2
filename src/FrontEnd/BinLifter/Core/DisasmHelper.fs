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

namespace B2R2.FrontEnd.BinLifter

open System.Text
open B2R2

type DisasmHelper (?fn: Addr -> Result<string, ErrorCase>) =
  let helper =
    match fn with
    | Some fn -> fn
    | None -> fun _ -> Error ErrorCase.SymbolNotFound

  member __.FindFunctionSymbol (addr: Addr) = helper addr

[<AbstractClass>]
type DisasmBuilder<'Result> () =
  abstract member Accumulate: AsmWordKind -> string -> unit
  abstract member AccumulateAddr: Addr -> WordSize -> bool -> unit
  abstract member Finalize: unit -> 'Result

type DisasmStringBuilder () =
  inherit DisasmBuilder<string> ()

  let sb = StringBuilder ()

  override __.Accumulate _kind s =
    sb.Append (s) |> ignore

  override __.AccumulateAddr addr wordSize showAddress =
    if not showAddress then ()
    else
      sb.Append (Addr.toString wordSize addr) |> ignore
      sb.Append (": ") |> ignore

  override __.Finalize () = sb.ToString ()

type DisasmWordBuilder (n) =
  inherit DisasmBuilder<AsmWord []> ()

  let ab = AsmWordBuilder (n)

  override __.Accumulate kind s =
    ab.Append ({ AsmWordKind = kind; AsmWordValue = s }) |> ignore

  override __.AccumulateAddr addr wordSize showAddress =
    if not showAddress then ()
    else
      ab.Append ({ AsmWordKind = AsmWordKind.Address
                   AsmWordValue = Addr.toString wordSize addr }) |> ignore
      ab.Append ({ AsmWordKind = AsmWordKind.String
                   AsmWordValue = ": " }) |> ignore

  override __.Finalize () = ab.Finish ()

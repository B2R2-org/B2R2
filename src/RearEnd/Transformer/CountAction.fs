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

namespace B2R2.RearEnd.Transformer

open B2R2

/// The `count` action.
type CountAction () =
  let rec count (o: obj) =
    let typ = o.GetType ()
    if typ.IsArray then countArrayResult o
    elif typ = typeof<Binary> then countBinary o
    else Utils.futureFeature ()

  and countArrayResult (o: obj) =
    let arr = o :?> _[]
    if Array.isEmpty arr then 0 else 1

  and countBinary (o: obj) =
    let bin = o :?> Binary
    let hdl = Binary.Handle bin
    hdl.BinFile.Span.Length

  interface IAction with
    member __.ActionID with get() = "count"
    member __.Signature with get() = "ObjCollection -> int"
    member __.Description with get() = """
    Take in ObjCollection as input and returns how many objects are valid. This
    action is useful when counting the number of results obtained from grep
    action.
"""
    member __.Transform _args collection =
      { Values = [| collection.Values
                    |> Array.fold (fun acc v -> acc + count v) 0 |] }

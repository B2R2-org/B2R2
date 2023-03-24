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

open FSharp.Reflection
open B2R2

/// The `print` action.
type PrintAction () =
  let rec print (o: obj) =
    let typ = o.GetType ()
    if typ = typeof<ObjCollection> then printObjCollection o
    elif typ.IsArray then printArray o
    elif FSharpType.IsUnion typ
      && typ.BaseType = typeof<OutString> then printOutString o
    else Printer.PrintToConsoleLine (o.ToString ())

  and printObjCollection (o: obj) =
    let res = o :?> ObjCollection
    res.Values
    |> Array.iteri (fun idx v ->
      Printer.PrintToConsoleLine $"[*] result({idx})"
      print v)

  and printArray (o: obj) =
    let arr = o :?> _[]
    arr |> Array.iter print

  and printOutString (o: obj) =
    let os = o :?> OutString
    Printer.PrintToConsoleLine os

  interface IAction with
    member __.ActionID with get() = "print"
    member __.Signature with get() = "'a -> unit"
    member __.Description with get() = """
    Take in an input object and print out its value.
"""
    member __.Transform _args o =
      print (box o)
      { Values = [||] }
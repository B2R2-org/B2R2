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

open System

/// The `print` action.
type PrintAction () =
  let printArray (o: obj) =
    let arr = o :?> _[]
    arr |> Array.iter (fun o -> Console.WriteLine $"{o}")

  interface IAction with
    member __.ActionID with get() = "print"
    member __.InputType with get() = typeof<obj>
    member __.OutputType with get() = typeof<unit>
    member __.Description with get() = """
    Takes in an input object and prints its value.
"""
    member __.Transform _args o =
      let typ = o.GetType ()
      if typ.IsArray then printArray o
      else Console.WriteLine (o.ToString ())
      () (* This is to make compiler happy. *)
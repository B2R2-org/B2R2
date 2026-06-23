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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open System.Collections.Generic
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents a strategy to identify functions in Python binaries.
type PythonFunctionIdentification(binFile: PythonBinFile) =
  /// Traverses nested code objects in a bytecode and collects their addresses.
  let rec collectEntryPoints acc = function
    | [] -> acc |> List.toArray
    | Python.PyCode(codeObj) :: rest ->
      let acc = (fst codeObj.Code) :: acc
      let objects =
        match codeObj.Consts with
        | Python.PyTuple(objs) -> objs
        | obj -> failwithf "Unexpected object: %A" obj
      let nestedCodeObjs =
        objects
        |> Array.filter (fun obj -> obj.IsPyCode)
        |> Array.toList
      collectEntryPoints acc (nestedCodeObjs @ rest)
    | obj -> failwithf "Unexpected object: %A" obj

  interface IFunctionIdentifiable with
    member _.Identify() = collectEntryPoints [] [ binFile.CodeObj ]
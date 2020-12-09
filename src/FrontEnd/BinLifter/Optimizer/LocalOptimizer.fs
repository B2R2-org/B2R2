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

open B2R2.BinIR.LowUIR

module private Localizer =
  let rec breakByMark acc (stmts: Stmt []) idx =
    if idx < stmts.Length then
      match stmts.[idx] with
      | ISMark (_, _)
      | LMark (_) ->
        let left, right = Array.splitAt idx stmts
        breakByMark (left :: acc) right 1
      | _ ->
        breakByMark acc stmts (idx + 1)
    else List.rev (stmts :: acc) |> List.toArray

  let breakIntoBlocks (stmts: Stmt []) =
    if Array.length stmts = 0 then [| stmts |]
    else breakByMark [] stmts 1

/// Intra-block local IR optimizer.
type LocalOptimizer =
  /// Run optimization on a flattened IR statements (an array of IR statements).
  static member Optimize stmts =
    Localizer.breakIntoBlocks stmts
    |> Array.map (fun stmts ->
      ConstantFolding.optimize stmts
      |> DeadCodeElimination.optimize)
    |> Array.concat

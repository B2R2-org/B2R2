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

[<AutoOpen>]
module private Localizer =
  let rec breakByMark acc (stmts: Stmt []) idx =
    if idx < stmts.Length then
      match stmts.[idx].S with
      | ISMark (_)
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
  /// Remove unnecessary IEMark to ease the analysis.
  static member private TrimIEMark (stmts: Stmt []) =
    let last = stmts.[stmts.Length - 1].S
    let secondLast = stmts.[stmts.Length - 2].S
    match secondLast, last with
    | InterJmp _, IEMark _
    | InterCJmp _, IEMark _
    | SideEffect _, IEMark _ ->
      Array.sub stmts 0 (stmts.Length - 1)
    | _ -> stmts

  /// Run optimization on a flattened IR statements (an array of IR statements).
  static member Optimize stmts =
    LocalOptimizer.TrimIEMark stmts
    |> breakIntoBlocks
    |> Array.map (fun stmts ->
      ConstantFolding.optimize stmts
      |> DeadCodeElimination.optimize)
    |> Array.concat

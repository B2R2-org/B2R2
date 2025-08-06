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

namespace B2R2.RearEnd.ROP

open System.Text

type ROPPayload = ROPValue array

module ROPPayload =

  let empty: ROPPayload = Array.empty

  let initWithExpr expr = [| ROPValue.ofExpr expr |]

  let addDummy32 n p =
    Array.init n (fun _ -> ROPValue.dummy32) |> Array.append p

  let addExpr e p = Array.append p [| ROPValue.ofExpr e |]

  let addExprs exprs p =
    Array.map ROPValue.ofExpr exprs |> Array.append p

  let setExpr e i p = Array.set p i (ROPValue.ofExpr e); p

  let addNum32 num p = Array.append p [| ROPValue.ofUInt32 num |]

  let addNum32s nums p =
    Array.map ROPValue.ofUInt32 nums |> Array.append p

  let setNum32 num i p = Array.set p i (ROPValue.ofUInt32 num); p

  let addGadget g p = Array.append p [| ROPValue.ofGadget g |]

  let addGadgetToSome g = function
    | Some p -> addGadget g p |> Some
    | None -> None

  let merge p1 p2 = Array.append p1 p2

  let mergeAny p1 p2 =
    match p1, p2 with
    | Some p1, Some p2 -> merge p1 p2 |> Some
    | Some _, None -> p1
    | None, Some _ -> p2
    | None, None -> None

  let mergeSome p1 p2 =
    match p1, p2 with
    | Some p1, Some p2 -> merge p1 p2 |> Some
    | _, _ -> None

  let toString liftingUnit binBase p =
    let sb = StringBuilder()
    let sb = sb.Append("------------")
    let sb = sb.Append(System.Environment.NewLine)
    let sb =
      Array.fold (fun (sb: StringBuilder) v ->
        sb.Append(ROPValue.toString liftingUnit binBase v)) sb p
    let sb = sb.Append("------------")
    let sb = sb.Append(System.Environment.NewLine)
    sb.ToString()

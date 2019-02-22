(*
  B2R2 - the Next-Generation Reversing Platform

  Author: HyungSeok Han <hyungseok.han@kaist.ac.kr>

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

namespace B2R2.ROP

open System
open B2R2
open B2R2.FrontEnd

type ROPExpr =
  | Var of string
  | Num of BitVector
  | Sub of ROPExpr * ROPExpr
  | Add of ROPExpr * ROPExpr

module ROPExpr =
  let inline ofUInt32 num = BitVector.ofUInt32 (uint32 num) 32<rt> |> Num

  let inline ofUInt64 num = BitVector.ofUInt64 (uint64 num) 64<rt> |> Num

  let zero32 = BitVector.zero 32<rt> |> Num

  let addNum32 expr (num: uint32) =
    match expr with
    | Num n -> BitVector.ofUInt32 num 32<rt> |> BitVector.add n |> Num
    | _ -> Add (expr, ofUInt32 num)

  let subNum32 expr (num: uint32) =
    match expr with
    | Num n -> BitVector.ofUInt32 num 32<rt> |> BitVector.sub n |> Num
    | _ -> Add (expr, ofUInt32 num)

  let rec toString = function
    | Num vec ->
      sprintf "[ %08x ]" (BitVector.toUInt32 vec) + Environment.NewLine
    | expr -> // XXX FIXME
      sprintf "[ %A ]" expr + Environment.NewLine

type ROPValue =
  | Expr of ROPExpr
  | Gadget of Gadget

module ROPValue =
  let inline ofGadget g = ROPValue.Gadget g

  let inline ofExpr e = ROPValue.Expr e

  let inline ofUInt32 num = ROPExpr.ofUInt32 num |> ROPValue.Expr

  let inline ofUInt64 num = ROPExpr.ofUInt64 num |> ROPValue.Expr

  let dummy32 = ofUInt32 0xdeadbeefu

  let strFolder hdl acc ins =
    let acc = acc + "  " + BinHandler.DisasmInstr hdl true false ins
    acc + Environment.NewLine

  let toString hdl binBase = function
    | ROPValue.Expr expr -> ROPExpr.toString expr
    | ROPValue.Gadget gadget ->
      let s = sprintf "[ %08X ]" ((uint32 gadget.Offset) + binBase)
      let s = s + Environment.NewLine
      gadget.Instrs |> List.fold (strFolder hdl) s

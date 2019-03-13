(*
    B2R2 - the Next-Generation Reversing Platform

    Author: Minkyu Jung <hestati@kaist.ac.kr>

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

namespace B2R2.FrontEnd

open System.Runtime.InteropServices

open B2R2
open B2R2.BinIR.LowUIR

type internal ConstPropContext = {
    VarMap     : Map<RegisterID, Expr>
    TempVarMap : Map<int, Expr>
}

type internal ExprWalker =
    static member Replace (cpc, e, [<Out>] out: byref<Expr>) =
        match e with
        | Var (_, n, _, _) -> match cpc.VarMap.TryGetValue n with
                                                    | (true, e) -> out <- e; true
                                                    | _  -> false
        | TempVar (_, n) -> match cpc.TempVarMap.TryGetValue n with
                                                | (true, e) -> out <- e; true
                                                | _  -> false
        | UnOp (t, _e, _, _) ->
            let (trans, o) = ExprWalker.Replace (cpc, _e)
            if trans then out <- AST.unop t o; true else false
        | BinOp (t, rt, e1, e2, _, _) ->
            let (trans, e1') = ExprWalker.Replace (cpc, e1)
            let (trans1, e2') = ExprWalker.Replace (cpc, e2)
            if trans || trans1 then
                let e1 = if trans then e1' else e1
                let e2 = if trans1 then e2' else e2
                out <- AST.binop t e1 e2; true
            else false
        | RelOp (t, e1, e2, _, _) ->
            let (trans, e1') = ExprWalker.Replace (cpc, e1)
            let (trans1, e2') = ExprWalker.Replace (cpc, e2)
            if trans || trans1 then
                let e1 = if trans then e1' else e1
                let e2 = if trans1 then e2' else e2
                out <- AST.relop t e1 e2; true
            else false
        | Load (endian, rt, _e, _, _) ->
            let (trans, o) = ExprWalker.Replace (cpc, _e)
            if trans then out <- AST.load endian rt o; true else false
        | Ite (cond, e1, e2, _, _) ->
            let (trans, cond') = ExprWalker.Replace (cpc, cond)
            let (trans1, e1') = ExprWalker.Replace (cpc, e1)
            let (trans2, e2') = ExprWalker.Replace (cpc, e2)
            if trans || trans1 || trans2 then
                let c = if trans then cond' else cond
                let e1 = if trans1 then e1' else e1
                let e2 = if trans2 then e2' else e2
                out <- AST.ite c e1 e2; true
            else false
        | Cast (t, rt, _e, _, _) ->
            let (trans, o) = ExprWalker.Replace (cpc, _e)
            if trans then out <- AST.cast t rt o; true else false
        | _ -> false

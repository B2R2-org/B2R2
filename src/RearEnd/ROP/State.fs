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

open System
open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.RearEnd.ROP.Simplify

type Reg = string

type Value (expr) =
  let expr = simplify expr
  override __.GetHashCode () = expr.GetHashCode ()
  override this.Equals other = this.GetHashCode () = other.GetHashCode ()
  interface IComparable with
    override this.CompareTo other = this.GetHashCode () - other.GetHashCode ()

  member __.GetExpr () = expr

  override __.ToString () = Pp.expToString expr

module Value =
  let toLinear (value: Value) =
    match value.GetExpr () with
    | Var (32<rt>, _, reg, _) -> Some (reg, 0u)
    | BinOp (BinOpType.ADD, _, Var (32<rt>, _, reg, _), Num n, _, _)
    | BinOp (BinOpType.ADD, _, Num n, Var (32<rt>, _, reg, _), _, _) ->
      Some (reg, BitVector.toUInt32 n)
    | BinOp (BinOpType.SUB, _, Var (32<rt>, _, reg, _), Num n, _, _)
    | BinOp (BinOpType.SUB, _, Num n, Var (32<rt>, _, reg, _), _, _) ->
      Some (reg, BitVector.neg n |> BitVector.toUInt32)
    | _ -> None

type State = {
  Regs     : Map<Reg, Value>
  TempRegs : Map<int, Value>
  Mems     : Map<Value, Value>
  SysCall  : State list
  SideEff  : bool
}

module State =

  let inline updateRegs r v regs = Map.add r v regs

  let inline updateMems a v mems = Map.add a v mems

  let initState = {
    Regs     = Map.empty
    TempRegs = Map.empty
    Mems     = Map.empty
    SysCall  = []
    SideEff  = false
  }

  let private getReg state reg =
    let _, _, name, _ = reg
    match Map.tryFind name state.Regs with
    | Some v -> v
    | None -> Var reg |> Value

  let private getTempReg state name =
    match Map.tryFind name state.TempRegs with
    | Some v -> v
    | None -> failwithf "get T_%d fail" name

  let rec evalExpr state = function
    | Var (t, id, n, rs) -> getReg state (t, id, n, rs)
    | TempVar (t, name) -> getTempReg state name
    | UnOp (op, expr, _, _) -> AST.unop op (getEvalExpr state expr) |> Value
    | BinOp (op, ty, lExpr, rExpr, _, _) ->
      AST.binop op (getEvalExpr state lExpr) (getEvalExpr state rExpr) |> Value
    | RelOp (op, lExpr, rExpr, _, _) ->
      AST.relop op (getEvalExpr state lExpr) (getEvalExpr state rExpr) |> Value
    | Load (endian, ty, expr, _, _) -> evalLoad state endian ty expr
    | Ite (cExpr, tExpr, fExpr, _, _) ->
      AST.ite (getEvalExpr state cExpr) (getEvalExpr state tExpr)
              (getEvalExpr state fExpr) |> Value
    | Cast (kind, ty, expr, _, _) ->
      AST.cast kind ty <| getEvalExpr state expr |> Value
    | expr -> Value expr // Num, Name, PCVar

  and evalLoad state endian ty expr =
    let addr = evalExpr state expr
    match Map.tryFind addr state.Mems with
    | Some v ->
      let expr = v.GetExpr ()
      let vType = AST.typeOf expr
      if vType = ty then v
      elif vType > ty then AST.extract (v.GetExpr ()) ty 0 |> Value
      else AST.load endian ty (addr.GetExpr ()) |> Value
    | None -> AST.load endian ty (addr.GetExpr ()) |> Value

  and getEvalExpr state expr =
    let value = evalExpr state expr
    value.GetExpr ()

  let private evalPutTemp state reg value =
    let value = evalExpr state value
    { state with TempRegs = Map.add reg value state.TempRegs }

  let private evalPutVar state reg value =
    let value = evalExpr state value
    { state with Regs = Map.add reg value state.Regs }

  let private evalStore state endian addr value =
    let addr = evalExpr state addr
    let value = evalExpr state value
    { state with Mems = updateMems addr value state.Mems }

  let private evalCJmp state condE trueE falseE =
    let trueE = getEvalExpr state trueE
    let falseE = getEvalExpr state falseE
    match getEvalExpr state condE with
    | e when e = AST.b1 -> trueE
    | e when e = AST.b0 -> falseE
    | e -> AST.ite e trueE falseE
    // FIXME: Do not assume EIP
    |> evalPutVar state "EIP"

  let private evalSideEff (state: State) = function
    | SysCall | Interrupt 0x80 ->
      let nEAX =
        Undefined (32<rt>, List.length state.SysCall |> sprintf "EAX%d")
        |> Value
      { state with SysCall = state :: state.SysCall
                   SideEff = true
                   Regs = updateRegs "EAX" nEAX state.Regs }
    | _ -> { state with SideEff = true }

  let evalStmt state stmt  =
    match stmt with
    | ISMark _ | IEMark _ | LMark _ -> state
    | Put (Var (_, _, reg, _), value) -> evalPutVar state reg value
    | Put (TempVar (_, reg), value) -> evalPutTemp state reg value
    | Store (endian, addr, value) -> evalStore state endian addr value
    | CJmp (condE, trueE, falseE) -> evalCJmp state condE trueE falseE
    | InterJmp (PCVar (_, pc), value, _) -> evalPutVar state pc value
    | Stmt.SideEffect eff -> evalSideEff state eff
    | e -> failwithf "evalStmt fail %A" e
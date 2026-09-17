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

type Value(expr) =
  let expr = simplify expr
  override _.GetHashCode() = expr.GetHashCode()
  override _.Equals x =
    match x with
    | :? Value as x -> expr.Equals <| x.GetExpr()
    | _ -> false
  interface IComparable with
    override this.CompareTo other = this.GetHashCode() - other.GetHashCode()

  member _.GetExpr() = expr

  override _.ToString() = PrettyPrinter.ToString expr

module Value =
  let toLinear (value: Value) =
    match value.GetExpr() with
    | Var(Type = 32<rt>; Name = reg) ->
      Some(reg, 0u)
    | BinOp(Op = BinOpType.ADD
            Left = Var(Type = 32<rt>; Name = reg)
            Right = Num(Value = n))
    | BinOp(Op = BinOpType.ADD
            Left = Num(Value = n)
            Right = Var(Type = 32<rt>; Name = reg)) ->
      Some(reg, n.ToUInt32())
    | BinOp(Op = BinOpType.SUB
            Left = Var(Type = 32<rt>; Name = reg)
            Right = Num(Value = n))
    | BinOp(Op = BinOpType.SUB
            Left = Num(Value = n)
            Right = Var(Type = 32<rt>; Name = reg)) ->
      Some(reg, (BitVector.Neg n).ToUInt32())
    | _ ->
      None

type State =
  { Regs: Map<Reg, Value>
    TempRegs: Map<int, Value>
    Mems: Map<Value, Value>
    SysCall: State list
    SideEff: bool }

module State =
  let inline updateRegs r v regs = Map.add r v regs

  let inline updateMems a v mems = Map.add a v mems

  let initState =
    { Regs = Map.empty
      TempRegs = Map.empty
      Mems = Map.empty
      SysCall = []
      SideEff = false }

  let private getReg state name expr =
    match Map.tryFind name state.Regs with
    | Some v -> v
    | None -> Value expr

  let private getTempReg state name =
    match Map.tryFind name state.TempRegs with
    | Some v -> v
    | None -> failwithf "get T_%d fail" name

  let rec evalExpr state e =
    match e with
    | Var(Name = name) ->
      getReg state name e
    | TempVar(Index = name) ->
      getTempReg state name
    | UnOp(Op = op; Operand = expr) ->
      AST.unop op (getEvalExpr state expr) |> Value
    | BinOp(Op = op; Type = ty; Left = lExpr; Right = rExpr) ->
      AST.binop op (getEvalExpr state lExpr) (getEvalExpr state rExpr) |> Value
    | RelOp(Op = op; Left = lExpr; Right = rExpr) ->
      AST.relop op (getEvalExpr state lExpr) (getEvalExpr state rExpr) |> Value
    | Load(Endian = endian; Type = ty; Addr = expr) ->
      evalLoad state endian ty expr
    | Ite(Cond = cExpr; TrueExpr = tExpr; FalseExpr = fExpr) ->
      AST.ite (getEvalExpr state cExpr)
              (getEvalExpr state tExpr)
              (getEvalExpr state fExpr) |> Value
    | Cast(Kind = kind; Type = ty; Operand = expr) ->
      AST.cast kind ty <| getEvalExpr state expr |> Value
    | RoundCtrl(Mode = mode; Body = body) ->
      AST.roundCtrl (getEvalExpr state mode) (getEvalExpr state body) |> Value
    | _ ->
      Value e // Num, Name, PCVar

  and evalLoad state endian ty expr =
    let addr = evalExpr state expr
    match Map.tryFind addr state.Mems with
    | Some v ->
      let expr = v.GetExpr()
      let vType = Expr.typeOf expr
      if vType = ty then v
      elif vType > ty then AST.extract (v.GetExpr()) ty 0 |> Value
      else AST.load endian ty (addr.GetExpr()) |> Value
    | None ->
      AST.load endian ty (addr.GetExpr()) |> Value

  and getEvalExpr state expr =
    let value = evalExpr state expr
    value.GetExpr()

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
    |> evalPutVar state "EIP" (* FIXME: Do not assume EIP *)

  let private evalSideEff (state: State) = function
    | SysCall | Interrupt 0x80 ->
      let nEAX =
        AST.undef 32<rt> (List.length state.SysCall |> sprintf "EAX%d")
        |> Value
      { state with SysCall = state :: state.SysCall
                   SideEff = true
                   Regs = updateRegs "EAX" nEAX state.Regs }
    | _ ->
      { state with SideEff = true }

  let evalStmt state stmt =
    match stmt with
    | ISMark _ | IEMark _ | LMark _ ->
      state
    | Put(Dst = Var(Name = reg); Src = value) ->
      evalPutVar state reg value
    | Put(Dst = TempVar(Index = reg); Src = value) ->
      evalPutTemp state reg value
    | Store(Endian = endian; Addr = addr; Value = value) ->
      evalStore state endian addr value
    | CJmp(Cond = condE; TrueTarget = trueE; FalseTarget = falseE) ->
      evalCJmp state condE trueE falseE
    | InterJmp(Target = value) ->
      evalPutVar state "EIP" value
    | SideEffect(Effect = eff) ->
      evalSideEff state eff
    | e ->
      failwithf "evalStmt fail %A" e

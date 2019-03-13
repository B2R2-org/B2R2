(*
    B2R2 - the Next-Generation Reversing Platform

    Author: Sang Kil Cha <sangkilc@kaist.ac.kr>
                    Minkyu Jung <hestati@kaist.ac.kr>

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

(* XXX

      This module is obsolete and should not be used or be referred to.

      XXX *)

/// Eval is a concrete evaluation module for BinIR.
module B2R2.BinIR.LowUIR.Eval

open B2R2
open B2R2.BinIR

exception UnknownVarException
exception UndefExpException
exception InvalidExpException
exception InvalidMemException

type EvalValue =
    | Undef
    | Def of BitVector

type VarTbl = Map<RegisterID, EvalValue>
type TmpVarTbl = Map<int, EvalValue>
type MemTbl = Map<Addr, byte>

(* XXX this will be eventually deleted in the future. *)
/// The main evaluation state that will be updated by every statement
/// encountered during the course of execution.
type EvalState =
    {
        PC            : Addr
        BlockEnd      : bool
        Vars          : VarTbl
        TmpVars       : TmpVarTbl
        Mems          : MemTbl
        NextStmtIdx   : int
        LblMap        : Map<Symbol, int>
    }

type EvalCallBacks =
    {
        /// StoreCallBack is used purely for debugging purpose.
        StoreCallBack : Addr -> Addr -> BitVector -> unit

        /// SideEffectCallBack is called everytime we evaluate a SideEffect
        /// statement. We can leverage this callback to model system calls, etc.
        SideEffectCallBack : SideEffect -> EvalState -> EvalState
    }

let emptyCallBack =
    {
        StoreCallBack = (fun _ _ _ -> ())
        SideEffectCallBack = (fun _ st -> st)
    }

let tr = BitVector.one 1<rt>

let rec private loadMemLoop acc m endian addr len =
    if len > 0u then
        match Map.tryFind addr m with
        | None -> raise InvalidMemException
        | Some b -> loadMemLoop (b :: acc) m endian (addr + 1UL) (len - 1u)
    else
        let arr =
            Array.ofList (if endian = Endian.Little then List.rev acc else acc)
        BitVector.ofArr arr

let private apply fn = function
    | Undef -> raise UndefExpException
    | Def bv -> Def (fn bv)

let private unwrap = function
    | Undef -> raise UndefExpException
    | Def bv -> bv

let loadMem m endian addr t =
    let len = RegType.toByteWidth t |> uint32
    loadMemLoop [] m endian addr len

let rec private getBytes acc cnt endian (v: bigint) =
    if cnt > 0 then
        let b = (v >>> ((cnt - 1) * 8)) &&& 255I |> byte
        getBytes (b :: acc) (cnt - 1) endian v
    else Array.ofList (if endian = Endian.Little then acc else List.rev acc)

let storeMem m endian addr v =
    let len = BitVector.getType v |> RegType.toByteWidth |> int
    let bs = BitVector.getValue v |> getBytes [] len endian
    Array.foldi (fun m idx b -> Map.add (addr + uint64 idx) b m) m bs |> fst

let rec evalConcrete st e =
    match e with
    | Num n -> Def n
    | Var (_, n, _, _) ->
        Option.getWithExn (Map.tryFind n st.Vars) UnknownVarException
    | PCVar (t, _) -> BitVector.ofUInt64 st.PC t |> Def
    | TempVar (_, n) ->
        Option.getWithExn (Map.tryFind n st.TmpVars) UnknownVarException
    | UnOp (UnOpType.NEG, e, _, _) -> evalConcrete st e |> apply BitVector.neg
    | UnOp (UnOpType.NOT, e, _, _) -> evalConcrete st e |> apply BitVector.bnot
    | BinOp (t, _, e1, e2, _, _) -> evalBinOp st e1 e2 t |> Def
    | RelOp (t, e1, e2, _, _) -> evalRelOp st e1 e2 t |> Def
    | Load (endian, t, addr, _, _) -> evalLoad st endian t addr |> Def
    | Ite (cond, e1, e2, _, _) -> evalIte st cond e1 e2
    | Cast (CastKind.SignExt, t, e, _, _) ->
        evalConcrete st e |> apply (fun bv -> BitVector.sext bv t)
    | Cast (CastKind.ZeroExt, t, e, _, _) ->
        evalConcrete st e |> apply (fun bv -> BitVector.zext bv t)
    | Extract (e, t, p, _, _) ->
        evalConcrete st e |> apply (fun bv -> BitVector.extract bv t p)
    | Undefined (_) -> Undef
    | _ -> raise InvalidExpException
and evalLoad st endian t addr =
    let addr = evalConcrete st addr |> unwrap
    loadMem st.Mems endian (BitVector.toUInt64 addr) t
and evalIte st cond e1 e2 =
    let cond = evalConcrete st cond |> unwrap
    if cond = tr then evalConcrete st e1 else evalConcrete st e2
and evalBinOpConc st e1 e2 fn =
    let e1 = evalConcrete st e1 |> unwrap
    let e2 = evalConcrete st e2 |> unwrap
    fn e1 e2
and evalBinOp st e1 e2 = function
    | BinOpType.ADD -> evalBinOpConc st e1 e2 BitVector.add
    | BinOpType.SUB -> evalBinOpConc st e1 e2 BitVector.sub
    | BinOpType.MUL  -> evalBinOpConc st e1 e2 BitVector.mul
    | BinOpType.DIV -> evalBinOpConc st e1 e2 BitVector.div
    | BinOpType.SDIV -> evalBinOpConc st e1 e2 BitVector.sdiv
    | BinOpType.MOD -> evalBinOpConc st e1 e2 BitVector.modulo
    | BinOpType.SMOD -> evalBinOpConc st e1 e2 BitVector.smodulo
    | BinOpType.SHL -> evalBinOpConc st e1 e2 BitVector.shl
    | BinOpType.SAR -> evalBinOpConc st e1 e2 BitVector.sar
    | BinOpType.SHR -> evalBinOpConc st e1 e2 BitVector.shr
    | BinOpType.AND -> evalBinOpConc st e1 e2 BitVector.band
    | BinOpType.OR -> evalBinOpConc st e1 e2 BitVector.bor
    | BinOpType.XOR -> evalBinOpConc st e1 e2 BitVector.bxor
    | BinOpType.CONCAT -> evalBinOpConc st e1 e2 BitVector.concat
    | _ -> raise IllegalASTTypeException
and evalRelOp st e1 e2 = function
    | RelOpType.EQ -> evalBinOpConc st e1 e2 BitVector.eq
    | RelOpType.NEQ -> evalBinOpConc st e1 e2 BitVector.neq
    | RelOpType.GT -> evalBinOpConc st e1 e2 BitVector.gt
    | RelOpType.GE -> evalBinOpConc st e1 e2 BitVector.ge
    | RelOpType.SGT -> evalBinOpConc st e1 e2 BitVector.sgt
    | RelOpType.SGE -> evalBinOpConc st e1 e2 BitVector.sge
    | RelOpType.LT -> evalBinOpConc st e1 e2 BitVector.lt
    | RelOpType.LE -> evalBinOpConc st e1 e2 BitVector.le
    | RelOpType.SLT -> evalBinOpConc st e1 e2 BitVector.slt
    | RelOpType.SLE -> evalBinOpConc st e1 e2 BitVector.sle
    | _ -> raise IllegalASTTypeException

let evalPut st lhs rhs =
    try 
        let v = evalConcrete st rhs
        match lhs with
        | Var (_, n, _, _) -> { st with Vars = Map.add n v st.Vars }
        | PCVar (_) -> { st with PC = unwrap v |> BitVector.toUInt64; }
        | TempVar (_, n) -> { st with TmpVars = Map.add n v st.TmpVars }
        | _ -> raise InvalidExpException
    with UndefExpException -> st (* Do not store undefined value *)

let evalStore st cb endian addr v =
    let addr = evalConcrete st addr |> unwrap |> BitVector.toUInt64
    let v = evalConcrete st v |> unwrap
    cb.StoreCallBack st.PC addr v
    { st with Mems = storeMem st.Mems endian addr v }

let evalJmp st target =
    match target with
    | Name n -> { st with NextStmtIdx = Map.find n st.LblMap }
    | _ -> raise InvalidExpException

let evalCJmp st cond t1 t2 =
    let cond = evalConcrete st cond |> unwrap
    if cond = tr then evalJmp st t1 else evalJmp st t2

let evalInterCJmp st cond pc t1 t2 =
    let cond = evalConcrete st cond |> unwrap
    evalPut st pc (if cond = tr then t1 else t2)

let private nextStmt st = { st with NextStmtIdx = st.NextStmtIdx + 1 }

let private endBlock st = { st with BlockEnd = true }

let evalStmt st cb = function
    | ISMark (_) -> st |> nextStmt
    | IEMark (addr) -> { st with PC = addr } |> nextStmt
    | LMark _ -> st |> nextStmt
    | Put (lhs, rhs) -> evalPut st lhs rhs |> nextStmt
    | Store (endian, addr, v) -> evalStore st cb endian addr v |> nextStmt
    | Jmp target -> evalJmp st target
    | CJmp (cond, t1, t2) -> evalCJmp st cond t1 t2
    | InterJmp (pc, target) -> evalPut st pc target |> endBlock
    | InterCJmp (cond, pc, t1, t2) -> evalInterCJmp st cond pc t1 t2 |> endBlock
    | SideEffect eff -> cb.SideEffectCallBack eff st |> nextStmt |> endBlock

/// For a given array of statements (of an instruction), genLblMap generates a
/// table that maps symbols to their corresponding label indices.
let genLblMap stmts =
    let rec loop acc idx =
        if idx < Array.length stmts then
            match stmts.[idx] with
            | LMark s -> loop (Map.add s idx acc) (idx + 1)
            | _ -> loop acc (idx + 1)
        else acc
    loop Map.empty 0

// vim: set tw=80 sts=2 sw=2:

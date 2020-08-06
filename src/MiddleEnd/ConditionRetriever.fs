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

namespace B2R2.MiddleEnd

open B2R2
open B2R2.FrontEnd
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.BinGraph
open B2R2.BinEssence
open B2R2.Lens

/// How do we compare vars? For example, in x86, there are two comparison
/// instructions: CMP vs. TEST.
type ComparisonKind =
  | CompareAfterSubtract
  | CompareAfterAnd

/// Intermediate information about a comparison instruction.
type IntermediateComparisonInfo = ComparisonKind * Expr * BitVector

/// Final information about a comparison instruction.
type ComparisonInfo = RelOpType * Expr * BitVector

/// Retrieve a high-level condition from a given condition expression pattern.
[<AbstractClass>]
type ConditionRetriever () =
  /// Find the corresponding comparison instruction from the given variable, and
  /// return its operands.
  abstract member FindComparison:
    BinEssence
    -> Vertex<SSABBlock>
    -> Variable
    -> IntermediateComparisonInfo option

  /// Pattern 1: CF (or ZF).
  abstract member RetrievePattern1:
    Variable -> IntermediateComparisonInfo -> ComparisonInfo option

  /// Pattern 2: (CF | ZF).
  abstract member RetrievePattern2:
    IntermediateComparisonInfo -> ComparisonInfo option

  /// Pattern 3: (ZF | (OF <> SF)).
  abstract member RetrievePattern3:
    IntermediateComparisonInfo -> ComparisonInfo option

  /// Pattern 4: (OF <> SF).
  abstract member RetrievePattern4:
    IntermediateComparisonInfo -> ComparisonInfo option

  /// Pattern 5: ((not ZF) & (OF = SF)). (negation of pattern 3)
  abstract member RetrievePattern5:
    IntermediateComparisonInfo -> ComparisonInfo option

  /// Pattern 6: (OF = SF). (negation of pattern 4)
  abstract member RetrievePattern6:
    IntermediateComparisonInfo -> ComparisonInfo option

  /// Find an address where myVar is defined.
  member __.FindAddr myVar addr stmts =
    match stmts with
    | Def (v, _) :: _ when myVar = v -> addr
    | Def (v, Num bv) :: stmts ->
      if Variable.IsPC v then
        __.FindAddr myVar (BitVector.toUInt64 bv) stmts
      else
        __.FindAddr myVar addr stmts
    | _ :: stmts -> __.FindAddr myVar addr stmts
    | [] -> addr

  /// Retrieve a condition based on the patterns defined in WYSINWYX: What You
  /// See Is Not What You eXecute p. 24.
  member __.Retrieve app vertex condExpr =
    match condExpr with
    | RelOp (RelOpType.EQ, 1<rt>, e, Num bv) ->
      let n = BitVector.toUInt64 bv
      if n = 0UL then
        __.Retrieve app vertex e
        |> Option.bind ConditionRetriever.Negate
      elif n = 1UL then __.Retrieve app vertex e
      else Utils.impossible ()
    | Var v ->
      __.FindComparison app vertex v |> Option.bind (__.RetrievePattern1 v)
    | BinOp (BinOpType.OR, 1<rt>, Var v, Var _) ->
      __.FindComparison app vertex v |> Option.bind __.RetrievePattern2
    | BinOp (BinOpType.OR, 1<rt>, Var v,
             RelOp (RelOpType.NEQ, _, Var _, Var _)) ->
      __.FindComparison app vertex v |> Option.bind __.RetrievePattern3
    | RelOp (RelOpType.NEQ, 1<rt>, Var v, Var _) ->
      __.FindComparison app vertex v |> Option.bind __.RetrievePattern4
    | BinOp (BinOpType.AND, 1<rt>, RelOp (RelOpType.EQ, _, Var v, Num bv),
                                   RelOp (RelOpType.EQ, _, Var _, Var _)) ->
      if BitVector.toUInt64 bv = 0UL then
        __.FindComparison app vertex v |> Option.bind __.RetrievePattern5
      else Utils.impossible ()
    | RelOp (RelOpType.EQ, 1<rt>, Var v, Var _) ->
      __.FindComparison app vertex v |> Option.bind __.RetrievePattern6
    | _ -> None

  static member Negate = function
    | (RelOpType.EQ, v, bv)  -> Some (RelOpType.NEQ, v, bv)
    | (RelOpType.NEQ, v, bv) -> Some (RelOpType.EQ, v, bv)
    | (RelOpType.GT, v, bv)  -> Some (RelOpType.LE, v, bv)
    | (RelOpType.GE, v, bv)  -> Some (RelOpType.LT, v, bv)
    | (RelOpType.SGT, v, bv) -> Some (RelOpType.SLE, v, bv)
    | (RelOpType.SGE, v, bv) -> Some (RelOpType.SLT, v, bv)
    | (RelOpType.LT, v, bv)  -> Some (RelOpType.GE, v, bv)
    | (RelOpType.LE, v, bv)  -> Some (RelOpType.GT, v, bv)
    | (RelOpType.SLT, v, bv) -> Some (RelOpType.SGE, v, bv)
    | (RelOpType.SLE, v, bv) -> Some (RelOpType.SGT, v, bv)
    | _ -> None

  static member Init (isa: ISA) =
    match isa.Arch with
    | Arch.IntelX86
    | Arch.IntelX64 -> IntelConditionRetriever () :> ConditionRetriever
    | _ -> DefaultRetriever () :> ConditionRetriever

and DefaultRetriever () =
  inherit ConditionRetriever ()
  override __.FindComparison _ _ _ = None
  override __.RetrievePattern1 _ _ = None
  override __.RetrievePattern2 _ = None
  override __.RetrievePattern3 _ = None
  override __.RetrievePattern4 _ = None
  override __.RetrievePattern5 _ = None
  override __.RetrievePattern6 _ = None

and IntelConditionRetriever () =
  inherit ConditionRetriever ()

  /// XXX: Two operands used to compare are first two expressions appeared at
  /// specific address
  let rec findTwoOperands addr isTarget first = function
    | Def (v, Num bv) :: stmts ->
      (* The second operand should be bitvector *)
      if isTarget && Option.isSome first then Option.get first, bv
      elif Variable.IsPC v then
        let addr_ = BitVector.toUInt64 bv
        findTwoOperands addr (addr = addr_) first stmts
      else findTwoOperands addr isTarget first stmts
    | Def (_, e) :: stmts ->
      (* We are at a right address, but none of operands are found until now *)
      if isTarget && Option.isNone first then
        findTwoOperands addr isTarget (Some e) stmts
      else findTwoOperands addr isTarget first stmts
    | _ :: stmts -> findTwoOperands addr isTarget first stmts
    | [] -> Utils.impossible ()

  override __.FindComparison ess v condVar =
    let ppoint = v.VData.PPoint
    let stmts = Array.toList v.VData.Stmts
    let addr = __.FindAddr condVar ppoint.Address stmts
    let ins = ess.InstrMap.[addr].Instruction :?> Intel.IntelInstruction
    match ins.Info.Opcode, ins.Info.Operands with
    | Intel.Opcode.CMP, Intel.TwoOperands (Intel.OprMem _, Intel.OprImm _)
    | Intel.Opcode.CMP, Intel.TwoOperands (Intel.OprReg _, Intel.OprImm _)
    | Intel.Opcode.SUB, Intel.TwoOperands (Intel.OprMem _, Intel.OprImm _)
    | Intel.Opcode.SUB, Intel.TwoOperands (Intel.OprReg _, Intel.OprImm _) ->
      let oprnd1, oprnd2 =
        findTwoOperands addr (ppoint.Address = addr) None stmts
      Some (CompareAfterSubtract, oprnd1, oprnd2)
    | _ -> None

  override __.RetrievePattern1 v info =
    match v.Kind, info with
    | RegVar (_, rid, _), (CompareAfterSubtract, e, bv) ->
      if rid = Intel.Register.toRegID Intel.Register.CF then
        Some (RelOpType.SLT, e, bv)
      elif rid = Intel.Register.toRegID Intel.Register.ZF then
        Some (RelOpType.EQ, e, bv)
      else None
    | _, _ -> None

  override __.RetrievePattern2 info =
    match info with
    | CompareAfterSubtract, e, bv -> Some (RelOpType.LE, e, bv)
    | _ -> None

  override __.RetrievePattern3 info =
    match info with
    | CompareAfterSubtract, e, bv -> Some (RelOpType.SLE, e, bv)
    | _ -> None

  override __.RetrievePattern4 info =
    match info with
    | CompareAfterSubtract, e, bv -> Some (RelOpType.SLT, e, bv)
    | _ -> None

  override __.RetrievePattern5 info =
    __.RetrievePattern3 info |> Option.bind ConditionRetriever.Negate

  override __.RetrievePattern6 info =
    __.RetrievePattern4 info |> Option.bind ConditionRetriever.Negate

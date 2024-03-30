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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph

[<AutoOpen>]
module private SSABasicBlockHelper =
  let private buildRegVar (hdl: BinHandle) reg =
    let wordSize = hdl.File.ISA.WordSize |> WordSize.toRegType
    RegVar (wordSize, reg, hdl.RegisterFactory.RegIDToString reg)

  let private addReturnValDef (hdl: BinHandle) defs =
    match hdl.File.ISA.Arch with
    | Architecture.EVM -> defs
    | _ ->
      let var = CallingConvention.returnRegister hdl |> buildRegVar hdl
      let rt = hdl.File.ISA.WordSize |> WordSize.toRegType
      let e = Undefined (rt, "ret")
      SSAOutVariableInfo.add hdl var e defs

  let private addStackPointerDef (hdl: BinHandle) funcAbs defs =
    match hdl.RegisterFactory.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterFactory.RegIDToRegType sp
      let var = buildRegVar hdl sp
      let retAddrSize = RegType.toByteWidth rt |> int64
      let adj = (funcAbs: SSAFunctionAbstraction).UnwindingBytes
      let shiftAmount = BitVector.OfInt64 (retAddrSize + adj) rt
      let v1 = Var { Kind = var; Identifier = -1 }
      let v2 = Num shiftAmount
      let e = BinOp (BinOpType.ADD, rt, v1, v2)
      SSAOutVariableInfo.add hdl var e defs
    | None -> defs

  let private addMemDef hdl defs =
    let e = Var { Kind = MemVar; Identifier = - 1 }
    SSAOutVariableInfo.add hdl MemVar e defs

  let computeDefinedVars hdl (funcAbs: SSAFunctionAbstraction) =
    if funcAbs.IsPLT then Map.empty |> addReturnValDef hdl
    else funcAbs.OutVariableInfo
    |> addMemDef hdl (* over-approximation *)
    |> addStackPointerDef hdl funcAbs

  let computeNextPPoint (ppoint: ProgramPoint) = function
    | Def (v, Num bv) ->
      match v.Kind with
      | PCVar _ -> ProgramPoint (BitVector.ToUInt64 bv, 0)
      | _ -> ProgramPoint.Next ppoint
    | _ -> ProgramPoint.Next ppoint

  let private addInOutMemVars inVars outVars =
    let inVar = { Kind = MemVar; Identifier = -1 }
    let outVar = { Kind = MemVar; Identifier = -1 }
    inVar :: inVars, outVar :: outVars

  let private postprocessStmtForEVM = function
    | ExternalCall ((BinOp (BinOpType.APP, _, FuncName "calldatacopy", _)) as e,
                    _, _) ->
      let inVars, outVars = addInOutMemVars [] []
      ExternalCall (e, inVars, outVars)
    | stmt -> stmt

  let private postprocessOthers stmt = stmt

  let postprocessStmt arch s =
    match arch with
    | Architecture.EVM -> postprocessStmtForEVM s
    | _ -> postprocessOthers s

  let toSSA (hdl: BinHandle) (ppoint: ProgramPoint) funcAbs liftedInstrs =
    match funcAbs with
    | Some (funcAbs: SSAFunctionAbstraction) ->
      if funcAbs.IsFromTailCall then [||]
      else
        let returnAddress = funcAbs.ReturnPoint.Address
        let stmts = (* For abstraction, we check which var can be defined. *)
          computeDefinedVars hdl funcAbs
          |> Seq.map (fun (KeyValue (kind, e)) ->
            let dst = { Kind = kind; Identifier = -1 }
            let src = e
            Def (dst, ReturnVal (ppoint.Address, returnAddress, src)))
          |> Seq.toArray
        let wordSize = hdl.File.ISA.WordSize |> WordSize.toRegType
        let fallThrough = BitVector.OfUInt64 returnAddress wordSize
        let jmpToFallThrough = Jmp (InterJmp (Num fallThrough))
        Array.append stmts [| jmpToFallThrough |]
        |> Array.map (fun s -> ProgramPoint.GetFake (), s)
    | None ->
      liftedInstrs
      |> Array.collect (fun liftedIns ->
        let wordSize = liftedIns.Original.WordSize |> WordSize.toRegType
        let stmts = liftedIns.Stmts
        let address = liftedIns.Original.Address
        let arch = hdl.File.ISA.Arch
        AST.translateStmts wordSize address (postprocessStmt arch) stmts)
      |> Array.map (fun s -> ProgramPoint.GetFake (), s)

/// Basic block type for an SSA-based CFG (SSACFG). It holds an array of
/// LiftedSSAStmts (ProgramPoint * Stmt).
type SSABasicBlock private (hdl: BinHandle, ppoint, funcAbs, liftedInstrs) =
  inherit AbstractableBasicBlock<SSAFunctionAbstraction> (ppoint, funcAbs)

  let mutable idom: IVertex<SSABasicBlock> option = None
  let mutable frontier: IVertex<SSABasicBlock> list = []
  let mutable stmts = toSSA hdl ppoint funcAbs liftedInstrs

  /// Return the LiftedInstruction array.
  member __.LiftedInstructions with get(): LiftedInstruction[] = liftedInstrs

  /// Return the SSA statements.
  member __.LiftedSSAStmts with get() = stmts

  /// Get the last SSA statement of the bblock.
  member __.LastStmt with get() = snd stmts[stmts.Length - 1]

  /// Immediate dominator of this block.
  member __.ImmDominator with get() = idom and set(d) = idom <- d

  /// Dominance frontier of this block.
  member __.DomFrontier with get() = frontier and set(f) = frontier <- f

  /// Prepend a Phi node to this SSA basic block.
  member __.PrependPhi varKind count =
    let var = { Kind = varKind; Identifier = -1 }
    let ppoint = ProgramPoint.GetFake ()
    stmts <- Array.append [| ppoint, Phi (var, Array.zeroCreate count) |] stmts

  /// Update program points. This must be called after updating SSA stmts.
  member __.UpdatePPoints () =
    stmts
    |> Array.foldi (fun ppoint idx (_, stmt) ->
      let ppoint' = computeNextPPoint ppoint stmt
      __.LiftedSSAStmts[idx] <- (ppoint', stmt)
      ppoint') ppoint
    |> ignore

  override __.Range with get() =
    match funcAbs with
    | Some _ -> raise AbstractBlockAccessException
    | None ->
      let lastIns = liftedInstrs[liftedInstrs.Length - 1].Original
      let lastAddr = lastIns.Address + uint64 lastIns.Length
      AddrRange (ppoint.Address, lastAddr - 1UL)

  override __.Cut (cutPoint: Addr) =
    match funcAbs with
    | Some _ -> raise AbstractBlockAccessException
    | None ->
      assert (__.Range.IsIncluding cutPoint)
      let before, after =
        liftedInstrs
        |> Array.partition (fun ins -> ins.Original.Address < cutPoint)
      SSABasicBlock.CreateRegular (hdl, ppoint, before),
      SSABasicBlock.CreateRegular (hdl, ppoint, after)

  override __.ToVisualBlock () =
    match funcAbs with
    | Some _ -> [||]
    | None ->
      stmts
      |> Array.map (fun (_, stmt) ->
        [| { AsmWordKind = AsmWordKind.String
             AsmWordValue = Pp.stmtToString stmt } |])

  static member CreateRegular (hdl, ppoint, liftedInstrs) =
    SSABasicBlock (hdl, ppoint, None, liftedInstrs)

  /// Create an abstracted basic block located at `ppoint`.
  static member CreateAbstract (hdl, ppoint, funcAbs: FunctionAbstraction) =
    let info = SSAFunctionAbstraction (funcAbs)
    SSABasicBlock (hdl, ppoint, Some info, [||])

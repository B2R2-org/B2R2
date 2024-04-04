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

namespace B2R2.MiddleEnd.SSA

open B2R2
open B2R2.BinIR
open B2R2.BinIR.SSA
open B2R2.FrontEnd
open B2R2.MiddleEnd.ControlFlowGraph

/// The main lifter for SSA.
type SSALifter<'Abs when 'Abs :> SSAFunctionAbstraction
                     and 'Abs : null> (hdl: BinHandle) =
  let buildRegVar reg =
    let wordSize = hdl.File.ISA.WordSize |> WordSize.toRegType
    RegVar (wordSize, reg, hdl.RegisterFactory.RegIDToString reg)

  let addReturnValDef defs =
    match hdl.File.ISA.Arch with
    | Architecture.EVM -> defs
    | _ ->
      let var = CallingConvention.returnRegister hdl |> buildRegVar
      let rt = hdl.File.ISA.WordSize |> WordSize.toRegType
      let e = Undefined (rt, "ret")
      SSAOutVariableInfo.add hdl var e defs

  let addStackPointerDef (funcAbs: 'Abs) defs =
    match hdl.RegisterFactory.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterFactory.RegIDToRegType sp
      let var = buildRegVar sp
      let retAddrSize = RegType.toByteWidth rt |> int64
      let adj = funcAbs.UnwindingBytes
      let shiftAmount = BitVector.OfInt64 (retAddrSize + adj) rt
      let v1 = Var { Kind = var; Identifier = -1 }
      let v2 = Num shiftAmount
      let e = BinOp (BinOpType.ADD, rt, v1, v2)
      SSAOutVariableInfo.add hdl var e defs
    | None -> defs

  let addMemDef defs =
    let e = Var { Kind = MemVar; Identifier = - 1 }
    SSAOutVariableInfo.add hdl MemVar e defs

  let computeDefinedVars (funcAbs: 'Abs) =
    if funcAbs.IsPLT then Map.empty |> addReturnValDef
    else funcAbs.OutVariableInfo
    |> addMemDef (* over-approximation *)
    |> addStackPointerDef funcAbs

  let addInOutMemVars inVars outVars =
    let inVar = { Kind = MemVar; Identifier = -1 }
    let outVar = { Kind = MemVar; Identifier = -1 }
    inVar :: inVars, outVar :: outVars

  let postprocessStmtForEVM = function
    | ExternalCall ((BinOp (BinOpType.APP, _, FuncName "calldatacopy", _)) as e,
                    _, _) ->
      let inVars, outVars = addInOutMemVars [] []
      ExternalCall (e, inVars, outVars)
    | stmt -> stmt

  let postprocessOthers stmt = stmt

  let postprocessStmt arch s =
    match arch with
    | Architecture.EVM -> postprocessStmtForEVM s
    | _ -> postprocessOthers s

  interface ISSALiftable<'Abs> with
    member __.Lift (liftedInstrs) =
      liftedInstrs
      |> Array.collect (fun liftedIns ->
        let wordSize = liftedIns.Original.WordSize |> WordSize.toRegType
        let stmts = liftedIns.Stmts
        let address = liftedIns.Original.Address
        let arch = hdl.File.ISA.Arch
        AST.translateStmts wordSize address (postprocessStmt arch) stmts)
      |> Array.map (fun s -> ProgramPoint.GetFake (), s)

    member __.Summarize (funcAbs, ppoint) =
      if funcAbs.IsFromTailCall then [||]
      else
        let returnAddress = funcAbs.ReturnPoint.Address
        let stmts = (* For abstraction, we check which var can be defined. *)
          computeDefinedVars funcAbs
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

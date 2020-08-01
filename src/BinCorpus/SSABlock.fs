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

namespace B2R2.BinCorpus

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.BinGraph

module SSABlockHelper =
  let private updateDefinedVar set = function
    | LowUIR.Put (LowUIR.Var (_) as dst, _) ->
      Set.add (SSA.AST.translateDest dst) set
    | LowUIR.Store (_) ->
      Set.add ({ SSA.Kind = SSA.MemVar; SSA.Identifier = -1 }) set
    | _ -> set

  let private defVarFolder acc (v: Vertex<IRBasicBlock>) =
    v.VData.GetIRStatements ()
    |> Array.fold (fun acc stmts -> Array.fold updateDefinedVar acc stmts) acc

  let private getStackPtrDef (hdl: BinHandler) wordSize =
    match hdl.RegisterBay.StackPointer with
    | Some sp ->
      SSA.RegVar (wordSize, sp, hdl.RegisterBay.RegIDToString sp) |> Some
    | None -> None

  let private getReturnValDef (hdl: BinHandler) wordSize =
    let r = CallingConvention.returnRegister hdl
    SSA.RegVar (wordSize, r, hdl.RegisterBay.RegIDToString r) |> Some

  let private addDefaultDefs hdl =
    let wordSize = hdl.ISA.WordSize |> WordSize.toRegType
    [ getStackPtrDef hdl wordSize; getReturnValDef hdl wordSize ]
    |> List.choose id
    |> List.map (fun kind -> { SSA.Kind = kind; SSA.Identifier = -1 })
    |> Set.ofList

  let private isGetPCThunkCode = function
    | 0xc324048bUL | 0xc3241c8bUL | 0xc3240c8bUL | 0xc324148bUL
    | 0xc324348bUL | 0xc3243c8bUL | 0xc3242c8bUL -> true
    | _ -> false

  /// This is a heuristic to discover __x86.get_pc_thunk- family functions.
  /// 1. If a function name symbol exists and its name matches, then we know it is
  /// __x86.get_pc_thunk- family
  /// 2. But there are some cases we don't have symbols for them. In such cases,
  /// we directly compare first 4 bytes of byte code. Because __x86.get_pc_thunk-
  /// family only has 4 bytes for its function body and their values are fixed.
  let private isGetPCThunk hdl addr =
    match hdl.FileInfo.TryFindFunctionSymbolName addr |> Utils.tupleToOpt with
    | Some name -> name.StartsWith "__x86.get_pc_thunk"
    | None -> BinHandler.ReadUInt (hdl, addr, 4) |> isGetPCThunkCode

  /// This is currently intra-procedural.
  let computeDefinedVars hdl (scfg: SCFG) addr =
    try
      let g, _ = scfg.GetFunctionCFG (addr, false)
      let defs = DiGraph.foldVertex g defVarFolder Set.empty
      let defs = if Set.isEmpty defs then addDefaultDefs hdl else defs
      let defs =
        if isGetPCThunk hdl addr then defs
        else
          let wordSize = hdl.ISA.WordSize |> WordSize.toRegType
          let r = CallingConvention.returnRegister hdl
          let retReg = SSA.RegVar (wordSize, r, hdl.RegisterBay.RegIDToString r)
          if not <| hdl.FileInfo.IsLinkageTable addr then defs
          else Set.add { SSA.Kind = SSA.MemVar; SSA.Identifier = -1 } defs
          |> Set.add { SSA.Kind = retReg; SSA.Identifier = -1 }
      Set.toArray defs
    with _ -> [||]

/// Basic block type for an SSA-based CFG (SSACFG).
type SSABBlock private (hdl, scfg, pp, instrs, retPoint, hasIndirectBranch) =
  inherit BasicBlock ()

  let mutable stmts =
    match retPoint with
    | Some (ret: ProgramPoint) ->
      let stmts = (* For a fake block, we check which things can be modified. *)
        SSABlockHelper.computeDefinedVars hdl scfg (pp: ProgramPoint).Address
        |> Array.map (fun dst ->
          let src = { SSA.Kind = dst.Kind; SSA.Identifier = -1 }
          SSA.Def (dst, SSA.ReturnVal (pp.Address, ret.Address, src)))
      let wordSize = hdl.ISA.WordSize |> WordSize.toRegType
      let fallThrough = BitVector.ofUInt64 ret.Address wordSize
      let jmpToFallThrough = SSA.Jmp (SSA.InterJmp (SSA.Num fallThrough))
      Array.append stmts [| jmpToFallThrough |]
    | None ->
      (instrs: InstructionInfo [])
      |> Array.map (fun i ->
        let wordSize = i.Instruction.WordSize |> WordSize.toRegType
        i.Stmts |> SSA.AST.translateStmts wordSize i.Instruction.Address)
      |> Array.concat

  let mutable frontier: Vertex<SSABBlock> list = []

  new (hdl, scfg, pp, instrs, hasIndirectBranch) =
    SSABBlock (hdl, scfg, pp, instrs, None, hasIndirectBranch)

  new (hdl, scfg, pp, retAddr, hasIndirectBranch) =
    SSABBlock (hdl, scfg, pp, [||], Some retAddr, hasIndirectBranch)

  override __.PPoint = pp

  override __.Range =
    let last = instrs.[instrs.Length - 1].Instruction
    AddrRange (pp.Address, last.Address + uint64 last.Length)

  override __.IsFakeBlock () = Array.isEmpty instrs

  override __.ToVisualBlock () =
    __.Stmts
    |> Array.map (fun stmt ->
      [| { AsmWordKind = AsmWordKind.String
           AsmWordValue = SSA.Pp.stmtToString stmt } |])

  /// Does this block has indirect branch?
  member __.HasIndirectBranch: bool = hasIndirectBranch

  /// Get the last statement of the bblock.
  member __.GetLastStmt () =
    stmts.[stmts.Length - 1]

  member __.Stmts with get () = stmts and set (v) = stmts <- v

  member __.InsInfos with get () = instrs

  member __.Frontier with get () = frontier and set(v) = frontier <- v

  member __.InsertPhi varKind count =
    let var = { SSA.Kind = varKind; SSA.Identifier = -1 }
    stmts <- Array.append [| SSA.Phi (var, Array.zeroCreate count) |] stmts

  override __.ToString () =
    if instrs.Length = 0 then "SSABBLK(Dummy)"
    else "SSABBLK(" + __.PPoint.Address.ToString("X") + ")"

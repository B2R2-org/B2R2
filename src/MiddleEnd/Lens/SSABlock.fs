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

namespace B2R2.MiddleEnd.Lens

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinHandleNS
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.BinEssenceNS

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

  let private buildRegVar hdl reg =
    let wordSize = hdl.ISA.WordSize |> WordSize.toRegType
    SSA.RegVar (wordSize, reg, hdl.RegisterBay.RegIDToString reg)

  let private addReturnValDef hdl defs =
    let reg = CallingConvention.returnRegister hdl |> buildRegVar hdl
    let def = { SSA.Kind = reg; SSA.Identifier = -1 }
    Set.add def defs

  let private addStackDef hdl defs =
    match hdl.RegisterBay.StackPointer with
    | Some sp ->
      let def = { SSA.Kind = buildRegVar hdl sp; SSA.Identifier = -1 }
      Set.add def defs
    | None -> defs

  let private addMemDef defs =
    let def = { SSA.Kind = SSA.MemVar; SSA.Identifier = - 1 }
    Set.add def defs

  let private isGetPCThunkCode = function
    | 0xc324048bUL | 0xc3241c8bUL | 0xc3240c8bUL | 0xc324148bUL
    | 0xc324348bUL | 0xc3243c8bUL | 0xc3242c8bUL -> true
    | _ -> false

  /// This is a heuristic to discover __x86.get_pc_thunk- family functions.
  /// 1. If a function name symbol exists and its name matches, then we know it
  /// is __x86.get_pc_thunk- family
  /// 2. But there are some cases we don't have symbols for them. In such cases,
  /// we directly compare first 4 bytes of byte code. Because
  /// __x86.get_pc_thunk- family only has 4 bytes for its function body and
  /// their values are fixed.
  let private isGetPCThunk hdl addr =
    match hdl.FileInfo.TryFindFunctionSymbolName addr with
    | Ok name -> name.StartsWith "__x86.get_pc_thunk"
    | Error _ -> BinHandle.ReadUInt (hdl, addr, 4) |> isGetPCThunkCode

  /// This is currently intra-procedural.
  let computeDefinedVars (ess: BinEssence) addr =
    let hdl = ess.BinHandle
    let defs = addStackDef hdl Set.empty
    try
      let g, _ = ess.GetFunctionCFG (addr, false)
      if hdl.FileInfo.IsLinkageTable addr then
        defs |> addReturnValDef hdl |> addMemDef |> Set.toArray
      else
        let defs = DiGraph.foldVertex g defVarFolder defs
        if isGetPCThunk hdl addr then defs
        else defs |> addReturnValDef hdl
        |> Set.toArray
    with _ -> defs |> addReturnValDef hdl |> Set.toArray

  let computeNextPPoint (ppoint: ProgramPoint) = function
    | SSA.Def (v, SSA.Num bv) ->
      match v.Kind with
      | SSA.PCVar _ -> ProgramPoint (BitVector.toUInt64 bv, 0)
      | _ -> ProgramPoint (ppoint.Address, ppoint.Position + 1)
    | _ -> ProgramPoint (ppoint.Address, ppoint.Position + 1)

type SSAStmtInfo = ProgramPoint * SSA.Stmt

/// Basic block type for an SSA-based CFG (SSACFG).
type SSABBlock private (ess, pp, instrs, retPoint, hasIndirectBranch) =
  inherit BasicBlock (pp)

  let mutable stmts: SSAStmtInfo [] =
    match retPoint with
    | Some (ret: ProgramPoint) ->
      let stmts = (* For a fake block, we check which can be modified. *)
        SSABlockHelper.computeDefinedVars ess (pp: ProgramPoint).Address
        |> Array.map (fun dst ->
          let src = { SSA.Kind = dst.Kind; SSA.Identifier = -1 }
          SSA.Def (dst, SSA.ReturnVal (pp.Address, ret.Address, src)))
      let wordSize = ess.BinHandle.ISA.WordSize |> WordSize.toRegType
      let fallThrough = BitVector.ofUInt64 ret.Address wordSize
      let jmpToFallThrough = SSA.Jmp (SSA.InterJmp (SSA.Num fallThrough))
      Array.append stmts [| jmpToFallThrough |]
      |> Array.map (fun s -> ProgramPoint.GetFake (), s)
    | None ->
      (instrs: InstructionInfo [])
      |> Array.map (fun i ->
        let wordSize = i.Instruction.WordSize |> WordSize.toRegType
        i.Stmts
        |> SSA.AST.translateStmts wordSize i.Instruction.Address)
      |> Array.concat
      |> Array.map (fun s -> ProgramPoint.GetFake (), s)

  let mutable frontier: Vertex<SSABBlock> list = []

  new (ess, pp, instrs, hasIndirectBranch) =
    SSABBlock (ess, pp, instrs, None, hasIndirectBranch)

  new (ess, pp, retAddr, hasIndirectBranch) =
    SSABBlock (ess, pp, [||], Some retAddr, hasIndirectBranch)

  override __.Range =
    let last = instrs.[instrs.Length - 1].Instruction
    AddrRange (pp.Address, last.Address + uint64 last.Length)

  override __.IsFakeBlock () = Array.isEmpty instrs

  override __.ToVisualBlock () =
    __.SSAStmtInfos
    |> Array.map (fun (_, stmt) ->
      [| { AsmWordKind = AsmWordKind.String
           AsmWordValue = SSA.Pp.stmtToString stmt } |])

  /// Does this block has indirect branch?
  member __.HasIndirectBranch: bool = hasIndirectBranch

  /// Get the last statement of the bblock.
  member __.GetLastStmt () =
    snd stmts.[stmts.Length - 1]

  member __.SSAStmtInfos with get () = stmts

  member __.InsInfos with get () = instrs

  member __.Frontier with get () = frontier and set(v) = frontier <- v

  member __.InsertPhi varKind count =
    let var = { SSA.Kind = varKind; SSA.Identifier = -1 }
    let ppoint = ProgramPoint.GetFake ()
    stmts <-
      Array.append [| ppoint, SSA.Phi (var, Array.zeroCreate count) |] stmts

  member __.AddressStmts () =
    stmts
    |> Array.foldi (fun ppoint idx (_, stmt) ->
      stmts.[idx] <- (ppoint, stmt)
      SSABlockHelper.computeNextPPoint ppoint stmt) pp
    |> ignore

  override __.ToString () =
    if instrs.Length = 0 then "SSABBLK(Dummy)"
    else "SSABBLK(" + __.PPoint.Address.ToString("X") + ")"

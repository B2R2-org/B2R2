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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinInterface
open B2R2.MiddleEnd.BinGraph

[<AutoOpen>]
module private SSABasicBlockHelper =
  let private buildRegVar hdl reg =
    let wordSize = hdl.ISA.WordSize |> WordSize.toRegType
    RegVar (wordSize, reg, hdl.RegisterBay.RegIDToString reg)

  let private addReturnValDef hdl defs =
    match (hdl: BinHandle).ISA.Arch with
    | Arch.EVM -> defs
    | _ ->
      let reg = CallingConvention.returnRegister hdl |> buildRegVar hdl
      let def = { Kind = reg; Identifier = -1 }
      Set.add def defs

  let private addStackDef hdl defs =
    match hdl.RegisterBay.StackPointer with
    | Some sp ->
      let def = { Kind = buildRegVar hdl sp; Identifier = -1 }
      Set.add def defs
    | None -> defs

  let private addMemDef defs =
    let def = { Kind = MemVar; Identifier = - 1 }
    Set.add def defs

  let computeDefinedVars hdl getPCThunkInfo isPLT =
    let defs = addStackDef hdl Set.empty
    if isPLT then defs |> addReturnValDef hdl |> addMemDef |> Set.toArray
    else
      match getPCThunkInfo with
      | YesGetPCThunk rid ->
        let def = { Kind = buildRegVar hdl rid; Identifier = -1 }
        Set.singleton def |> addStackDef hdl |> addMemDef |> Set.toArray
      | _ ->
        Set.empty
        |> addStackDef hdl |> addReturnValDef hdl |> addMemDef |> Set.toArray

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
    | SideEffect (eff, _, _) as stmt ->
      match eff with
      | ExternalCall (BinOp (BinOpType.APP, _,
                                    FuncName "calldatacopy", _)) ->
        let inVars, outVars = addInOutMemVars [] []
        SideEffect (eff, inVars, outVars)
      | _ -> stmt
    | stmt -> stmt

  let private postprocessOthers stmt = stmt

  let postprocessStmt hdl s =
    match hdl.ISA.Arch with
    | Arch.EVM -> postprocessStmtForEVM s
    | _ -> postprocessOthers s

/// SSA statement information.
type SSAStmtInfo = ProgramPoint * Stmt

/// Basic block type for an SSA-based CFG (SSACFG). It holds an array of
/// SSAStmtInfos (ProgramPoint * Stmt).
[<AbstractClass>]
type SSABasicBlock (pp, instrs: InstructionInfo []) =
  inherit BasicBlock (pp)

  let mutable idom: Vertex<SSABasicBlock> option = None
  let mutable frontier: Vertex<SSABasicBlock> list = []

  override __.Range =
    if Array.isEmpty instrs then Utils.impossible () else ()
    let last = instrs[instrs.Length - 1].Instruction
    AddrRange (pp.Address, last.Address + uint64 last.Length - 1UL)

  override __.IsFakeBlock () = Array.isEmpty instrs

  override __.ToVisualBlock () =
    __.SSAStmtInfos
    |> Array.map (fun (_, stmt) ->
      [| { AsmWordKind = AsmWordKind.String
           AsmWordValue = Pp.stmtToString stmt } |])

  /// Return the corresponding InstructionInfo array.
  member __.InsInfos with get () = instrs

  /// Get the last SSA statement of the bblock.
  member __.GetLastStmt () =
    snd __.SSAStmtInfos[__.SSAStmtInfos.Length - 1]

  /// Immediate dominator of this block.
  member __.ImmDominator with get() = idom and set(d) = idom <- d

  /// Dominance frontier of this block.
  member __.DomFrontier with get() = frontier and set(f) = frontier <- f

  /// Prepend a Phi node to this SSA basic block.
  member __.PrependPhi varKind count =
    let var = { Kind = varKind; Identifier = -1 }
    let ppoint = ProgramPoint.GetFake ()
    __.SSAStmtInfos <-
      Array.append [| ppoint, Phi (var, Array.zeroCreate count) |]
                   __.SSAStmtInfos

  /// Update program points. This must be called after updating SSA stmts.
  member __.UpdatePPoints () =
    __.SSAStmtInfos
    |> Array.foldi (fun ppoint idx (_, stmt) ->
      let ppoint' = computeNextPPoint ppoint stmt
      __.SSAStmtInfos[idx] <- (ppoint', stmt)
      ppoint') pp
    |> ignore

  /// Return the array of SSAStmtInfos.
  abstract SSAStmtInfos: SSAStmtInfo [] with get, set

  /// Return the corresponding fake block information. This is only valid for a
  /// fake SSABasicBlock.
  abstract FakeBlockInfo: FakeBlockInfo with get, set

/// Regular SSABasicBlock with regular instructions.
type RegularSSABasicBlock (hdl: BinHandle, pp, instrs) =
  inherit SSABasicBlock (pp, instrs)

  let mutable stmts: SSAStmtInfo [] =
    (instrs: InstructionInfo [])
    |> Array.map (fun i ->
      let wordSize = i.Instruction.WordSize |> WordSize.toRegType
      let stmts = i.Stmts
      let address = i.Instruction.Address
      AST.translateStmts wordSize address (postprocessStmt hdl) stmts)
    |> Array.concat
    |> Array.map (fun s -> ProgramPoint.GetFake (), s)

  override __.SSAStmtInfos with get() = stmts and set(s) = stmts <- s

  override __.FakeBlockInfo
    with get() = Utils.impossible () and set(_) = Utils.impossible ()

  override __.ToString () =
    "SSABBLK(" + String.u64ToHexNoPrefix __.PPoint.Address + ")"

/// Fake SSABasicBlock, which may or may not hold a function summary with
/// ReturnVal expressions.
type FakeSSABasicBlock (hdl, pp, retPoint: ProgramPoint, fakeBlkInfo) =
  inherit SSABasicBlock (pp, [||])

  let mutable stmts: SSAStmtInfo [] =
    if fakeBlkInfo.IsTailCall then [||]
    else
      let stmts = (* For a fake block, we check which var can be modified. *)
        computeDefinedVars hdl fakeBlkInfo.GetPCThunkInfo fakeBlkInfo.IsPLT
        |> Array.map (fun dst ->
          let src = { Kind = dst.Kind; Identifier = -1 }
          Def (dst, ReturnVal (pp.Address, retPoint.Address, src)))
      let wordSize = hdl.ISA.WordSize |> WordSize.toRegType
      let fallThrough = BitVector.OfUInt64 retPoint.Address wordSize
      let jmpToFallThrough = Jmp (InterJmp (Num fallThrough))
      Array.append stmts [| jmpToFallThrough |]
      |> Array.map (fun s -> ProgramPoint.GetFake (), s)

  let mutable fakeBlkInfo = fakeBlkInfo

  override __.SSAStmtInfos with get() = stmts and set(s) = stmts <- s

  override __.FakeBlockInfo
    with get() = fakeBlkInfo and set(f) = fakeBlkInfo <- f

  override __.ToString () =
    "SSABBLK(Dummy;" + pp.ToString () + ";" + retPoint.ToString () + ")"

/// SSACFG's vertex.
type SSAVertex = Vertex<SSABasicBlock>

[<RequireQualifiedAccess>]
module SSABasicBlock =
  let initRegular hdl pp instrs =
    RegularSSABasicBlock (hdl, pp, instrs) :> SSABasicBlock

  let initFake hdl pp retPoint fakeBlkInfo =
    FakeSSABasicBlock (hdl, pp, retPoint, fakeBlkInfo) :> SSABasicBlock

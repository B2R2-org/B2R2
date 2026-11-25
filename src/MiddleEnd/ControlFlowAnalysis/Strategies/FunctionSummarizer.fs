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

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open B2R2
open B2R2.ABI
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

/// Represents a base class for summarizing a function in a lightweight manner.
/// One can extend this class to implement a more sophisticated function
/// summarizer.
type FunctionSummarizer<'FnCtx, 'GlCtx>() =
  let retrieveStackAdjustment (ins: IInstruction) =
    match ins.Immediate() with
    | true, v -> int v
    | false, _ -> 0

  let intReturnValueDef (hdl: BinHandle) =
    let retReg =
      hdl.Conventions.Calling.IntReturnRegister
      |> hdl.RegisterFactory.GetRegVar
    let rt = hdl.ISA.WordSize |> WordSize.toRegType
    let e = AST.undef rt "ret"
    [| (retReg, e) |]

  /// Collects the definitions that leave the given register variable undefined
  /// under the given name. A concatenated register variable, such as ST0 or
  /// XMM0, cannot be a definition target, so we define each of the chunks it
  /// concatenates.
  let rec undefinedDefs name acc e =
    match e with
    | BinOp(Op = BinOpType.CONCAT; Left = hi; Right = lo) ->
      undefinedDefs name (undefinedDefs name acc hi) lo
    | _ ->
      (e, AST.undef (Expr.typeOf e) name) :: acc

  /// Collects the definitions of the registers that hold a floating-point
  /// return value, both halves of a double that takes two registers.
  let floatReturnValueDef (hdl: BinHandle) =
    ArgLocation.toRegisters hdl.Conventions.Calling.FloatReturnLocation
    |> List.map hdl.RegisterFactory.GetRegVar
    |> List.fold (undefinedDefs "ret") []
    |> List.toArray

  /// Makes the definitions that invalidate the given registers, which are the
  /// caller-saved registers that a callee may modify.
  let callerSavedValueDefs (hdl: BinHandle) (clobbered: Set<RegisterID>) =
    clobbered
    |> Seq.map hdl.RegisterFactory.GetRegVar
    |> Seq.fold (undefinedDefs "caller-saved") []
    |> List.toArray

  /// Returns how many bytes of the stack the return address of a call takes,
  /// which the return pops. A link register takes none.
  let returnAddressSize (hdl: BinHandle) rt =
    match hdl.Conventions.Calling.ReturnAddressLocation with
    | OnStack -> RegType.toByteWidth rt |> int64
    | InRegister _ -> 0L

  /// Makes the definition that moves the stack pointer past what the callee
  /// pops, if it pops anything.
  let stackPointerDef (hdl: BinHandle) unwindingAmount =
    match hdl.RegisterFactory.StackPointer with
    | Some sp ->
      let rt = hdl.RegisterFactory.GetRegType sp
      let shift = returnAddressSize hdl rt + int64 unwindingAmount
      if shift = 0L then
        [||]
      else
        let sp = hdl.RegisterFactory.GetRegVar sp
        let e = AST.binop BinOpType.ADD sp (AST.num (BitVector(shift, rt)))
        [| (sp, e) |]
    | None ->
      [||]

  let toRegExpr (hdl: BinHandle) register =
    Intel.Register.toRegID register
    |> hdl.RegisterFactory.GetRegVar

  let tryFindLiveRegFromGetPCThunk (hdl: BinHandle) (addr: Addr) =
    match hdl.ReadUInt(addr, 4) with
    | 0xc324048bUL -> Some(toRegExpr hdl Intel.Register.EAX)
    | 0xc3241c8bUL -> Some(toRegExpr hdl Intel.Register.EBX)
    | 0xc3240c8bUL -> Some(toRegExpr hdl Intel.Register.ECX)
    | 0xc324148bUL -> Some(toRegExpr hdl Intel.Register.EDX)
    | 0xc324348bUL -> Some(toRegExpr hdl Intel.Register.ESI)
    | 0xc3243c8bUL -> Some(toRegExpr hdl Intel.Register.EDI)
    | 0xc3242c8bUL -> Some(toRegExpr hdl Intel.Register.EBP)
    | _ -> None

  let genFreshStackVarExpr hdl =
    let rt = (hdl: BinHandle).ISA.WordSize |> WordSize.toRegType
    let spId = hdl.RegisterFactory.StackPointer.Value
    let sp = hdl.RegisterFactory.GetRegVar spId
    AST.load Endian.Little rt sp (* [rsp] *)

  /// Finds the register that a SPARC thunk reading the PC adds %o7 to:
  /// retl; add %o7, %rd, %rd, which gives rd the address of the call, as the
  /// call links it into %o7.
  let tryFindSPARCGetPCThunkReg (hdl: BinHandle) (addr: Addr) =
    if hdl.ReadUInt(addr, 4) = 0x81c3e008UL then
      let add = hdl.ReadUInt(addr + 4UL, 4)
      let rd = (add >>> 25) &&& 0x1fUL
      if add &&& 0xc1ffffe0UL = 0x8003c000UL && add &&& 0x1fUL = rd then
        enum<SPARC.Register> (int rd) |> SPARC.Register.toRegID |> Some
      else
        None
    else
      None

  let initializeLiveVarMap hdl funcAddr =
    match (hdl: BinHandle).ISA with
    | X86 ->
      match tryFindLiveRegFromGetPCThunk hdl funcAddr with
      | Some var ->
        let e = genFreshStackVarExpr hdl
        [| (var, e) |]
      | None ->
        [||]
    | SPARC ->
      match tryFindSPARCGetPCThunkReg hdl funcAddr with
      | Some rid ->
        let var = hdl.RegisterFactory.GetRegVar rid
        let link = SPARC.Register.toRegID SPARC.Register.O7
        let e = AST.binop BinOpType.ADD var (hdl.RegisterFactory.GetRegVar link)
        [| (var, e) |]
      | None ->
        [||]
    | _ ->
      [||]

  /// Finds how far into the frame of a caller 64-bit PowerPC code keeps its
  /// TOC pointer: 40 bytes under ELFv1, whose functions have descriptors in
  /// .opd, and 24 under ELFv2.
  let tocSaveOffset (hdl: BinHandle) =
    match BinFile.BinFileOps.tryFindSectionByName hdl.File ".opd" with
    | Ok _ -> 40UL
    | Error _ -> 24UL

  /// Makes the store that saves the TOC pointer of 64-bit PowerPC code in the
  /// frame of the caller, as the stub that a direct call to another module
  /// goes through does, which is where the caller reloads r2 from after such
  /// a call. An indirect call loads the TOC of its callee into r2, so the
  /// caller saves its own before the call, with no stub.
  let tocSaveDefs (hdl: BinHandle) =
    match hdl.ISA with
    | PPC64 ->
      let reg r = hdl.RegisterFactory.GetRegVar(PPC.Register.toRegID r)
      let offset = AST.num (BitVector(tocSaveOffset hdl, 64<rt>))
      let slot = AST.binop BinOpType.ADD (reg PPC.Register.R1) offset
      [| AST.store hdl.ISA.Endian slot (reg PPC.Register.R2) |]
    | _ ->
      [||]

  /// Makes the definition that leaves the return address in ra past a call of
  /// Alpha code, as the callee returns through ra, which is where GCC finds gp
  /// again from right past the call.
  let returnLinkDefs (hdl: BinHandle) (returnAddress: Addr) =
    match hdl.ISA with
    | Alpha ->
      let rid = Alpha.Register.toRegID Alpha.Register.R26
      let ra = hdl.RegisterFactory.GetRegVar rid
      [| AST.put ra (AST.num (BitVector(returnAddress, 64<rt>))) |]
    | _ ->
      [||]

  let computeLiveDefs hdl callee calleeInfo =
    let unwindingAmount, clobbered = calleeInfo.Unwinding, calleeInfo.Clobbered
    if calleeInfo.IsExternal then
      [| yield! intReturnValueDef hdl
         yield! floatReturnValueDef hdl
         yield! callerSavedValueDefs hdl clobbered
         yield! stackPointerDef hdl unwindingAmount |]
    else
      let liveVarDefs = initializeLiveVarMap hdl callee
      [| if Array.isEmpty liveVarDefs then
           yield! intReturnValueDef hdl
           yield! floatReturnValueDef hdl
           yield! callerSavedValueDefs hdl clobbered
         else
           yield! liveVarDefs
         yield! stackPointerDef hdl unwindingAmount |]

  /// Computes how many bytes are unwound by this function.
  abstract ComputeUnwindingAmount:
    ctx: CFGBuildingContext<'FnCtx, 'GlCtx> -> int

  /// Summarizes the function at `callee` using LowUIR, which the function of
  /// the given context calls with the given instruction.
  abstract Summarize:
       ctx: CFGBuildingContext<'FnCtx, 'GlCtx>
     * callee: Addr
     * calleeInfo: CalleeInfo
     * IInstruction
    -> Rundown<LowUIR.Stmt>

  /// Computes how many bytes are unwound in a simplistic way, assuming that
  /// "ret NN" instructions are used.
  default _.ComputeUnwindingAmount ctx =
    let mutable amount = 0
    let exits = ctx.CFG.Exits
    let reachableExits =
      exits
      |> Seq.filter (fun v ->
        not <| ctx.GapAnalysisVertices.Contains v.VData.Internals.PPoint)
    for exitV in reachableExits do
      let vData = exitV.VData :> ILowUIRBasicBlock
      if vData.IsAbstract then
        ()
      else
        let ins = vData.LastInstruction
        if ins.IsRET then
          let newAmount = retrieveStackAdjustment ins
          assert (amount <= newAmount) (* bad case *)
          amount <- newAmount
        else
          ()
    amount

  /// Simply over-approximates the function semantics. Particularly, we are
  /// interested in several well-known "getpc" functions for x86.
  default _.Summarize(ctx, callee, calleeInfo, callInstruction) =
    let returnAddress = ReturnAddress.ofCall callInstruction
    let stmts = (* For abstraction, we check which var can be defined. *)
      computeLiveDefs ctx.BinHandle callee calleeInfo
      |> Array.map (fun (dst, src) -> AST.put dst src)
    let regType = ctx.BinHandle.ISA.WordSize |> WordSize.toRegType
    let fallThrough = AST.num <| BitVector(returnAddress, regType)
    let jmpToFallThrough = AST.interjmp fallThrough InterJmpKind.Base
    [| yield! stmts
       yield! tocSaveDefs ctx.BinHandle
       yield! returnLinkDefs ctx.BinHandle returnAddress
       jmpToFallThrough |]

  interface IFunctionSummarizable<'FnCtx, 'GlCtx> with
    member this.Summarize(ctx, callee, calleeInfo, ins) =
      FunctionSummary(callee,
                      calleeInfo.Unwinding,
                      this.Summarize(ctx, callee, calleeInfo, ins),
                      calleeInfo.IsExternal,
                      calleeInfo.Status,
                      calleeInfo.PointerWrites)

    member _.MakeUnknownFunctionSummary(hdl, callIns, unwindingBytes) =
      let returnAddress = ReturnAddress.ofCall callIns
      let wordSize = hdl.ISA.WordSize
      let regType = wordSize |> WordSize.toRegType
      let fallThrough = AST.num <| BitVector(returnAddress, regType)
      let jmpToFallThrough = AST.interjmp fallThrough InterJmpKind.Base
      let stmts =
        stackPointerDef hdl unwindingBytes
        |> Array.map (fun (dst, src) -> AST.put dst src)
      let ssaRundown = [| yield! stmts; yield jmpToFallThrough |]
      (* Nothing tells which registers the callee takes, so it writes through
         none, rather than through every one that happens to hold a pointer
         as the call starts. *)
      FunctionSummary(0UL,
                      unwindingBytes,
                      ssaRundown,
                      false,
                      NotNoRet,
                      PointerWritesOf Map.empty)

    member this.ComputeUnwindingAmount ctx = this.ComputeUnwindingAmount ctx

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
open B2R2.FrontEnd
open B2R2.FrontEnd.Intel
open B2R2.MiddleEnd.BinGraph
open B2R2.MiddleEnd.ControlFlowGraph
open B2R2.MiddleEnd.ControlFlowAnalysis

[<AutoOpen>]
module private SRetAnalysisHelper =
  /// Intel32SRetAnalysis is instantiated only for an x86-32 ISA, so
  /// every native instruction reaching these helpers must be Intel-specific.
  let inline toIntelInstruction (ins: BinLifter.IInstruction) =
    ins :?> Intel.Instruction

  let isStackPointer = function
    | Intel.Register.RSP | Intel.Register.ESP -> true
    | _ -> false

  let stackAllocation wordSize (ins: Intel.Instruction) =
    match ins.Opcode, ins.Operands with
    | Intel.Opcode.PUSH, OneOperand _ -> wordSize
    | Intel.Opcode.SUB, TwoOperands(OprReg reg, OprImm(v, _))
      when isStackPointer reg -> int v
    | _ -> 0

  let countPushedBytes wordSize (inss: Intel.Instruction array) =
    inss |> Array.sumBy (stackAllocation wordSize)

  let tryFindLastPushedRegister (inss: Intel.Instruction array) =
    inss
    |> Array.tryFindIndexBack (fun ins -> ins.Opcode = Intel.Opcode.PUSH)
    |> Option.bind (fun idx ->
      match inss[idx].Operands with
      | OneOperand(OprReg reg) -> Some(idx, reg)
      | _ -> None)

  let isStackAddressDefinition reg (ins: Intel.Instruction) =
    match ins.Opcode, ins.Operands with
    | Intel.Opcode.LEA,
      TwoOperands(OprReg dst, OprMem(ValueSome baseReg, _, _, _))
      when dst = reg && isStackPointer baseReg -> Some true
    | _, TwoOperands(OprReg dst, _) when dst = reg -> Some false
    | _, ThreeOperands(OprReg dst, _, _) when dst = reg -> Some false
    | _ -> None

  let isZeroDisplacement = function
    | ValueNone | ValueSome 0L -> true
    | _ -> false

  let tryGetStackReturnBufferRegister (ins: Intel.Instruction) =
    match ins.Opcode, ins.Operands with
    | Intel.Opcode.MOV,
      TwoOperands(OprMem(ValueSome baseReg, ValueNone, disp, _), OprReg reg)
      when isStackPointer baseReg && isZeroDisplacement disp -> Some reg
    | _ -> None

  /// Finds the last `mov [esp], reg` before the indirect call. Compilers can
  /// pass the hidden sret pointer through a pre-allocated argument slot instead
  /// of using `push reg`; the zero-displacement stack store identifies the
  /// slot.
  let tryFindStackReturnBufferStore (inss: Intel.Instruction array) =
    inss
    |> Array.tryFindIndexBack (tryGetStackReturnBufferRegister >> Option.isSome)
    |> Option.bind (fun idx ->
      tryGetStackReturnBufferRegister inss[idx]
      |> Option.map (fun reg -> idx, reg))

  let tryFindStackAddressDefinitionBefore index reg inss =
    (inss: Intel.Instruction array)
    |> Array.take index
    |> Array.rev
    |> Array.tryPick (isStackAddressDefinition reg)

  let rec isStackAddressFromPredecessors
      ctx depth visited reg (vertex: IVertex<LowUIRBasicBlock>) =
    let internals = vertex.VData.Internals
    let pp = internals.PPoint
    if depth = 0 || internals.IsAbstract || Set.contains pp visited then
      false
    else
      let visited = Set.add pp visited
      let inss = internals.Instructions |> Array.map toIntelInstruction
      match tryFindStackAddressDefinitionBefore
              inss.Length reg inss with
      | Some isStackAddress ->
        isStackAddress
      | None ->
        let preds = ctx.CFG.GetPreds vertex
        (* Follow only a short, unambiguous provenance chain. If any incoming
           path disagrees or lacks evidence, do not classify the value as a
           stack-derived return buffer. *)
        not (Array.isEmpty preds)
        && Array.forall
             (isStackAddressFromPredecessors ctx (depth - 1) visited reg) preds

  let isStackAddressBefore ctx caller inss index reg =
    match tryFindStackAddressDefinitionBefore index reg inss with
    | Some isStackAddress ->
      isStackAddress
    | None ->
      let preds = ctx.CFG.GetPreds caller
      not (Array.isEmpty preds)
      && Array.forall (isStackAddressFromPredecessors ctx 2 Set.empty reg) preds

  /// Checks whether the argument nearest the call is a pointer derived from the
  /// caller's stack frame, as expected for a hidden sret return buffer. It
  /// recognizes both `push reg` and `mov [esp], reg`, and follows the register
  /// definition through at most two unambiguous predecessor blocks.
  let hasStackReturnBufferArgument ctx caller inss =
    match tryFindLastPushedRegister inss with
    | Some(pushIdx, reg)
      when isStackAddressBefore ctx caller inss pushIdx reg ->
      true
    | _ ->
      match tryFindStackReturnBufferStore inss with
      | Some(storeIdx, reg) ->
        isStackAddressBefore ctx caller inss storeIdx reg
      | None ->
        false

/// Decides whether an x86-32 indirect call passes a hidden sret argument.
type Intel32SRetAnalysis<'FnCtx, 'GlCtx
  when 'FnCtx :> IResettable
  and 'FnCtx: (new: unit -> 'FnCtx)
  and 'GlCtx: (new: unit -> 'GlCtx)>() =

  interface ISRetAnalyzable<'FnCtx, 'GlCtx> with
    /// An sret (structure-return) argument is a hidden pointer to caller-owned
    /// storage where a callee writes a value that cannot be returned directly
    /// in registers. In the x86-32 compiler pattern handled here, this pointer
    /// occupies one four-byte stack slot and the callee removes that slot (for
    /// example, with `ret 4`), while the caller removes the remaining
    /// arguments.
    /// We therefore report an sret call only when the caller's stack
    /// adjustment leaves exactly one word and that word is a stack-derived
    /// sret pointer. On x86-64, the hidden pointer is normally register-passed,
    /// so the generic analysis conservatively returns false instead.
    member _.IsSRetCall(ctx, caller) =
      let wordSize = WordSize.toByteWidth ctx.BinHandle.ISA.WordSize
      let inss =
        caller.VData.Internals.Instructions
        |> Array.map toIntelInstruction
      let pushed = countPushedBytes wordSize inss
      let lastIns = Array.last inss
      let fallthroughAddr = lastIns.Address + uint64 lastIns.Length
      match ctx.BBLFactory.PeekBBL fallthroughAddr with
      | Ok ftBBL ->
        if not <| hasStackReturnBufferArgument ctx caller inss then
          false
        else
          let firstIns = toIntelInstruction ftBBL[0]
          match firstIns.Opcode, firstIns.Operands with
          (* The caller leaves one sret word for the callee to pop. *)
          | Intel.Opcode.ADD, TwoOperands(OprReg reg, OprImm(v, _))
            when isStackPointer reg && pushed - int v = wordSize ->
            true
          (* The caller restores the sret word already popped by the callee. *)
          | Intel.Opcode.SUB, TwoOperands(OprReg reg, OprImm(v, _))
            when isStackPointer reg && int v = wordSize ->
            true
          | _ ->
            false
      | _ ->
        false

/// Conservatively assumes that an unknown indirect call is not an sret call,
/// i.e., that its callee pops no additional argument bytes. Conventional
/// compiler ABIs generally use caller cleanup for indirect calls, while x86-64
/// passes most arguments in registers and does not use callee-popped argument
/// counts.
type SRetAnalysis<'FnCtx, 'GlCtx
  when 'FnCtx :> IResettable
  and 'FnCtx: (new: unit -> 'FnCtx)
  and 'GlCtx: (new: unit -> 'GlCtx)>() =

  interface ISRetAnalyzable<'FnCtx, 'GlCtx> with
    /// Assumes that an unknown indirect call is not an sret call.
    member _.IsSRetCall(_, _) = false

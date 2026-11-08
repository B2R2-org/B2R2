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

/// Provides what tells how 32-bit ARM code runs and lays out a function: the
/// instructions that run only on a condition, the prologue that saves on the
/// stack the registers whose values the caller keeps, and the literals that
/// the code loads from the pool past it.
module internal ARM32Code =
  /// Tells whether the instruction runs only on a condition.
  let isConditional (ins: ARM32.Instruction) =
    match ins.Condition with
    | ARM32.Condition.AL | ARM32.Condition.NV | ARM32.Condition.UN -> false
    | _ -> true

  /// Tells whether the register keeps its value for the caller of a function
  /// that writes it: one that the convention has the callee save, or the link
  /// register, which holds where the function returns.
  let isPreserved (cc: CallingConvention) r =
    r = ARM32.Register.LR || cc.IsCalleeSaved(ARM32.Register.toRegID r)

  /// Tells whether the instruction saves a preserved register on the stack,
  /// with a push or with a store that moves the stack down first, which
  /// libgcc writes to keep the stack aligned to eight bytes.
  let saves cc (ins: ARM32.Instruction) =
    match ins.Opcode, ins.Operands with
    | (ARM32.Opcode.PUSH | ARM32.Opcode.VPUSH),
      ARM32.OneOperand(ARM32.OprRegList regs) ->
      List.exists (isPreserved cc) regs
    | (ARM32.Opcode.STMDB | ARM32.Opcode.VSTMDB),
      ARM32.TwoOperands(ARM32.OprReg ARM32.Register.SP,
                        ARM32.OprRegList regs) ->
      ins.WriteBack && List.exists (isPreserved cc) regs
    | ARM32.Opcode.STR,
      ARM32.TwoOperands(ARM32.OprReg r,
                        ARM32.OprMemory(ARM32.PreIdxMode(ARM32.ImmOffset(
                          ARM32.Register.SP, Some ARM32.Minus, _)))) ->
      isPreserved cc r
    | _ ->
      false

  /// Tells whether the instruction takes a return address back from the stack
  /// into the link register or the PC, as only an epilogue does.
  let popsReturnAddress (ins: ARM32.Instruction) =
    let holdsReturn r = r = ARM32.Register.LR || r = ARM32.Register.PC
    match ins.Opcode, ins.Operands with
    | ARM32.Opcode.POP, ARM32.OneOperand(ARM32.OprRegList regs) ->
      List.exists holdsReturn regs
    | (ARM32.Opcode.LDM | ARM32.Opcode.LDMIA),
      ARM32.TwoOperands(ARM32.OprReg ARM32.Register.SP,
                        ARM32.OprRegList regs) ->
      List.exists holdsReturn regs
    | ARM32.Opcode.LDR,
      ARM32.TwoOperands(ARM32.OprReg r,
                        ARM32.OprMemory(ARM32.PostIdxMode(ARM32.ImmOffset(
                          ARM32.Register.SP, _, _)))) ->
      holdsReturn r
    | _ ->
      false

  /// Returns how many bytes the load reads, if it reads a literal pool.
  let tryLiteralSizeOf (ins: ARM32.Instruction) =
    match ins.Opcode, ins.Operands with
    | ARM32.Opcode.LDR, _ ->
      Some 4UL
    | ARM32.Opcode.VLDR,
      ARM32.TwoOperands(ARM32.OprSIMD(ARM32.SFReg(ARM32.Vector r)), _)
      when r >= ARM32.Register.D0 && r <= ARM32.Register.D31 ->
      Some 8UL
    | ARM32.Opcode.VLDR, _ ->
      Some 4UL
    | _ ->
      None

  /// Returns where the literal that the instruction loads lies, if it loads
  /// one.
  let tryLiteralRangeOf (ins: IInstruction) =
    match ins.MemoryDereferences() with
    | true, [| addr |] ->
      tryLiteralSizeOf (ins :?> ARM32.Instruction)
      |> Option.map (fun size -> AddrRange.create addr (addr + size - 1UL))
    | _ ->
      None

  /// The farthest that a load lies from the literal it loads: an offset from
  /// the PC reaches 4095 bytes, and the PC reads 8 bytes past the load in ARM.
  let [<Literal>] LiteralReach = 4104UL

  /// Tells whether ARM code within reach of the address loads a literal that
  /// covers it, reading an instruction at every word with the given parser,
  /// as the code that loads it may be code that the recovery has yet to build,
  /// such as a case of a switch that a literal pool amid the switch serves.
  /// Only ARM code may be read this way, as one halfword in 32 reads as a load
  /// of a literal in Thumb, whether it is data, ARM code or the second half of
  /// a Thumb instruction.
  let isLoadedNearby (tryParse: Addr -> Result<IInstruction, _>) addr =
    let covers ins =
      match tryLiteralRangeOf ins with
      | Some(range: AddrRange) -> range.IsIncluding addr
      | None -> false
    let rec scan (insAddr: Addr) =
      if insAddr > addr + LiteralReach then
        false
      else
        match tryParse insAddr with
        | Ok ins when covers ins -> true
        | _ -> scan (insAddr + 4UL)
    scan ((addr - min addr LiteralReach) / 4UL * 4UL)

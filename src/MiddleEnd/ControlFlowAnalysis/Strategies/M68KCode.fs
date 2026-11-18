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
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.M68K

/// Provides what m68k code tells on its own of where a function starts. The
/// ABI of Linux passes every argument on the stack and leaves nothing for a
/// callee in a data or an address register, so code that reads one before it
/// writes it, other than to save it for its caller, runs on what code above
/// left there and starts no function. A function first sets up its frame,
/// saving the registers that it preserves, linking a frame pointer or taking
/// room on the stack, and the code above a function runs into nothing past
/// it: it returns, jumps, traps, or pads with a nop.
module internal M68KCode =
  /// Tells whether the code of the given length right above the address
  /// decodes as one instruction that satisfies the predicate.
  let private decodesAbove (lu: LiftingUnit) (addr: Addr) pred len =
    match lu.TryParseInstruction(addr - len) with
    | Ok ins -> uint64 ins.Length = len && pred (ins :?> Instruction)
    | Error _ -> false

  /// Tells whether an instruction that ends right at the address satisfies
  /// the predicate, at any length that it decodes at, as nothing tells where
  /// the instruction above an address starts.
  let private hasAbove lu (addr: Addr) pred =
    [ 2UL .. 2UL .. 10UL ]
    |> List.exists (fun len -> len <= addr && decodesAbove lu addr pred len)

  /// Tells whether the memory operand adds an index to the PC.
  let private isIndexedOnPC mem =
    match mem with
    | Indexed indexed -> indexed.Base = Some Register.PC && indexed.Index.IsSome
    | _ -> false

  /// Tells whether the instruction jumps through a table right past it, as
  /// GCC dispatches a switch: it jumps to the PC plus an index.
  let private isTableJump (ins: Instruction) =
    match ins.Opcode, ins.Operands with
    | Opcode.JMP, OneOperand(OpMem mem) -> isIndexedOnPC mem
    | _ -> false

  /// Tells whether a function preserves the register for its caller: D2 to D7
  /// and A2 to A6.
  let private isPreserved (reg: Register) =
    (reg >= Register.D2 && reg <= Register.D7)
    || (reg >= Register.A2 && reg <= Register.A6)

  /// Tells whether the instruction saves registers that its function
  /// preserves on the stack.
  let private saves (ins: Instruction) =
    match ins.Opcode, ins.Operands with
    | Opcode.MOVEM, TwoOperands(OpRegList _, OpMem(PreDec Register.A7)) ->
      true
    | Opcode.MOVE, TwoOperands(OpReg reg, OpMem(PreDec Register.A7)) ->
      ins.Size = OperandSize.Long && isPreserved reg
    | _ ->
      false

  /// Returns the registers that address the memory operand.
  let private regsOfMem mem =
    match mem with
    | Direct reg | PostInc reg | PreDec reg | Disp(_, reg) ->
      [ reg ]
    | Indexed indexed ->
      let index = indexed.Index |> Option.map _.Reg |> Option.toList
      Option.toList indexed.Base @ index

  /// Returns the registers that the operand names.
  let rec private regsOf opr =
    match opr with
    | OpReg reg -> [ reg ]
    | OpMem mem -> regsOfMem mem
    | OpRegList regs -> List.ofArray regs
    | OpRegPair(reg1, reg2) | OpMemPair(reg1, reg2) -> [ reg1; reg2 ]
    | OpBitField(f, spec) -> regsOf f @ regsOf spec.Offset @ regsOf spec.Width
    | _ -> []

  /// Tells whether the instruction only writes the register that it names as
  /// where its result goes, rather than reading it as well, as a move does.
  let private writesOnly (ins: Instruction) =
    match ins.Opcode with
    | Opcode.MOVE | Opcode.MOVEA | Opcode.MOVEQ | Opcode.LEA -> true
    | _ -> false

  /// Returns the registers that the operand where the result of the
  /// instruction goes reads: those that address it, and the register that it
  /// names unless the instruction only writes it.
  let private readsOfDest ins opr =
    match opr with
    | OpReg _ when writesOnly ins -> []
    | _ -> regsOf opr

  /// Returns the registers that the instruction reads. Even one that clears a
  /// register counts as reading it, as code in the middle of a function clears
  /// one right past a jump much as a function starts to, and a function that
  /// does starts with what it returns, which the code above would leave.
  let private readsOf (ins: Instruction) =
    match ins.Operands with
    | NoOperand -> []
    | OneOperand opr -> regsOf opr
    | TwoOperands(src, dst) -> regsOf src @ readsOfDest ins dst
    | ThreeOperands(a, b, c) -> regsOf a @ regsOf b @ regsOf c
    | FourOperands(a, b, c, d) -> regsOf a @ regsOf b @ regsOf c @ regsOf d

  /// Returns the register that the instruction names as where its result goes,
  /// if any.
  let private writesOf (ins: Instruction) =
    match ins.Operands with
    | OneOperand(OpReg reg) -> [ reg ]
    | TwoOperands(_, OpReg reg) -> [ reg ]
    | ThreeOperands(_, _, OpReg reg) -> [ reg ]
    | _ -> []

  /// Returns the registers that the instruction reads and those that it
  /// writes, leaving out what it saves for its caller: the registers that it
  /// pushes, or the frame pointer that it links.
  let private effectOf (ins: Instruction) =
    match ins.Opcode, ins.Operands with
    | _ when saves ins -> [], []
    | Opcode.LINK, TwoOperands(OpReg reg, _) -> [], [ reg ]
    | _ -> readsOf ins, writesOf ins

  /// Tells whether the register holds what code computes with: a data or an
  /// address register other than the stack pointer.
  let private isGeneral (reg: Register) =
    reg >= Register.D0 && reg <= Register.A6

  /// The most instructions that the reading of where a function may start goes
  /// through.
  let [<Literal>] private MaxLeadLength = 6

  /// Tells whether the code from the address reads a data or an address
  /// register that it has not written, other than to save it, before it
  /// changes the flow, within the given number of instructions. Code that does
  /// not decode may read anything.
  let rec private readsLeftover (lu: LiftingUnit) written addr count =
    if count = 0 then
      false
    else
      match lu.TryParseInstruction(addr: Addr) with
      | Ok ins ->
        let reads, writes = effectOf (ins :?> Instruction)
        let isLeftover reg = isGeneral reg && not (Set.contains reg written)
        if List.exists isLeftover reads then
          true
        elif ins.IsBranch || ins.IsInterrupt || ins.IsExit then
          false
        else
          let written = Set.union written (Set.ofList writes)
          readsLeftover lu written (addr + uint64 ins.Length) (count - 1)
      | Error _ ->
        true

  /// Tells whether the instruction takes room on the stack: it moves the stack
  /// pointer down by a constant.
  let private allocates (ins: Instruction) =
    let sp = Register.A7
    match ins.Opcode, ins.Operands with
    | Opcode.LEA, TwoOperands(OpMem(Disp(disp, src)), OpReg dst) ->
      src = sp && dst = sp && disp < 0s
    | (Opcode.SUBQ | Opcode.SUBA), TwoOperands(OpImm _, OpReg dst) ->
      dst = sp
    | _ ->
      false

  /// Tells whether the instruction sets up the frame of a function: it saves
  /// registers that the function preserves, links a frame pointer, or takes
  /// room on the stack.
  let private setsUpFrame (ins: Instruction) =
    ins.Opcode = Opcode.LINK || saves ins || allocates ins

  /// Tells whether code that ends with the instruction runs into nothing past
  /// it: it returns, jumps, traps, or pads with a nop.
  let private endsFlow (ins: Instruction) =
    let i = ins :> IInstruction
    i.IsRET || i.IsExit || i.IsNop
    || ins.Opcode = Opcode.BRA || ins.Opcode = Opcode.JMP

  /// Tells whether the code at the address shows a function starting there,
  /// given whether it starts its section: no table that a jump right above
  /// goes through starts there, as GCC lays out a switch, it reads no
  /// register that code above may have left, and it sets up a frame first or
  /// lies where no code runs into it.
  let showsEntry (lu: LiftingUnit) isSectionStart (addr: Addr) =
    match lu.TryParseInstruction(addr) with
    | Ok ins ->
      not (hasAbove lu addr isTableJump)
      && not (readsLeftover lu Set.empty addr MaxLeadLength)
      && (setsUpFrame (ins :?> Instruction)
          || isSectionStart
          || hasAbove lu addr endsFlow)
    | Error _ ->
      false

  /// Tells whether the indexed operand adds no more than a displacement to the
  /// PC, as one of the full extension format may.
  let private isPlainPCDisp (indexed: IndexedMem) =
    indexed.Base = Some Register.PC
    && indexed.Index.IsNone
    && indexed.OuterDisp.IsNone

  /// Returns the address that the memory operand of the instruction names as a
  /// displacement from the PC, if it does.
  let private tryPCRelative (ins: Instruction) mem =
    match mem with
    | Disp(disp, Register.PC) ->
      Some(ins.TargetOf(int32 disp))
    | Indexed indexed when isPlainPCDisp indexed ->
      Some(ins.TargetOf(indexed.BaseDisp))
    | _ ->
      None

  /// Returns the address that the operand of a LEA or a PEA names, which it
  /// takes as it is rather than reads: one that the PC gives, or, given that
  /// the binary stays where it is linked, one that it names absolutely.
  let private tryEffectiveAddress isFixedBase (ins: Instruction) opr =
    match opr with
    | OpMem mem -> tryPCRelative ins mem
    | OpAddr addr when isFixedBase -> Some addr
    | _ -> None

  /// Returns the address that the instruction takes as a constant, if any: the
  /// effective address that a LEA or a PEA computes, or, given that the binary
  /// stays where it is linked, a long immediate that it moves or compares, as
  /// code does that stores or passes a function pointer. Code that the loader
  /// may place anywhere holds no address as an immediate.
  let tryTakenAddress isFixedBase (ins: Instruction) =
    match ins.Opcode, ins.Operands with
    | Opcode.PEA, OneOperand opr | Opcode.LEA, TwoOperands(opr, _) ->
      tryEffectiveAddress isFixedBase ins opr
    | Opcode.MOVEQ, _ ->
      None
    | _, TwoOperands(OpImm imm, _) when isFixedBase ->
      if ins.Size = OperandSize.Long then Some(uint64 (uint32 imm)) else None
    | _ ->
      None

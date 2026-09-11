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

namespace B2R2.FrontEnd.CIL

open B2R2
open B2R2.FrontEnd.BinLifter

/// Represents a CIL instruction.
type Instruction internal(addr, numBytes, op, opr, lifter: ILiftable) =

  /// Address of this instruction.
  member _.Address with get(): Addr = addr

  /// Length of this instruction in bytes.
  member _.Length with get(): uint32 = numBytes

  /// Opcode.
  member _.Opcode with get(): Opcode = op

  /// Operands.
  member _.Operands with get(): Operands = opr

  interface IInstruction with

    member _.Address with get() = addr

    member _.Length with get() = numBytes

    member this.IsBranch =
      let ins = this :> IInstruction
      ins.IsDirectBranch || ins.IsCondBranch || ins.IsCall || ins.IsRET

    member _.IsModeChanging = false

    (* Every branch this machine has says where it goes by a distance written
       in the instruction itself, and a call names a method by a token rather
       than by where it is, so a branch is direct and a call is neither. *)
    member _.IsDirectBranch =
      match opr with
      | OneOperand(OprTarget _) | OneOperand(OprTargets _) -> true
      | _ -> false

    (* calli goes where a function pointer on the evaluation stack says, which
       is the one place a target is decided at run time. *)
    member _.IsIndirectBranch = op = Calli

    member _.IsCondBranch =
      match op with
      | Brfalse_S | Brtrue_S | Beq_S | Bge_S | Bgt_S | Ble_S | Blt_S
      | Bne_Un_S | Bge_Un_S | Bgt_Un_S | Ble_Un_S | Blt_Un_S
      | Brfalse | Brtrue | Beq | Bge | Bgt | Ble | Blt
      | Bne_Un | Bge_Un | Bgt_Un | Ble_Un | Blt_Un | Switch -> true
      | _ -> false

    (* brfalse goes where the value is not, and bne.un where the two are not
       the same; every other conditional branch goes where its name holds. *)
    member this.IsCJmpOnTrue =
      match op with
      | Brfalse_S | Brfalse | Bne_Un_S | Bne_Un -> false
      | _ -> (this :> IInstruction).IsCondBranch

    member _.IsCall =
      match op with
      | Call | Callvirt | Calli | Newobj | Jmp -> true
      | _ -> false

    (* endfinally and endfilter leave a handler the way ret leaves a method:
       for somewhere the instruction itself does not say. *)
    member _.IsRET =
      match op with
      | Ret | Endfinally | Endfilter -> true
      | _ -> false

    (* Nearly every instruction here pushes onto or pops from the evaluation
       stack, which is not the stack these ask about: nothing addresses it, so
       nothing is a push or a pop in the sense a stack pointer would notice. *)
    member _.IsPush = false

    member _.IsPop = false

    (* break hands control to a debugger, which is the one trap there is. *)
    member _.IsInterrupt = op = Break

    member _.IsExit =
      match op with
      | Throw | Rethrow -> true
      | _ -> false

    member _.IsNop = op = Nop

    member _.IsInlinedAssembly = false

    member this.IsTerminator _ =
      let ins = this :> IInstruction
      ins.IsBranch || ins.IsInterrupt || ins.IsExit

    member _.DirectBranchTarget(target: byref<Addr>) =
      match opr with
      | OneOperand(OprTarget t) ->
        target <- t
        true
      | _ ->
        false

    member _.IndirectTrampolineAddr(_: byref<Addr>) = false

    member _.MemoryDereferences(_: byref<Addr[]>) = false

    member _.Immediate(v: byref<int64>) =
      match opr with
      | OneOperand(OprI4 i) ->
        v <- int64 i
        true
      | OneOperand(OprI8 i) ->
        v <- i
        true
      | OneOperand(OprVar i) ->
        v <- int64 i
        true
      | OneOperand(OprByte b) ->
        v <- int64 b
        true
      | _ ->
        false

    (* A jmp hands the arguments on to another method and never comes back, so
       like a return or a throw it has no instruction after it. *)
    member this.GetNextInstrAddrs() =
      let ins = this :> IInstruction
      let next = addr + uint64 numBytes
      match opr with
      | OneOperand(OprTargets targets) ->
        next :: targets |> List.distinct |> List.toArray
      | OneOperand(OprTarget target) when ins.IsCondBranch ->
        [ next; target ] |> List.distinct |> List.toArray
      | OneOperand(OprTarget target) ->
        [| target |]
      | _ when ins.IsRET || ins.IsExit || op = Jmp ->
        [||]
      | _ ->
        [| next |]

    member _.InterruptNum(_: byref<int64>) = false

    member this.Translate builder = lifter.Lift(this, builder).Stream.ToStmts()

    member this.TranslateToList builder = lifter.Lift(this, builder).Stream

    member this.Disasm builder = lifter.Disasm(this, builder).ToString()

    member this.Disasm() =
      let builder = StringDisasmBuilder(false, null, WordSize.Bit64)
      lifter.Disasm(this, builder).ToString()

    member this.Decompose builder = lifter.Disasm(this, builder).ToAsmWords()

and internal ILiftable =
  abstract Lift: Instruction * ILowUIRBuilder -> ILowUIRBuilder
  abstract Disasm: Instruction * IDisasmBuilder -> IDisasmBuilder

// vim: set tw=80 sts=2 sw=2:

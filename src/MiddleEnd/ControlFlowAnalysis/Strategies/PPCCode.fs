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
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.PPC

/// Provides what PowerPC code tells on its own: where the routines start that
/// the ABI provides to save and to restore the registers that a function
/// preserves. A function that GCC optimizes for size calls one to save them
/// and jumps to one to restore them and return, which no symbol of a stripped
/// binary tells of, and which the linker lays down without a frame on 64-bit
/// PowerPC. Each routine stores or loads one register, from r14 or f14 up,
/// and runs into the routine of the next one, up to that of r31 or f31, which
/// returns. The slot of register n lies 32 - n slots below a base register.
module internal PPCCode =
  /// Represents what an instruction of a routine that saves or restores
  /// registers does.
  type private Step =
    /// Stores or loads the register of the given number to or from its slot
    /// below the given base register.
    | Access of number: int * baseReg: Register
    /// Loads r0 with the return address, as the routine of the last register
    /// that a restore takes starts to.
    | LinkLoad
    /// Moves r0 to LR, past which no routine starts.
    | LinkRestore
    /// Saves r0 to the frame of the caller, or pops the frame.
    | Frame
    | Return
    /// Ends the code before it, which no routine runs into.
    | Boundary
    | Other

  /// Gives the number of a general or floating-point register.
  let private numberOf (r: Register) =
    let n = int r
    if n < 32 then n else n - 32

  let private isSlot (r: Register) width (disp: int32) =
    let n = numberOf r
    n >= 14 && n <= 31 && int64 disp = int64 (n - 32) * width

  let private classifyAccess (ins: Instruction) =
    match ins.Opcode, ins.Operands with
    | (Opcode.LD | Opcode.LWZ), TwoOperands(OprReg Register.R0, OprMem _) ->
      LinkLoad
    | (Opcode.STD | Opcode.STW), TwoOperands(OprReg Register.R0, OprMem _) ->
      Frame
    | (Opcode.STD | Opcode.LD | Opcode.STFD | Opcode.LFD),
      TwoOperands(OprReg r, OprMem(d, b)) when isSlot r 8L d ->
      Access(numberOf r, b)
    | (Opcode.STW | Opcode.LWZ), TwoOperands(OprReg r, OprMem(d, b))
      when isSlot r 4L d ->
      Access(numberOf r, b)
    | _ ->
      Other

  let private classify (ins: Instruction) =
    let i = ins :> BinLifter.IInstruction
    match ins.Opcode, ins.Operands with
    | Opcode.MTLR, OneOperand(OprReg Register.R0) -> LinkRestore
    | Opcode.MR, TwoOperands(OprReg Register.R1, OprReg Register.R11) -> Frame
    | _ when i.IsRET && not i.IsCondBranch -> Return
    | _ when i.IsNop || i.IsExit -> Boundary
    | _ when i.IsBranch && not i.IsCondBranch && not i.IsCall -> Boundary
    | _ -> classifyAccess ins

  /// Represents a group of routines being read: the entries found so far, the
  /// register that the last access reached, the base it went through, and
  /// whether the return address is back in LR.
  type private Group =
    { Entries: Addr list
      Last: int
      Base: Register option
      Restored: bool }

  let private continues group number baseReg =
    (group.Last < 0 || number = group.Last + 1)
    && (group.Base.IsNone || group.Base = Some baseReg)

  /// Reads the group of routines whose steps start at the given index, giving
  /// the entries of its routines if it ends with the return of the routine of
  /// register 31. A routine starts at each access before LR is restored, or at
  /// the load of the return address right before the access.
  let rec private readGroup (steps: (Addr * Step)[]) i group =
    if i >= steps.Length then
      None
    else
      match snd steps[i] with
      | Access(n, b) when continues group n b ->
        let entry =
          if i > 0 && snd steps[i - 1] = LinkLoad then fst steps[i - 1]
          else fst steps[i]
        let entries =
          if group.Restored then group.Entries else entry :: group.Entries
        let group = { group with Entries = entries; Last = n; Base = Some b }
        readGroup steps (i + 1) group
      | LinkLoad | Frame ->
        readGroup steps (i + 1) group
      | LinkRestore ->
        readGroup steps (i + 1) { group with Restored = true }
      | Return when group.Last = 31 ->
        Some group.Entries
      | _ ->
        None

  let private emptyGroup =
    { Entries = []
      Last = -1
      Base = None
      Restored = false }

  /// Checks if a group of routines may start at the given step: no code runs
  /// into it, as the step before ends the code before it.
  let private startsGroup (steps: (Addr * Step)[]) i =
    match snd steps[i] with
    | Access _ | LinkLoad ->
      i = 0
      || (match snd steps[i - 1] with
          | Boundary | Return -> true
          | _ -> false)
    | _ ->
      false

  /// Checks if the given address lies within the frame of a function, past
  /// where its FDE starts, as an epilogue does, which restores registers the
  /// way a routine does.
  let private isWithinFrame (hdl: BinHandle) addr =
    match hdl.File with
    | :? ELFBinFile as elf ->
      match elf.TryFindFDERange addr with
      | Some frame -> frame.Min < addr
      | None -> false
    | _ ->
      false

  let private stepsOf (lu: LiftingUnit) (start, size) =
    [| for addr in start .. 4UL .. start + size - 4UL do
         match lu.TryParseInstruction addr with
         | Ok(:? Instruction as ins) -> addr, classify ins
         | _ -> addr, Boundary |]

  let private findEntriesIn hdl lu range =
    let steps = stepsOf lu range
    [| for i in 0 .. steps.Length - 1 do
         if startsGroup steps i && not (isWithinFrame hdl (fst steps[i])) then
           match readGroup steps i emptyGroup with
           | Some entries -> yield! entries
           | None -> ()
         else
           () |]

  /// Returns the ranges of the code to scan: the sections of code, or the
  /// segments that run, where no section tells of code, as in a raw image.
  let private codeRangesOf (hdl: BinHandle) =
    let file = hdl.File
    let sections =
      BinFileOps.getSections file
      |> Seq.filter (fun sec -> sec.Kind = CodeSection)
      |> Seq.map (fun sec -> sec.Address, sec.Size)
      |> Seq.toArray
    if Array.isEmpty sections then
      BinFileOps.getSegments file
      |> Seq.filter (fun seg -> seg.Permission.HasFlag Permission.Executable)
      |> Seq.map (fun seg -> seg.Address, seg.Size)
      |> Seq.toArray
    else
      sections

  /// Finds the entries of the routines that save and restore the registers
  /// that a function preserves.
  let findSaveRestoreEntries (hdl: BinHandle) =
    let lu = hdl.NewLiftingUnit()
    codeRangesOf hdl
    |> Seq.filter (fun (_, size) -> size >= 4UL)
    |> Seq.collect (findEntriesIn hdl lu)
    |> Seq.distinct
    |> Seq.toArray

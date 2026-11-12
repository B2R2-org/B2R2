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

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.MIPS

/// Provides what MIPS code tells on its own: where it addresses data, where
/// its functions start, and what its calls through the GOT reach. The code
/// builds an address in two halves: LUI sets a register to the high half, or
/// in PIC code a load from the local GOT through gp sets it to the page, and
/// an ADDIU of the low half to the register, or a load or a store at that
/// offset from it, completes the address. A PIC function finds gp by adding to
/// t9, which holds its own address on entry, the constant that takes that
/// address to gp.
module internal MIPSCode =
  /// Represents what a register holds as far as the scan knows.
  type private Holding =
    /// The global pointer, which the code of a binary with one GOT always sets
    /// to the same value.
    | GP
    /// The global pointer on its way from t9, which holds the address of the
    /// function on entry: the code adds t9 to a displacement, in either order
    /// with its low half, and the sum is the global pointer once complete.
    | FromEntry
    /// A displacement of the global pointer from t9, which LUI and ADDIU build
    /// in position-independent code, where they build no address.
    | Displacement
    /// A high half, as LUI sets it, or a page, as a local GOT entry holds it,
    /// which an ADDIU of the low half, or a load or a store at that offset,
    /// completes into an address.
    | High of value: Addr * setAt: Addr
    /// A whole address. One that the code has not used yet is pending, as it
    /// may be the displacement of the global pointer, which the code adds to
    /// t9 and never uses as an address.
    | Whole of value: Addr * pending: bool
    /// A high half or a page plus an index that the scan does not know, as the
    /// code reaches into a table. An access at the low half from it completes
    /// the address where the index selects the first entry.
    | Indexed of value: Addr * setAt: Addr

  /// Represents the state of the scan.
  type private Scan =
    { /// What each general-purpose register holds.
      Regs: Holding option[]
      /// The addresses of data found so far.
      Refs: HashSet<Addr>
      /// The value of the global pointer.
      GP: Addr
      /// The bits of an address of the binary.
      Mask: Addr
      /// Whether the code builds addresses from the high halves that LUI sets,
      /// as code that is not position-independent does.
      FromHalves: bool
      /// Reads the local GOT entry at the given address, if it is one.
      ReadGOT: Addr -> Addr option
      /// The address of the instruction the scan is at.
      mutable At: Addr }

  let [<Literal>] private T9 = 25

  /// The most bytes past where a high half or a page is set at which an
  /// instruction may complete an address from it, as a compiler keeps the two
  /// close. Past that, the register may well hold something else by another
  /// path that a scan in a straight line does not see.
  let [<Literal>] private Reach = 64UL

  let [<Literal>] private GPNumber = 28

  /// Returns the number of the given register, if it is a general-purpose one.
  let private tryGetNumber (r: Register) =
    let n = int r
    if n >= 0 && n < 32 then Some n else None

  /// Records the whole address that the given register holds, if it is
  /// pending, as the code uses it now.
  let private commit scan n =
    match scan.Regs[n] with
    | Some(Whole(v, true)) ->
      scan.Refs.Add(v &&& scan.Mask) |> ignore
      scan.Regs[n] <- Some(Whole(v, false))
    | _ ->
      ()

  /// Sets what the given register holds. The global pointer never holds
  /// anything else when the code uses it, so whatever writes it leaves it
  /// holding the global pointer, unless the write builds it.
  let private set scan n holding =
    match holding with
    | None when n = GPNumber -> scan.Regs[n] <- Some GP
    | _ when n = 0 -> ()
    | _ -> scan.Regs[n] <- holding

  /// Returns what the given register holds, as far as the scan still trusts
  /// it: a high half or a page set too far back is no longer known.
  let private holdingOf scan n =
    match scan.Regs[n] with
    | Some(High(_, at)) | Some(Indexed(_, at)) when scan.At - at > Reach -> None
    | holding -> holding

  /// Returns the address that the given register holds, if the scan knows it.
  let private tryGetValue scan n =
    match holdingOf scan n with
    | Some GP | Some FromEntry -> Some scan.GP
    | Some(High(v, _)) | Some(Whole(v, _)) | Some(Indexed(v, _)) -> Some v
    | Some Displacement | None -> None

  /// Returns the number of each register that the given operands name.
  let private registersOf (operands: Operand list) =
    operands
    |> List.choose (fun opr ->
      match opr with
      | OpReg r -> tryGetNumber r
      | OpMem(b, _, _) -> tryGetNumber b
      | _ -> None)

  /// Returns the operands of the given instruction in order.
  let private operandsOf (ins: Instruction) =
    match ins.Operands with
    | NoOperand -> []
    | OneOperand o1 -> [ o1 ]
    | TwoOperands(o1, o2) -> [ o1; o2 ]
    | ThreeOperands(o1, o2, o3) -> [ o1; o2; o3 ]
    | FourOperands(o1, o2, o3, o4) -> [ o1; o2; o3; o4 ]

  /// Checks if the given opcode stores the register that its first operand
  /// names, rather than writes it.
  let private isStore = function
    | Opcode.SB | Opcode.SH | Opcode.SW | Opcode.SD | Opcode.SWL | Opcode.SWR
    | Opcode.SDL | Opcode.SDR | Opcode.SWC1 | Opcode.SDC1 | Opcode.SWXC1
    | Opcode.SDXC1 | Opcode.SUXC1 -> true
    | _ -> false

  /// Returns the register that the given instruction writes as it names it
  /// first, if any, and the registers it reads.
  let private accessesOf (ins: Instruction) =
    match operandsOf ins with
    | OpReg r :: rest
      when not (isStore ins.Opcode) && not (ins :> IInstruction).IsBranch ->
      tryGetNumber r, registersOf rest
    | operands ->
      None, registersOf operands

  /// Updates the scan by an instruction that the scan does not follow: it
  /// leaves what it writes unknown. What it reads it uses as a number, as a
  /// comparison or a mask does, so no address that it reads is recorded.
  let private stepOther scan ins =
    accessesOf ins |> fst |> Option.iter (fun n -> set scan n None)

  /// Sign-extends the given 16-bit immediate.
  let private signExtend16 (imm: uint64) = uint64 (int64 (int16 (uint16 imm)))

  /// Returns the high half that LUI sets from the given immediate.
  let private highOf (imm: uint64) = uint64 (int64 (int32 (uint32 imm <<< 16)))

  /// Updates the scan by an ADDIU or a DADDIU of the given immediate to the
  /// given source register: it completes an address from a high half, a page,
  /// or the global pointer, or goes on building the global pointer from t9.
  /// The scan follows no offset from a whole address, which reaches a field
  /// within whatever the address names.
  let private stepLow scan d s imm =
    commit scan s
    match holdingOf scan s with
    | Some FromEntry -> set scan d (Some FromEntry)
    | Some Displacement -> set scan d (Some Displacement)
    | Some GP -> set scan d (Some(Whole(scan.GP + imm, true)))
    | Some(High(v, _)) -> set scan d (Some(Whole(v + imm, true)))
    | _ -> set scan d None

  /// Updates the scan by an ADDU or a DADDU of t9 to the given register, which
  /// builds the global pointer from the displacement that the register holds.
  /// The displacement is no address, so it is dropped rather than recorded.
  let private stepFromEntry scan d other =
    match scan.Regs[other] with
    | Some(Whole(v, _)) ->
      scan.Regs[other] <- Some(Whole(v, false))
      set scan d (Some FromEntry)
    | Some(High _) | Some Displacement ->
      set scan d (Some FromEntry)
    | _ ->
      commit scan other
      set scan d None

  /// Updates the scan by an ADDU or a DADDU of the given registers: a high half
  /// or a page plus a value the scan does not know is on its way to an entry
  /// of a table. A whole address plus an index reaches an element at an
  /// index that need not start from zero, and the scan follows it no further.
  let private stepIndex scan d s t =
    commit scan s
    commit scan t
    match holdingOf scan s, holdingOf scan t with
    | Some(High(v, at)), None | None, Some(High(v, at)) ->
      set scan d (Some(Indexed(v, at)))
    | _ ->
      set scan d None

  /// Checks if an access at an offset from what the given register holds
  /// completes an address: from a high half, a page, or the global pointer,
  /// but not from a whole address, which the offset reaches a field of.
  let private completes scan n =
    match holdingOf scan n with
    | Some(Whole _) | Some Displacement | None -> false
    | Some GP | Some FromEntry | Some(High _) | Some(Indexed _) -> true

  /// Updates the scan by a load or a store at the given offset from the given
  /// base: a load of a local GOT entry gives its destination the page or the
  /// address in it, and any other access may complete an address.
  let private stepAccess scan (ins: Instruction) rt b (offset: int64) =
    commit scan b
    let isLoad = not (isStore ins.Opcode)
    let addr = tryGetValue scan b |> Option.map (fun v -> v + uint64 offset)
    match addr |> Option.bind scan.ReadGOT with
    | Some entry when isLoad ->
      set scan rt (Some(High(entry, scan.At)))
    | Some _ ->
      ()
    | None ->
      if completes scan b then
        scan.Refs.Add(Option.get addr &&& scan.Mask) |> ignore
      else
        ()
      if isLoad then set scan rt None else commit scan rt

  /// Updates the scan by the given instruction, which is no branch.
  let private step scan (ins: Instruction) =
    match ins.Opcode, ins.Operands with
    | Opcode.LUI, TwoOperands(OpReg d, OpImm imm) ->
      let holding =
        if scan.FromHalves then High(highOf imm, scan.At) else Displacement
      tryGetNumber d |> Option.iter (fun d -> set scan d (Some holding))
    | (Opcode.ADDIU | Opcode.DADDIU),
      ThreeOperands(OpReg d, OpReg s, OpImm imm) ->
      match tryGetNumber d, tryGetNumber s with
      | Some d, Some s -> stepLow scan d s (signExtend16 imm)
      | _ -> stepOther scan ins
    | (Opcode.ADDU | Opcode.DADDU), ThreeOperands(OpReg d, OpReg s, OpReg t)
      when int s = T9 || int t = T9 ->
      let other = if int s = T9 then t else s
      match tryGetNumber d, tryGetNumber other with
      | Some d, Some other -> stepFromEntry scan d other
      | _ -> stepOther scan ins
    | (Opcode.ADDU | Opcode.DADDU), ThreeOperands(OpReg d, OpReg s, OpReg t) ->
      match tryGetNumber d, tryGetNumber s, tryGetNumber t with
      | Some d, Some s, Some t -> stepIndex scan d s t
      | _ -> stepOther scan ins
    | Opcode.OR, ThreeOperands(OpReg d, OpReg s, OpReg Register.R0) ->
      match tryGetNumber d, tryGetNumber s with
      | Some d, Some s -> set scan d scan.Regs[s]
      | _ -> stepOther scan ins
    | _, TwoOperands(OpReg rt, OpMem(b, Imm offset, _)) ->
      match tryGetNumber rt, tryGetNumber b with
      | Some rt, Some b -> stepAccess scan ins rt b offset
      | _ -> stepOther scan ins
    | _ ->
      stepOther scan ins

  /// Checks if the given instruction leaves the code that follows it to run
  /// with values from elsewhere: a jump, a return, or one that stops.
  let private leaves (ins: IInstruction) =
    (ins.IsBranch && not ins.IsCondBranch && not ins.IsCall) || ins.IsExit

  /// Checks if the given holding is the global pointer, which a binary with one
  /// GOT holds wherever its code runs.
  let private isGP = function
    | Some GP | Some FromEntry -> true
    | _ -> false

  /// Forgets what every register holds but the global pointer. A register
  /// that holds the global pointer goes on holding it, as the code of a
  /// function keeps a copy of it in one.
  let private forgetAll scan =
    for n in 0 .. 31 do
      if isGP scan.Regs[n] then () else set scan n None
    done

  /// Updates the scan by what the given instruction does to the code after
  /// it, past its delay slot. A call uses the addresses in the argument
  /// registers, a0 to a7, and leaves the registers that the callee may change
  /// unknown; a jump through a register, as a return or a call in tail
  /// position, uses those in the value registers and the argument registers,
  /// and like any instruction that leaves, it forgets every register.
  let private stepFlow scan (ins: Instruction) =
    let i = ins :> IInstruction
    if i.IsCall then
      for n in 4 .. 11 do commit scan n done
      for n in [ 1 .. 15 ] @ [ 24; 25; 31 ] do set scan n None done
    elif leaves i then
      if i.IsIndirectBranch then for n in 2 .. 11 do commit scan n done
      else ()
      forgetAll scan
    else
      ()

  /// Updates the scan by the given branch: it reads its registers, then its
  /// delay slot runs, and then the branch takes effect. A conditional branch
  /// only compares what it reads, which is no use of an address: code
  /// compares a register with a number it builds as it builds an address.
  let private stepBranch scan (ins: Instruction) =
    if (ins :> IInstruction).IsCondBranch then ()
    else accessesOf ins |> snd |> List.iter (commit scan)
    ins.DelaySlot
    |> Option.iter (fun slot ->
      scan.At <- slot.Address
      step scan slot)
    stepFlow scan ins

  /// Collects into the scan the addresses of data that the code of the given
  /// section computes, reading the section as one run of instructions. A word
  /// that is no instruction is data amid the code, past which no register
  /// holds anything known.
  let private scanSection (lu: LiftingUnit) scan (sec: BinSection) =
    let rec loop (addr: Addr) =
      if addr + 4UL <= sec.Address + sec.Size then
        match lu.TryParseInstruction addr with
        | Ok ins ->
          scan.At <- addr
          let ins = ins :?> Instruction
          if (ins :> IInstruction).IsBranch || ins.HasDelaySlot then
            stepBranch scan ins
            loop ins.FallThroughAddress
          else
            step scan ins
            loop (addr + uint64 ins.Length)
        | Error _ ->
          forgetAll scan
          loop (addr + 4UL)
      else
        ()
    loop sec.Address

  /// Returns the local GOT entry at the given address, if it is one: an entry
  /// of the GOT that only the loader writes.
  let private tryReadGOT (hdl: BinHandle) (elf: ELFBinFile) got addr =
    let isInGOT (sec: BinSection) =
      sec.Address <= addr && addr < sec.Address + sec.Size
    if Option.exists isInGOT got && elf.IsReadOnlyAfterLoading addr then
      let width = WordSize.toByteWidth hdl.File.ISA.WordSize
      match hdl.TryReadUInt(addr, width) with
      | Ok v when width = 4 -> Some(uint64 (int64 (int32 (uint32 v))))
      | Ok v -> Some v
      | Error _ -> None
    else
      None

  /// Checks if the code of the given binary builds addresses from the high
  /// halves that LUI sets: 32-bit code that is not position-independent does,
  /// whereas position-independent code reads them from the GOT, as all 64-bit
  /// code does, where LUI only builds numbers.
  let private buildsFromHalves (hdl: BinHandle) =
    hdl.File.ISA.WordSize = WordSize.Bit32 && not hdl.File.IsBaseRelative

  /// Returns the mask of the bits of an address of the given width.
  let private maskOf wordSize =
    if wordSize = WordSize.Bit32 then 0xffffffffUL else System.UInt64.MaxValue

  /// Finds the GOT of the given binary, if it has one.
  let private tryFindGOT (hdl: BinHandle) =
    hdl.File.Structure
    |> Option.bind (fun st ->
      match st.TryFindSectionByName ".got" with
      | Ok got -> Some got
      | Error _ -> None)

  /// Returns the value of gp in the code of a binary with the given GOT, which
  /// points past its start so that an offset of 16 bits reaches all of it.
  let private gpOf (got: BinSection) = got.Address + 0x7ff0UL

  /// Collects, in ascending order, the addresses of data that the code of the
  /// given binary computes on its own, each where a piece of data starts or a
  /// place within one. A binary without a GOT has no global pointer to read
  /// it through, and only its LUI pairs tell.
  let collectDataReferences (hdl: BinHandle) =
    let refs = HashSet<Addr>()
    match hdl.File with
    | :? ELFBinFile as elf ->
      let got = tryFindGOT hdl
      let scan =
        { Regs = Array.create 32 None
          Refs = refs
          GP = got |> Option.map gpOf |> Option.defaultValue 0UL
          Mask = maskOf hdl.File.ISA.WordSize
          FromHalves = buildsFromHalves hdl
          ReadGOT = tryReadGOT hdl elf got
          At = 0UL }
      scan.Regs[GPNumber] <- Some GP
      let lu = hdl.NewLiftingUnit()
      BinFileOps.getSections hdl.File
      |> Seq.filter (fun sec -> sec.Kind = CodeSection)
      |> Seq.iter (scanSection lu scan)
    | _ ->
      ()
    let addrs = Seq.toArray refs
    Array.sortInPlace addrs
    addrs

  /// Represents where a scan for prologues looks: the code of a section, in
  /// which gp has the given value, in addresses of the bits of the mask.
  type private PrologueScan =
    { LU: LiftingUnit
      Section: BinSection
      GP: Addr
      Mask: Addr }

  /// The most bytes before the LUI that starts to find gp at which its function
  /// may start, as a prologue may make the frame and save registers first.
  let [<Literal>] private MaxPrologueLead = 64UL

  /// The most instructions past the LUI within which a prologue adds t9.
  let [<Literal>] private MaxPrologueSpan = 16

  /// The most NOPs that may pad the code before the entry of a function.
  let [<Literal>] private MaxPadding = 4

  /// Checks if the given instruction ends a run of straight code.
  let private isBranch (ins: Instruction) =
    (ins :> IInstruction).IsBranch || ins.HasDelaySlot

  /// Updates what the registers hold in a prologue by the given instruction,
  /// each a constant that the code may have added t9 to: an ADDIU adds its
  /// immediate, an ADDU of t9 adds t9, and any other write leaves the register
  /// holding nothing known. Returns None once the code writes t9, which then
  /// no longer holds the entry.
  let private stepPrologue mask (held: Map<int, Addr * bool>) ins =
    let carry d value =
      match value with
      | Some v -> Some(Map.add d v held)
      | None -> Some(Map.remove d held)
    match (ins: Instruction).Opcode, ins.Operands with
    | (Opcode.ADDIU | Opcode.DADDIU),
      ThreeOperands(OpReg d, OpReg s, OpImm imm) when int d <> T9 ->
      held.TryFind(int s)
      |> Option.map (fun (c, t9) -> (c + signExtend16 imm) &&& mask, t9)
      |> carry (int d)
    | (Opcode.ADDU | Opcode.DADDU), ThreeOperands(OpReg d, OpReg s, OpReg t)
      when (int s = T9 || int t = T9) && int d <> T9 ->
      held.TryFind(if int s = T9 then int t else int s)
      |> Option.bind (fun (c, t9) -> if t9 then None else Some(c, true))
      |> carry (int d)
    | _ ->
      match accessesOf ins |> fst with
      | Some T9 -> None
      | Some d -> Some(Map.remove d held)
      | None -> Some held

  /// Checks if the code runs straight from the given address to the given
  /// one, so that a function entered at the former reaches the latter.
  let rec private runsStraight scan (addr: Addr) target =
    if addr >= target then
      addr = target
    else
      match scan.LU.TryParseInstruction addr with
      | Ok ins when not (isBranch (ins :?> Instruction)) ->
        runsStraight scan (addr + 4UL) target
      | _ ->
        false

  /// Checks if the given instruction leaves t9 to the code after it as no one
  /// knows it: it leaves for good, as a return does, or it is a call, whose
  /// callee may change t9.
  let private leavesT9Unknown (ins: IInstruction) =
    leaves ins || (ins.IsCall && not ins.IsCondBranch)

  /// Checks if the instruction at the given address leaves t9 to the code
  /// after it as no one knows it, with its delay slot right before next.
  let private leavesT9UnknownBefore scan (addr: Addr) next =
    match scan.LU.TryParseInstruction addr with
    | Ok(:? Instruction as ins) ->
      leavesT9Unknown ins && ins.FallThroughAddress = next
    | _ ->
      false

  /// Checks if no code runs into the given address with t9 holding it: it
  /// starts its section, or the code before it, past the NOPs that may pad it,
  /// leaves for good or calls. The code that a call returns to never finds gp
  /// from t9, which the callee may have changed, so the call never returns
  /// there. Data before it runs into nothing either.
  let rec private startsCode scan (addr: Addr) padding =
    let sec = scan.Section
    if addr = sec.Address then
      true
    elif addr >= sec.Address + 8UL
         && leavesT9UnknownBefore scan (addr - 8UL) addr then
      true
    elif padding > 0 then
      match scan.LU.TryParseInstruction(addr - 4UL) with
      | Ok ins when ins.IsNop ->
        startsCode scan (addr - 4UL) (padding - 1)
      | Ok _ ->
        false
      | Error _ ->
        true
    else
      false

  /// Finds the entry that a register holding t9 plus the given constant tells,
  /// for a prologue whose LUI is at luiAddr: the address that t9 has to hold
  /// for the sum to be gp, if no code runs into it, and the code runs straight
  /// from there to the LUI, not far before it.
  let private tryEntryOf scan luiAddr (c: Addr, hasT9) =
    let entry = (scan.GP - c) &&& scan.Mask
    if hasT9
       && entry <= luiAddr
       && luiAddr - entry <= MaxPrologueLead
       && entry >= scan.Section.Address
       && entry % 4UL = 0UL
       && runsStraight scan entry luiAddr
       && startsCode scan entry MaxPadding
    then Some entry
    else None

  /// Finds the entry that any of the given registers tells, for a prologue
  /// whose LUI is at luiAddr.
  let private tryEntryIn scan luiAddr (held: Map<int, Addr * bool>) =
    held |> Map.values |> Seq.tryPick (tryEntryOf scan luiAddr)

  /// Checks if the given branch runs its delay slot only when it is taken.
  let private isLikely (ins: Instruction) =
    match ins.Opcode with
    | Opcode.BEQL | Opcode.BNEL | Opcode.BLEZL | Opcode.BLTZL | Opcode.BGEZL
    | Opcode.BGTZL | Opcode.BLTZALL | Opcode.BGEZALL | Opcode.BC1FL
    | Opcode.BC1TL -> true
    | _ -> false

  /// Returns the delay slot of the given branch if the slot runs whether or
  /// not the branch is taken.
  let private tryGetSlotRunAlways (ins: Instruction) =
    if isLikely ins then None else ins.DelaySlot

  /// Finds the entry of the function whose prologue starts to find gp with the
  /// given LUI, following the straight code past it up to the delay slot of
  /// the branch that ends it, which runs either way unless the branch is a
  /// likely one.
  let private tryFindPrologueEntry scan (lui: Instruction) =
    let rec loop held (addr: Addr) n =
      match tryEntryIn scan lui.Address held with
      | Some _ as found ->
        found
      | None when n = 0 || Map.isEmpty held ->
        None
      | None ->
        match scan.LU.TryParseInstruction addr with
        | Ok(:? Instruction as ins) when not (isBranch ins) ->
          match stepPrologue scan.Mask held ins with
          | Some held -> loop held (addr + 4UL) (n - 1)
          | None -> None
        | Ok(:? Instruction as ins) ->
          tryGetSlotRunAlways ins
          |> Option.bind (stepPrologue scan.Mask held)
          |> Option.bind (tryEntryIn scan lui.Address)
        | _ ->
          None
    match lui.Operands with
    | TwoOperands(OpReg d, OpImm imm) when int d > 0 && int d < 32 ->
      let held = Map.ofList [ int d, (highOf imm &&& scan.Mask, false) ]
      loop held (lui.Address + 4UL) MaxPrologueSpan
    | _ ->
      None

  /// Finds the entries of the functions in the given section whose prologues
  /// find gp from t9.
  let private findPrologueEntriesIn lu gp mask (sec: BinSection) =
    let scan = { LU = lu; Section = sec; GP = gp; Mask = mask }
    [| sec.Address .. 4UL .. sec.Address + sec.Size - 4UL |]
    |> Array.choose (fun addr ->
      match scan.LU.TryParseInstruction addr with
      | Ok(:? Instruction as ins) when ins.Opcode = Opcode.LUI ->
        tryFindPrologueEntry scan ins
      | _ ->
        None)

  /// Finds the entries of the functions of the given binary whose code finds
  /// gp from t9, which holds the address of a PIC function on entry: the
  /// constant that the code adds to t9 is gp less that address, so the address
  /// is gp less the constant, where the code has to run straight to the add,
  /// which may sit in the delay slot of a branch that runs it either way.
  let findGPPrologueEntries (hdl: BinHandle) =
    match tryFindGOT hdl with
    | Some got ->
      let lu = hdl.NewLiftingUnit()
      let mask = maskOf hdl.File.ISA.WordSize
      BinFileOps.getSections hdl.File
      |> Seq.filter (fun sec -> sec.Kind = CodeSection && sec.Size >= 4UL)
      |> Seq.collect (findPrologueEntriesIn lu (gpOf got) mask)
      |> Seq.distinct
      |> Seq.toArray
    | None ->
      [||]

  /// Checks if the given instruction calls through t9.
  let private callsThroughT9 (ins: Instruction) =
    match ins.Opcode, ins.Operands with
    | Opcode.JALR, OneOperand(OpReg r)
    | Opcode.JALR, TwoOperands(_, OpReg r) -> int r = T9
    | _ -> false

  /// Checks if the given instruction writes t9.
  let private writesT9 ins = fst (accessesOf ins) = Some T9

  /// Finds the offset from gp of the GOT entry that the given instructions load
  /// into t9 last, going back from the one at idx, along with what they add to
  /// it after, as code reaching a function through a local page does.
  let rec private tryFindT9Load (instrs: Instruction[]) idx (added: uint64) =
    if idx < 0 then
      None
    else
      let ins = instrs[idx]
      match ins.Opcode, ins.Operands with
      | (Opcode.LW | Opcode.LD), TwoOperands(OpReg d, OpMem(b, Imm offset, _))
        when int d = T9 && int b = GPNumber ->
        Some(uint64 offset, added)
      | (Opcode.ADDIU | Opcode.DADDIU),
        ThreeOperands(OpReg d, OpReg s, OpImm imm)
        when int d = T9 && int s = T9 && added = 0UL ->
        tryFindT9Load instrs (idx - 1) (signExtend16 imm)
      | _ when writesT9 ins ->
        None
      | _ ->
        tryFindT9Load instrs (idx - 1) added

  /// Reads the GOT entry at the given address, of either kind: a global entry
  /// holds the address of its function, or that of the stub through which the
  /// loader binds an import, until the program runs.
  let private tryReadGOTEntry (hdl: BinHandle) (got: BinSection) addr =
    if got.Address <= addr && addr < got.Address + got.Size then
      let width = WordSize.toByteWidth hdl.File.ISA.WordSize
      match hdl.TryReadUInt(addr, width) with
      | Ok v -> Some v
      | Error _ -> None
    else
      None

  /// Finds the function that the call ending the given instructions reaches,
  /// if it calls through t9 what the code loads from the GOT: the address that
  /// a global entry holds, or the page that a local entry holds plus what the
  /// code adds to it. The code reads the GOT through gp, which a binary with
  /// one GOT sets to the same value wherever its code runs.
  let tryFindGOTCallee (hdl: BinHandle) (instrs: IInstruction[]) =
    let instrs = instrs |> Array.map (fun ins -> ins :?> Instruction)
    let last = instrs.Length - 1
    match tryFindGOT hdl with
    | Some got when last >= 0 && callsThroughT9 instrs[last] ->
      let mask = maskOf hdl.File.ISA.WordSize
      tryFindT9Load instrs (last - 1) 0UL
      |> Option.bind (fun (offset, added) ->
        tryReadGOTEntry hdl got ((gpOf got + offset) &&& mask)
        |> Option.map (fun entry -> (entry + added) &&& mask))
      |> Option.filter (fun target ->
        target <> 0UL && hdl.File.IsExecutableAddr target)
    | _ ->
      None

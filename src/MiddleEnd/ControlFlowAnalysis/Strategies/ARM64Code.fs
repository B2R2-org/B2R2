(*
  B2R2 - the Next-Generation Reversing Platform

  Copyright (c) SoftSec Lab. @ KAIST, since 2016

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*)

namespace B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.ARM64

/// Provides where AArch64 code addresses data on its own. ADRP sets a register
/// to the page of the data, and an ADD of an immediate to the register, or a
/// load or a store at an immediate offset from it, completes the address,
/// while ADR names an address by itself.
module internal ARM64Code =
  /// Returns the destination and the label of the given ADR or ADRP.
  let private tryGetLabel (ins: Instruction) =
    match ins.Operands with
    | TwoOperands(OprRegister d, OprMemory(LiteralMode(ImmOffset(Lbl l)))) ->
      Some(d, uint64 l)
    | _ ->
      None

  /// Returns the number that the X and the W register of the given register
  /// share, if it is a general-purpose register.
  let private tryGetNumber (r: Register) =
    let n = int r
    if n < 0x40 && (n &&& 0x1f) < 31 then Some(n &&& 0x1f) else None

  /// Sets the given register to the page that the ADRP at the given address
  /// computes.
  let private setPage (pages: (Addr * Addr) option[]) r page adrpAddr =
    match tryGetNumber r with
    | Some n -> pages[n] <- Some(page, adrpAddr)
    | None -> ()

  /// Forgets the page of the given register.
  let private forget (pages: (Addr * Addr) option[]) r =
    match tryGetNumber r with
    | Some n -> pages[n] <- None
    | None -> ()

  /// The most bytes past an ADRP at which an instruction may complete its
  /// address, as a compiler keeps the two close.
  let [<Literal>] private Reach = 64UL

  /// Returns the page that ADRP has set the given register to, if the ADRP
  /// lies close enough before the instruction at the given address.
  let private tryGetPage (pages: (Addr * Addr) option[]) r (addr: Addr) =
    match tryGetNumber r with
    | Some n ->
      match pages[n] with
      | Some(page, adrpAddr) when addr - adrpAddr <= Reach -> Some page
      | _ -> None
    | None ->
      None

  /// Returns the addressing mode of the given load or store.
  let private tryGetAddressingMode (ins: Instruction) =
    match ins.Operands with
    | TwoOperands(_, OprMemory mode)
    | ThreeOperands(_, _, OprMemory mode) -> Some mode
    | _ -> None

  /// Returns the address that the given instruction completes from the page
  /// that ADRP has set its base register to: the page plus what an ADD adds to
  /// it, or plus the offset at which a load or a store accesses.
  let private tryComplete pages (ins: Instruction) =
    match ins.Opcode, ins.Operands with
    | Opcode.ADD,
      FourOperands(_, OprRegister b, OprImm imm, OprShift(_, Imm amount)) ->
      tryGetPage pages b ins.Address
      |> Option.map (fun page -> page + (uint64 imm <<< int amount))
    | _ ->
      match tryGetAddressingMode ins with
      | Some(BaseMode(ImmOffset(BaseOffset(b, offset)))) ->
        tryGetPage pages b ins.Address
        |> Option.map (fun page -> page + uint64 (defaultArg offset 0L))
      | _ ->
        None

  /// Checks if the given opcode stores the register that its first operand
  /// names, rather than writes it.
  let private isStore = function
    | Opcode.STR | Opcode.STRB | Opcode.STRH | Opcode.STUR | Opcode.STURB
    | Opcode.STURH | Opcode.STP | Opcode.STNP -> true
    | _ -> false

  /// Checks if the given opcode loads a pair, writing the registers that its
  /// first two operands name.
  let private isPairLoad = function
    | Opcode.LDP | Opcode.LDPSW | Opcode.LDNP | Opcode.LDXP
    | Opcode.LDAXP -> true
    | _ -> false

  /// Returns the operands of the given instruction in order.
  let private operandsOf (ins: Instruction) =
    match ins.Operands with
    | NoOperand -> []
    | OneOperand o1 -> [ o1 ]
    | TwoOperands(o1, o2) -> [ o1; o2 ]
    | ThreeOperands(o1, o2, o3) -> [ o1; o2; o3 ]
    | FourOperands(o1, o2, o3, o4) -> [ o1; o2; o3; o4 ]
    | FiveOperands(o1, o2, o3, o4, o5) -> [ o1; o2; o3; o4; o5 ]

  /// Returns the registers that the given instruction writes as it names them
  /// first: one, or two for a load of a pair.
  let private destinationsOf (ins: Instruction) =
    let count = if isPairLoad ins.Opcode then 2 else 1
    operandsOf ins
    |> List.truncate count
    |> List.choose (fun opr ->
      match opr with
      | OprRegister r -> Some r
      | _ -> None)

  /// Returns the registers that the given instruction may write, which then
  /// hold no page: what it names first, unless it stores that, and a base that
  /// it writes back.
  let private writtenBy (ins: Instruction) =
    let written = if isStore ins.Opcode then [] else destinationsOf ins
    match tryGetAddressingMode ins with
    | Some(PreIdxMode(ImmOffset(BaseOffset(b, _))))
    | Some(PostIdxMode(ImmOffset(BaseOffset(b, _)))) -> b :: written
    | _ -> written

  /// Checks if the given instruction leaves the code that follows it to run
  /// with values from elsewhere: a jump, a return, or one that stops.
  let private leaves (ins: IInstruction) =
    (ins.IsBranch && not ins.IsCondBranch && not ins.IsCall) || ins.IsExit

  /// Forgets the pages of the registers that the given instruction writes. A
  /// call also clobbers what AAPCS64 lets a callee change, X0 to X18 and X30,
  /// and an instruction that leaves forgets every page.
  let private forgetWritten pages (ins: Instruction) =
    writtenBy ins |> List.iter (forget pages)
    if (ins :> IInstruction).IsCall then
      Array.fill pages 0 19 None
      pages[30] <- None
    elif leaves ins then
      Array.fill pages 0 pages.Length None
    else
      ()

  /// Collects into refs the address of data that the given instruction
  /// computes, and updates the pages that the registers hold past it.
  let private step pages (refs: HashSet<Addr>) (ins: Instruction) =
    match ins.Opcode, tryGetLabel ins with
    | Opcode.ADRP, Some(d, label) ->
      setPage pages d ((ins.Address &&& ~~~0xfffUL) + label) ins.Address
    | Opcode.ADR, Some(d, label) ->
      refs.Add(ins.Address + label) |> ignore
      forget pages d
    | _ ->
      tryComplete pages ins |> Option.iter (refs.Add >> ignore)
      forgetWritten pages ins

  /// Collects into refs the addresses of data that the code of the given
  /// section computes, reading the section as one run of instructions. A word
  /// that is no instruction is data amid the code, past which no register
  /// holds a page.
  let private scan (lu: LiftingUnit) refs (sec: BinSection) =
    let pages = Array.create 32 None
    let rec loop (addr: Addr) =
      if addr + 4UL <= sec.Address + sec.Size then
        match lu.TryParseInstruction addr with
        | Ok ins -> step pages refs (ins :?> Instruction)
        | Error _ -> Array.fill pages 0 pages.Length None
        loop (addr + 4UL)
      else
        ()
    loop sec.Address

  /// Collects, in ascending order, the addresses of data that the code of the
  /// given binary computes on its own, each where a piece of data starts or a
  /// place within one.
  let collectDataReferences (hdl: BinHandle) =
    let refs = HashSet<Addr>()
    let lu = hdl.NewLiftingUnit()
    BinFileOps.getSections hdl.File
    |> Seq.filter (fun sec -> sec.Kind = CodeSection)
    |> Seq.iter (scan lu refs)
    let addrs = Seq.toArray refs
    Array.sortInPlace addrs
    addrs

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

module internal B2R2.Assembly.ARM32.AsmMain

open B2R2
open B2R2.FrontEnd.ARM32
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.ARM32.ParserHelper
open B2R2.Assembly.ARM32.AsmField
open B2R2.Assembly.ARM32.AsmOpcode
open B2R2.Assembly.ARM32.AsmThumb

type UserState =
  { /// Label string to the index of the instruction it marks. The index starts
    /// from zero, and a label does not take one of its own.
    LabelMap: Map<string, int>
    /// Index of the instruction being parsed, which a label does not change.
    CurIndex: int }

/// Builds the lookup from an opcode to the encoder for it. Each assembler
/// builds its own and lets it go when it goes, rather than the rows living for
/// as long as the process does.
let buildEncoderTable () =
  [ dataProcessingEncoders ()
    multiplyEncoders ()
    miscellaneousEncoders ()
    hintEncoders ()
    loadStoreEncoders ()
    blockTransferEncoders ()
    mediaEncoders ()
    coprocessorEncoders ()
    floatingPointEncoders ()
    advancedSIMDEncoders () ]
  |> List.concat
  |> Map.ofList

/// Builds the lookup for the Thumb encoders, which are a different set: T32
/// says the same things as A32 but says almost none of them the same way.
let buildThumbEncoderTable () =
  let narrow = thumbNarrowEncoders () |> Map.ofList
  let wide =
    [ thumbSharedEncoders (); thumbWideEncoders () ]
    |> List.concat
    |> Map.ofList
  let paired =
    narrow
    |> Map.map (fun opcode encode ->
      match Map.tryFind opcode wide with
      | Some wideEncode -> preferNarrow encode wideEncode
      | None -> encode)
  wide
  |> Map.fold (fun acc opcode encode ->
    if Map.containsKey opcode acc then acc else Map.add opcode encode acc)
    paired

/// Where each instruction sits, given how long each one before it turned out to
/// be. An A32 instruction is always four bytes; a Thumb one is not.
let private addressesOf (baseAddr: Addr) lengths =
  lengths
  |> List.scan (fun addr length -> addr + uint64 (length: int)) baseAddr
  |> List.toArray

/// Resolves a label to the address of the instruction it marks. A label that
/// was never defined is a mistake in the source, not a lookup that failed.
let private findLabel state (addresses: Addr[]) lbl =
  match Map.tryFind lbl state.LabelMap with
  | Some index when index < addresses.Length -> addresses[index]
  | Some _ | None ->
    raise <| EncodingFailureException $"Undefined label '{lbl}'"

/// <summary>
/// Where the program counter reads while an instruction executes, which is
/// what a PC-relative offset is measured from. In A32 that is eight bytes
/// ahead of the instruction, aligned down to a word for the instructions that
/// read a literal.
///
/// This mirrors how the disassembler resolves a literal, because an offset
/// measured from anywhere else would encode a different target than the one
/// the text names. The instructions it leaves out are the ones the
/// disassembler resolves against the instruction's own address instead.
/// </summary>
let private programCounter isThumb opcode (addr: Addr) =
  let ahead = if isThumb then 4UL else 8UL
  match opcode with
  | Opcode.B | Opcode.BX | Opcode.CBZ | Opcode.CBNZ -> addr + ahead
  | Opcode.BL | Opcode.BLX | Opcode.ADR
  | Opcode.LDR | Opcode.LDRB | Opcode.LDRD | Opcode.LDRH | Opcode.LDRSB
  | Opcode.LDRSH | Opcode.PLD | Opcode.PLDW | Opcode.PLI | Opcode.VLDR ->
    let pc = addr + ahead
    pc - (pc % 4UL)
  | _ -> addr

/// The distance from an instruction's program counter to the address given,
/// which is what the encoding of a PC-relative operand holds. The subtraction
/// wraps at thirty-two bits, so a target below the program counter comes out
/// as the negative offset that reaches it.
let private offsetTo (pc: Addr) (target: Addr) =
  int64 (int32 (uint32 target - uint32 pc))

/// <summary>
/// Rewrites the operands that name a place rather than a value: a label, and
/// an absolute address written the way the disassembler prints a resolved one.
/// Both become the offset from this instruction's program counter, which is
/// what the encoders read.
/// </summary>
let private resolvePlaces isThumb state addresses index ins =
  let pc = programCounter isThumb ins.Opcode (Array.item index addresses)
  let resolve = function
    | GoToLabel lbl ->
      let target = findLabel state addresses lbl
      OprMemory(LiteralMode(offsetTo pc target))
    | OprMemory(LiteralMode target) ->
      OprMemory(LiteralMode(offsetTo pc (uint64 target)))
    | operand -> operand
  let operands = getOperandsAsList ins.Operands |> List.map resolve
  { ins with Operands = extractOperands operands }

let encodeInstruction encoders ins =
  match Map.tryFind ins.Opcode encoders with
  | Some encode -> encode ins
  | None ->
    raise <| EncodingFailureException $"{ins.Opcode} is not supported yet"

/// <summary>
/// The conditions an IT instruction supplies to the instructions after it.
///
/// Its own condition is the first; each letter of its mnemonic after the "IT"
/// says whether the instruction it stands for runs under that condition or
/// under the opposite one.
/// </summary>
let private blockConditions (ins: AsmInsInfo) =
  let first =
    match ins.Operands, ins.Condition with
    | OneOperand(OprCond cond), _ -> cond
    | _, Some cond -> cond
    | _ -> Condition.AL
  let letters = (ins.Opcode.ToString()).Substring 2
  first
  :: [ for letter in letters ->
         if letter = 'T' then first else oppositeCondition first ]

/// <summary>
/// The form of an instruction that says it sets the flags, which is what a
/// plain mnemonic means inside a block.
///
/// A narrow encoding has no bit to say whether it sets them: the ones that do
/// are written with an S outside a block and without one inside, so a mnemonic
/// written without one here may still mean the encoding that does.
///
/// A move of a register is the exception. It keeps a form of its own that never
/// sets the flags, and the form that does may not appear inside a block at all.
/// </summary>
let private flagSettingForm (ins: AsmInsInfo) =
  match ins.Opcode, ins.Operands with
  | Opcode.MOV, TwoOperands(_, OprReg _) -> None
  | Opcode.MOV, _ -> Some Opcode.MOVS
  | Opcode.ADD, _ -> Some Opcode.ADDS
  | Opcode.SUB, _ -> Some Opcode.SUBS
  | Opcode.AND, _ -> Some Opcode.ANDS
  | Opcode.EOR, _ -> Some Opcode.EORS
  | Opcode.ADC, _ -> Some Opcode.ADCS
  | Opcode.SBC, _ -> Some Opcode.SBCS
  | Opcode.RSB, _ -> Some Opcode.RSBS
  | Opcode.ORR, _ -> Some Opcode.ORRS
  | Opcode.BIC, _ -> Some Opcode.BICS
  | Opcode.MVN, _ -> Some Opcode.MVNS
  | Opcode.MUL, _ -> Some Opcode.MULS
  | Opcode.LSL, _ -> Some Opcode.LSLS
  | Opcode.LSR, _ -> Some Opcode.LSRS
  | Opcode.ASR, _ -> Some Opcode.ASRS
  | Opcode.ROR, _ -> Some Opcode.RORS
  | _ -> None

/// <summary>
/// Rewrites an instruction inside a block to the form that sets the flags, when
/// that form is one a halfword can hold.
///
/// When it is not, what the source wrote stands: a wide encoding says for
/// itself whether it sets the flags, so a mnemonic written without an S means
/// the one that does not.
/// </summary>
let private asFlagSetting encoders ins =
  match flagSettingForm ins with
  | Some setting ->
    let candidate = { ins with Opcode = setting }
    let fitsAHalfword =
      match Map.tryFind setting encoders with
      | Some encode ->
        (try encodedLength (encode candidate) = 2 with _ -> false)
      | None -> false
    if fitsAHalfword then candidate else ins
  | None -> ins

/// Whether an instruction may sit inside an IT block. The ones that cannot are
/// the ones that decide for themselves whether to branch, which is what the
/// block is already deciding.
let private fitsInBlock opcode =
  match opcode with
  | Opcode.CBZ | Opcode.CBNZ | Opcode.BL | Opcode.BLX -> false
  | opcode -> not (isITInstruction opcode)

/// <summary>
/// Checks every instruction against the IT block it sits in, and takes the
/// condition off the ones that sit in one.
///
/// A Thumb instruction has nowhere of its own to keep a condition: the block
/// before it says what that is, and the source repeats it on each instruction
/// only so that the two can be seen to agree. Once they do there is nothing
/// left to encode, and outside a block there is nowhere for one to go at all.
/// </summary>
let private resolveConditions encoders instrs =
  let rec walk pending encoded instrs =
    match instrs, pending with
    | [], _ -> List.rev encoded
    | (ins: AsmInsInfo) :: rest, expected :: remaining ->
      if not ins.IsThumb then
        raise <| EncodingFailureException
                   "an IT block cannot reach into ARM code"
      elif not (fitsInBlock ins.Opcode) then
        raise <| EncodingFailureException
                   $"{ins.Opcode} cannot sit inside an IT block"
      elif ins.Condition <> Some expected then
        let written =
          match ins.Condition with
          | Some cond -> $"{cond}"
          | None -> "no condition"
        raise <| EncodingFailureException
                   $"the block runs this under {expected}, not {written}"
      else
        let ins = asFlagSetting encoders { ins with Condition = None }
        walk remaining (ins :: encoded) rest
    | ins :: rest, [] ->
      (* Outside a block only a branch has a condition field of its own, and
         only in Thumb: every A32 instruction has one. *)
      if ins.IsThumb && Option.isSome ins.Condition
         && ins.Opcode <> Opcode.B then
        raise <| EncodingFailureException
                   $"{ins.Opcode} takes no condition outside an IT block"
      else
        let opened =
          if ins.IsThumb && isITInstruction ins.Opcode then blockConditions ins
          else []
        walk opened (ins :: encoded) rest
  walk [] [] instrs

let private encodeThumb encoders ins =
  match Map.tryFind ins.Opcode encoders with
  | Some encode -> encode ins
  | None ->
    raise <| EncodingFailureException $"{ins.Opcode} is not supported yet"

/// <summary>
/// Encodes one instruction with the table its instruction set is written in.
///
/// Only the tables a source actually asks for are ever built, which is why they
/// arrive here unforced.
/// </summary>
let private encodeOne (arm: Lazy<_>) (thumb: Lazy<_>) ins =
  if ins.IsThumb then encodeThumb thumb.Value ins
  else Word(encodeInstruction arm.Value ins)

/// The bytes of an encoded instruction, in the order the given endianness
/// stores them. A word keeps its bytes as one number; two halfwords keep theirs
/// as two.
let private toBytes endian encoded =
  let halfword (value: uint16) =
    let bytes = System.BitConverter.GetBytes value
    if endian = Endian.Big then Array.rev bytes else bytes
  match encoded with
  | Narrow value -> halfword value
  | Wide(first, second) -> Array.append (halfword first) (halfword second)
  | Word value ->
    let bytes = System.BitConverter.GetBytes value
    if endian = Endian.Big then Array.rev bytes else bytes

/// <summary>
/// Assembles a source whose lines may belong to either instruction set, which
/// the directives in it switch between.
///
/// Which length an instruction takes follows from how it is written rather than
/// from how far away anything is, so encoding every instruction once with the
/// distances left where they fall settles all the lengths, and encoding them
/// again with the addresses those lengths give settles the distances.
/// </summary>
let assemble arm thumb state endian baseAddr instrs =
  let instrs = resolveConditions (thumb: Lazy<_>).Value instrs
  let encodeAt addresses index ins =
    let ins = resolvePlaces ins.IsThumb state addresses index ins
    if not ins.IsThumb && Array.item index addresses % 4UL <> 0UL then
      raise <| EncodingFailureException
                 $"{ins.Opcode} is an ARM instruction and needs a word boundary"
    else
      encodeOne arm thumb ins
  let provisional = addressesOf baseAddr (instrs |> List.map (fun _ -> 4))
  let lengths =
    instrs
    |> List.mapi (fun index ins -> encodeAt provisional index ins)
    |> List.map encodedLength
  let addresses = addressesOf baseAddr lengths
  instrs
  |> List.mapi (fun index ins -> ins.IsThumb, encodeAt addresses index ins)
  |> List.map (fun (isThumb, encoded) -> isThumb, toBytes endian encoded)

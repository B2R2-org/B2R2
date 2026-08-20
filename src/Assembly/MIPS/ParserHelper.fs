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

module internal B2R2.Assembly.MIPS.ParserHelper

open System
open B2R2
open B2R2.FrontEnd.MIPS
open B2R2.Assembly.BinLowerer

/// <summary>
/// Represents one instruction as the source wrote it.
///
/// A MIPS mnemonic hangs at most two suffixes off a name: the condition a
/// floating-point compare tests, and the format the operands are read in.
/// Both are optional because most instructions write neither, and the format
/// is what tells the instructions sharing a name between the general registers
/// and the floating-point ones apart.
/// </summary>
type AsmInsInfo =
  { Opcode: Opcode
    Condition: Condition option
    Fmt: FPRFormat option
    Operands: Operands }

/// AssemblyLine is either a label definition or an instruction.
type AssemblyLine =
  | LabelDefLine
  | InstructionLine of AsmInsInfo

let checkIfInstructionLine = function
  | InstructionLine ins -> Some ins
  | LabelDefLine -> None

let filterInstructionLines lst = List.choose checkIfInstructionLine lst

let extractOperands = function
  | [] -> NoOperand
  | [ o1 ] -> OneOperand o1
  | [ o1; o2 ] -> TwoOperands(o1, o2)
  | [ o1; o2; o3 ] -> ThreeOperands(o1, o2, o3)
  | [ o1; o2; o3; o4 ] -> FourOperands(o1, o2, o3, o4)
  | _ -> raise <| EncodingFailureException "Too many operands"

let getOperandsAsList = function
  | NoOperand -> []
  | OneOperand o1 -> [ o1 ]
  | TwoOperands(o1, o2) -> [ o1; o2 ]
  | ThreeOperands(o1, o2, o3) -> [ o1; o2; o3 ]
  | FourOperands(o1, o2, o3, o4) -> [ o1; o2; o3; o4 ]

/// Every register the enumeration holds, which is what the two vocabularies
/// below are read off.
let private allRegisters =
  Enum.GetValues typeof<Register> |> Seq.cast<Register> |> Seq.toList

/// <summary>
/// Every register name the disassembler prints at the given word size, and the
/// numbered name of each register besides.
///
/// The two vocabularies differ: eight of the general registers are written by
/// one name where a source is thirty-two bits wide and by another where it is
/// sixty-four. The names come from Register.toString rather than from a list
/// written out here, so that what the assembler accepts cannot drift from what
/// the disassembler emits.
/// </summary>
let private namesAt wordSize =
  let numbered =
    allRegisters
    |> List.choose (fun reg ->
      let number = int reg
      let index = number - int Register.F0
      if number <= int Register.R31 then Some($"r{number}", reg)
      elif number <= int Register.F31 then Some($"f{index}", reg)
      else None)
  allRegisters
  |> List.map (fun reg -> Register.toString reg wordSize, reg)
  |> List.append numbered
  |> List.distinctBy fst
  |> Map.ofList

/// The register names a thirty-two bit source writes.
let registers32 = namesAt WordSize.Bit32

/// The register names a sixty-four bit source writes.
let registers64 = namesAt WordSize.Bit64

/// <summary>
/// Which of the two vocabularies an instruction writes its registers in.
///
/// The disassembler names them by how wide what the instruction works on is
/// rather than by how wide the source is, and the four stores that say their
/// own width are therefore written in the vocabulary that width belongs to.
/// </summary>
let registerNaming opcode wordSize =
  match opcode with
  | Opcode.SB | Opcode.SH | Opcode.SW -> WordSize.Bit32
  | Opcode.SD -> WordSize.Bit64
  | _ -> wordSize

/// The names the disassembler spells otherwise than as the lowercased name of
/// the opcode, because the name itself holds a dot: the conversions, the two
/// truncations, and the jumps that clear the instruction hazards.
let private irregularNames =
  [ Opcode.CVTD, "cvt.d"
    Opcode.CVTS, "cvt.s"
    Opcode.CVTW, "cvt.w"
    Opcode.TRUNCL, "trunc.l"
    Opcode.TRUNCW, "trunc.w"
    Opcode.JALRHB, "jalr.hb"
    Opcode.JRHB, "jr.hb" ]
  |> Map.ofList

/// Every mnemonic, paired with the opcode it names. Each opcode has exactly
/// one name here, which is the one the disassembler writes it under.
let opcodes =
  Enum.GetValues typeof<Opcode>
  |> Seq.cast<Opcode>
  |> Seq.filter (fun opcode -> opcode <> Opcode.InvalOP)
  |> Seq.map (fun opcode ->
    match Map.tryFind opcode irregularNames with
    | Some name -> name, opcode
    | None -> (string opcode).ToLowerInvariant(), opcode)
  |> Seq.distinctBy fst
  |> Map.ofSeq

/// Every name of a member of the given enumeration, lowercased, which is how
/// the disassembler writes the condition and the format suffixes alike.
let private suffixNames<'T when 'T: comparison> () =
  Enum.GetValues typeof<'T>
  |> Seq.cast<'T>
  |> Seq.map (fun value -> (string value).ToLowerInvariant(), value)
  |> Seq.distinctBy fst
  |> Map.ofSeq

/// Every condition a floating-point compare tests.
let conditions = suffixNames<Condition> ()

/// Every format the operands of a floating-point instruction are read in.
let formats = suffixNames<FPRFormat> ()

/// The condition and the format a mnemonic hangs off its name, which is at
/// most one of each and in that order.
let private trySuffixes (parts: string[]) =
  match parts with
  | [||] ->
    Some(None, None)
  | [| fmt |] ->
    Map.tryFind fmt formats |> Option.map (fun fmt -> None, Some fmt)
  | [| cond; fmt |] ->
    match Map.tryFind cond conditions, Map.tryFind fmt formats with
    | Some cond, Some fmt -> Some(Some cond, Some fmt)
    | _ -> None
  | _ ->
    None

/// <summary>
/// The opcode, the condition and the format a written mnemonic names.
///
/// A name may hold a dot of its own, so the longest prefix that names an
/// opcode is tried first and what follows it is read as the suffixes; where
/// that leaves something no suffix accounts for, a shorter prefix is tried.
/// </summary>
let decomposeMnemonic (mnemonic: string) =
  let parts = mnemonic.ToLowerInvariant().Split '.'
  let rec tryPrefix length =
    if length = 0 then
      None
    else
      let name = String.Join('.', parts[..length - 1])
      match Map.tryFind name opcodes |> Option.map (fun opcode ->
              opcode, trySuffixes parts[length..]) with
      | Some(opcode, Some(cond, fmt)) -> Some(opcode, cond, fmt)
      | Some(_, None) | None -> tryPrefix (length - 1)
  tryPrefix parts.Length

/// <summary>
/// Whether the instruction names a place, which is the operand the
/// disassembler prints as the address it resolved rather than as the value the
/// encoding holds.
///
/// The two jumps name one too, but they hold a word of the region they sit in
/// rather than a distance, and the disassembler prints that word as it stands;
/// so a source writes them as a value and they are not places here.
/// </summary>
let takesPlace = function
  | Opcode.B | Opcode.BAL | Opcode.BEQ | Opcode.BEQL | Opcode.BNE
  | Opcode.BNEL | Opcode.BGEZ | Opcode.BGEZAL | Opcode.BGTZ | Opcode.BLEZ
  | Opcode.BLTZ | Opcode.BLTZAL | Opcode.BC1F | Opcode.BC1T -> true
  | _ -> false

/// Whether the instruction names a word of the region it sits in, which is how
/// the two jumps reach a place.
let namesRegion = function
  | Opcode.J | Opcode.JAL -> true
  | _ -> false

/// How wide the access an instruction naming memory makes is. Nothing in what
/// the source writes says, because the width belongs to the instruction rather
/// than to the operand.
let accessLength opcode wordSize =
  match opcode with
  | Opcode.LB | Opcode.LBU | Opcode.SB -> 8<rt>
  | Opcode.LH | Opcode.LHU | Opcode.SH -> 16<rt>
  | Opcode.LD | Opcode.LDL | Opcode.LDR | Opcode.LLD | Opcode.SCD
  | Opcode.SD | Opcode.SDL | Opcode.SDR | Opcode.LDXC1 | Opcode.SDXC1 -> 64<rt>
  | Opcode.LDC1 | Opcode.SDC1 -> WordSize.toRegType wordSize
  | _ -> 32<rt>

/// <summary>
/// Turns the address a place operand was written as into the distance to it.
///
/// The disassembler prints where a branch goes rather than how far it is, so
/// what a source writes there is an address; what the encoding holds is the
/// distance from the instruction, and only the last operand of a branch is
/// ever the place.
/// </summary>
let markPlace opcode (pc: Addr) operands =
  if takesPlace opcode then
    match List.rev operands with
    | OpImm target :: rest ->
      OpAddr(Relative(int64 (target - pc))) :: rest |> List.rev
    | _ ->
      operands
  else
    operands

/// Builds one instruction as written.
let newInfo opcode cond fmt operands =
  { Opcode = opcode; Condition = cond; Fmt = fmt; Operands = operands }

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

module internal B2R2.Assembly.MIPS.AsmMain

open B2R2
open B2R2.FrontEnd.MIPS
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.MIPS.ParserHelper
open B2R2.Assembly.MIPS.AsmField
open B2R2.Assembly.MIPS.AsmOpcode
open B2R2.Assembly.MIPS.AsmFloat

type UserState =
  { /// Label string to the index of the instruction it marks. The index starts
    /// from zero, and a label does not take one of its own.
    LabelMap: Map<string, int>
    /// Index of the instruction being parsed, which a label does not change.
    CurIndex: int
    /// Address of the instruction being parsed. The older encoding could
    /// multiply the index by four to get it; microMIPS cannot, an
    /// instruction there being two bytes or four.
    CurAddr: Addr }

/// <summary>
/// Adds a table of encoders to another, keeping what was already there for the
/// instructions the new rows do not claim.
///
/// A dozen names belong both to the general registers and to the
/// floating-point ones, and what tells the two apart is the format written
/// into the mnemonic, so where a name is in both the two encoders are put
/// behind one that reads that.
/// </summary>
let private addEncoders claims table rows =
  rows
  |> List.fold (fun table (opcode, encode) ->
    match Map.tryFind opcode table with
    | Some other ->
      let choose ins = if claims ins then encode ins else other ins
      Map.add opcode choose table
    | None ->
      Map.add opcode encode table) table

/// Builds the lookup from an opcode to the encoder for it. Each assembler
/// builds its own and lets it go when it goes, rather than the rows living for
/// as long as the process does.
/// <param name="release">
/// Which release the source is written for. Release 6 is a different
/// encoding space, not an extension: MUL, DIV and the rest of that family
/// are written the same way there and encoded differently, so the release
/// is what tells the two apart -- nothing in the source text does.
/// </param>
let buildEncoderTable (release: MIPSRelease) =
  let general =
    [ arithmeticEncoders ()
      branchEncoders ()
      loadStoreEncoders ()
      privilegedEncoders () ]
    |> List.concat
    |> Map.ofList
  let general =
    if release = MIPSRelease.R6 then
      addEncoders (fun _ -> true) general
        (release6Encoders () @ privilegedR6Encoders ())
    else
      general
  let withFloat =
    addEncoders (fun ins -> Option.isSome ins.Fmt) general
      (floatEncoders ())
  if release = MIPSRelease.R6 then
    (* SELEQZ and SELNEZ name both an integer instruction and a float one,
       and only the format written into the mnemonic tells them apart, so
       the float rows claim exactly the formatted ones. *)
    addEncoders (fun ins -> Option.isSome ins.Fmt) withFloat
      (release6FloatEncoders ())
  else
    withFloat

/// Resolves a label to the address of the instruction it marks. A label that
/// was never defined is a mistake in the source, not a lookup that failed.
let private findLabel state (addresses: Addr[]) lbl count =
  match Map.tryFind lbl state.LabelMap with
  | Some index when index <= count ->
    addresses[index]
  | Some _ | None ->
    raise <| EncodingFailureException $"Undefined label '{lbl}'"

/// <summary>
/// Rewrites the operand that names a label into what the encoding holds in its
/// place.
///
/// What the source writes is where to go; a branch holds how far that is from
/// here and a jump holds which word of the region it sits in the place is, so
/// the two are one operand read at different times.
/// </summary>
let private resolveLabels state (addresses: Addr[]) count index ins =
  let pc = addresses[index]
  let resolve = function
    | GoToLabel lbl ->
      let target = findLabel state addresses lbl count
      if namesRegion ins.Opcode then OpImm(region pc target)
      else OpAddr(Relative(int64 (target - pc)))
    | operand ->
      operand
  let operands = getOperandsAsList ins.Operands |> List.map resolve
  { ins with Operands = extractOperands operands }

let private encodeInstruction (encoders: Map<_, _>) ins =
  match Map.tryFind ins.Opcode encoders with
  | Some encode ->
    encode ins
  | None ->
    raise <| EncodingFailureException $"{ins.Opcode} is not supported yet"

/// <summary>
/// The bytes of an encoded instruction of the older encoding, in the order
/// the given endianness stores them. The length is what the caller worked
/// out and is always four here, so it goes unread.
/// </summary>
let toBytes endian (_length: int) (word: uint32) =
  let bytes = System.BitConverter.GetBytes word
  if endian = Endian.Big then Array.rev bytes else bytes

/// <summary>
/// Where each instruction of a source sits, and where the end of it is.
///
/// The array holds one address per instruction plus one for the place after
/// the last, which is the address a label written below everything marks. An
/// instruction is four bytes in the older encoding and two or four in
/// microMIPS, so this is a running total rather than a multiplication.
/// </summary>
let private addressesOf sizeOf (baseAddr: Addr) instrs =
  let mutable next = baseAddr
  [| for ins in instrs do
       yield next
       next <- next + uint64 (sizeOf ins)
     yield next |]

/// <summary>
/// Assembles a whole source.
///
/// How long an instruction is follows from what it is rather than from what
/// its operands turned out to be, so where everything sits is known before
/// anything is encoded and a label can be resolved in one pass.
/// </summary>
let assemble (encoders: Lazy<_>) state endian baseAddr sizeOf toBytes instrs =
  let count = List.length instrs
  let addresses = addressesOf sizeOf baseAddr instrs
  instrs
  |> List.mapi (fun index ins ->
    resolveLabels state addresses count index ins
    |> encodeInstruction encoders.Value
    |> toBytes endian (sizeOf ins))

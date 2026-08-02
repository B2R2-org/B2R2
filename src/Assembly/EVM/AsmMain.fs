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

module internal B2R2.Assembly.EVM.AsmMain

open B2R2
open B2R2.Assembly.BinLowerer
open B2R2.Assembly.EVM.ParserHelper
open B2R2.Assembly.EVM.AsmOpcode

type UserState =
  { /// Label string to the index of the instruction it marks. The index starts
    /// from zero, and a label does not take one of its own.
    LabelMap: Map<string, int>
    /// Index of the instruction being parsed, which a label does not change.
    CurIndex: int }

/// Builds the lookup from a mnemonic to the encoder for it. Each assembler
/// builds its own and lets it go when it goes, rather than the rows living for
/// as long as the process does.
let buildEncoderTable () =
  [ arithmeticEncoders ()
    comparisonEncoders ()
    environmentEncoders ()
    blockEncoders ()
    stateEncoders ()
    pushEncoders ()
    stackEncoders ()
    logEncoders ()
    systemEncoders () ]
  |> List.concat
  |> Map.ofList

/// How many bytes each push takes, which is the byte naming it together with
/// the number it holds. Nothing else this architecture has is wider than the
/// byte naming it, and the push that pushes zero holds nothing.
let private pushSizes =
  [ for n in 1 .. 32 -> $"push{n}", uint64 n + 1UL ] |> Map.ofList

/// How many bytes an instruction takes, which its name alone answers.
let private sizeOf ins =
  match Map.tryFind ins.Mnemonic pushSizes with
  | Some size -> size
  | None -> 1UL

/// Where each instruction of a source sits, and after the last of them the
/// place just past it, which is where a label written below everything marks.
let private addresses baseAddr instrs =
  instrs
  |> List.scan (fun addr ins -> addr + sizeOf ins) baseAddr
  |> List.toArray

/// Resolves a label to the address of the instruction it marks. A label that
/// was never defined is a mistake in the source, not a lookup that failed.
let private findLabel state (addrs: Addr[]) lbl =
  match Map.tryFind lbl state.LabelMap with
  | Some index when index < addrs.Length ->
    addrs[index]
  | Some _ | None ->
    raise <| EncodingFailureException $"Undefined label '{lbl}'"

/// <summary>
/// Rewrites the operand naming a label into where that label is.
///
/// A push holds where it goes outright rather than how far away that is, so
/// where the push itself sits does not come into it: the address the label
/// marks is the whole of what the push holds. What a jump goes by is a number
/// the stack holds, and pushing it is what a source names a place for.
/// </summary>
let private resolveLabels state addrs ins =
  let resolve = function
    | AsmLabel lbl -> AsmTarget(findLabel state addrs lbl)
    | operand -> operand
  { ins with Operands = List.map resolve ins.Operands }

/// <summary>
/// The bytes of one instruction.
///
/// How wide the instruction came out is checked against how wide its name said
/// it would be, because the addresses the lines below it were worked out from
/// the latter, and a label would land elsewhere were the two to disagree.
/// </summary>
let private encodeInstruction (encoders: Map<_, _>) ins =
  match Map.tryFind ins.Mnemonic encoders with
  | Some encode ->
    let bytes = List.toArray (encode ins)
    if uint64 bytes.Length = sizeOf ins then
      bytes
    else
      raise
      <| EncodingFailureException $"{ins.Mnemonic} came out the wrong width"
  | None ->
    raise <| EncodingFailureException $"{ins.Mnemonic} is not supported yet"

/// <summary>
/// Assembles a whole source.
///
/// Where each label sits can be worked out before anything is encoded, because
/// how wide an EVM instruction is depends on nothing but which instruction it
/// is: a push says in its own name how many bytes it holds, and everything else
/// is the single byte naming it.
/// </summary>
let assemble (encoders: Lazy<_>) state baseAddr instrs =
  let addrs = addresses baseAddr instrs
  let encode = encodeInstruction encoders.Value
  instrs |> List.map (resolveLabels state addrs >> encode)

// vim: set tw=80 sts=2 sw=2:

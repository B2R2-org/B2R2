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

/// <summary>
/// Encodes the instructions of Variable Length Encoding (VLE), the second
/// encoding of the Power ISA. Its instructions are named e_ where they fill
/// two halfwords and se_ where they fill one, and what the Book of the
/// category calls a form is drawn with the bits numbered from the most
/// significant, which is how the fields below are placed.
/// </summary>
module internal B2R2.Assembly.PPC.AsmVLE

open B2R2
open B2R2.FrontEnd.PPC
open B2R2.Assembly.PPC.ParserHelper
open B2R2.Assembly.PPC.AsmField

/// Every opcode that fills one halfword, which are the ones the category names
/// with the prefix se_.
let private halfwords =
  lazy (System.Enum.GetValues typeof<Opcode>
        |> Seq.cast<Opcode>
        |> Seq.filter (fun opcode -> (string opcode).StartsWith "SE_")
        |> Set.ofSeq)

/// How many bytes an instruction takes: two where it is one of the short forms
/// of the category and four otherwise.
let size (ins: AsmInsInfo) =
  if halfwords.Value.Contains ins.Opcode then 2 else 4

/// An instruction that names nothing and fills a halfword, which is the whole
/// of its encoding.
let private cForm value ins =
  match ins.Operands with
  | [] -> value
  | _ -> wrongOperands ins

/// The instructions of Variable Length Encoding, by what they are called.
let vleEncoders () =
  [ Op.SE_ILLEGAL, cForm 0x0000u
    Op.SE_ISYNC, cForm 0x0001u
    Op.SE_SC, cForm 0x0002u
    Op.SE_BLR, cForm 0x0004u
    Op.SE_BLRL, cForm 0x0005u
    Op.SE_BCTR, cForm 0x0006u
    Op.SE_BCTRL, cForm 0x0007u ]

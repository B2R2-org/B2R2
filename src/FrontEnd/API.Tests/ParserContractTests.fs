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

namespace B2R2.FrontEnd.Tests

open System
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Pins the exception contract of <see
/// cref='T:B2R2.FrontEnd.BinLifter.IInstructionParsable'/> itself, reaching the
/// parsers through ArchSupport rather than through LiftingUnit, which converts
/// on their behalf and would hide what they raise.
[<TestClass>]
type ParserContractTests() =
  /// Every architecture ArchSupport builds a parser for.
  static let archs =
    [| Architecture.Intel
       Architecture.ARMv7
       Architecture.ARMv8
       Architecture.MIPS
       Architecture.PPC
       Architecture.RISCV
       Architecture.SPARC
       Architecture.S390
       Architecture.SH4
       Architecture.PARISC
       Architecture.AVR
       Architecture.TMS320C6000
       Architecture.EVM |]

  static let parserFor (arch: Architecture) =
    let isa = ISA arch
    ArchSupport.createParser (BinReader.Init isa.Endian) isa

  (* A span that cannot hold a whole instruction is a property of the input, but
     the read running off its end surfaced as a span-level exception, so Parse
     had no single type for a caller to catch. *)
  [<TestMethod>]
  member _.``[IInstructionParsable] an empty span is a parse failure test``() =
    for arch in archs do
      let parser = parserFor arch
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        parser.Parse(ReadOnlySpan [||], 0UL) |> ignore) |> ignore

  (* The byte-array overload must answer the same way as the span one; several
     parsers used to carry a separate copy of the body for it. *)
  [<TestMethod>]
  member _.``[IInstructionParsable] both overloads agree test``() =
    for arch in archs do
      let parser = parserFor arch
      let empty: byte[] = [||]
      Assert.ThrowsExactly<ParsingFailureException>(fun () ->
        parser.Parse(empty, 0UL) |> ignore) |> ignore

  (* Terminator writes a fatal-error banner and a stack trace to stderr before
     it raises, so a parser that reports an undecodable encoding through it
     floods the console of a tool that is merely disassembling: the guard at the
     Parse boundary converts the exception but cannot unprint the banner. These
     three Thumb encodings reach a gap in the Advanced SIMD tables. *)
  [<TestMethod>]
  member _.``[IInstructionParsable] a parse failure stays quiet test``() =
    let real = Console.Error
    let sink = new IO.StringWriter()
    Console.SetError sink
    try
      let isa = ISA Architecture.ARMv7
      let parser = ArchSupport.createParser (BinReader.Init isa.Endian) isa
      (parser :?> ARM32.IModeSwitchable).IsThumb <- true
      for hex in [| "98efb07b"; "84eff686"; "b9ef3c04" |] do
        let head = ByteArray.ofHexString hex
        let bytes = Array.append head (Array.zeroCreate 60)
        try parser.Parse(ReadOnlySpan bytes, 0UL) |> ignore with _ -> ()
      Assert.AreEqual<string>("", sink.ToString())
    finally
      Console.SetError real

  (* Undecodable bytes reach that outcome by many routes -- an unhandled
     dispatch value, a reserved encoding, an assertion the author believed
     unreachable -- and every one of them is the same answer to the caller. The
     span is wider than any MaxInstructionSize so a short read cannot be the
     cause. *)
  [<TestMethod>]
  member _.``[IInstructionParsable] a parse failure has one type test``() =
    let rng = Random 20260730
    let bytes = Array.zeroCreate 64
    for arch in archs do
      let parser = parserFor arch
      for _ = 1 to 2000 do
        rng.NextBytes bytes
        try parser.Parse(ReadOnlySpan bytes, 0UL) |> ignore
        with
        | ParsingFailureException -> ()
        | e -> Assert.Fail $"{arch}: {e.GetType().Name}"

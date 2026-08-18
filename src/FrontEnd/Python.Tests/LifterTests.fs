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

namespace B2R2.FrontEnd.Python.Tests

open System.IO
open System.IO.Compression
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.Python
open Microsoft.VisualStudio.TestTools.UnitTesting

/// Holds the one Lifter to everything the sixteen decode tables can hand it.
/// The lifter is a single match over Opcode with no version dimension of its
/// own, so nothing but this stops an opcode a version introduces -- or one
/// whose argument a version takes away -- from reaching the fallback arm, or
/// from reading an argument that is not there. Both are raised exceptions
/// rather than wrong answers, which is what this walks the tables to find.
[<TestClass>]
type LifterTests() =
  static let zipPath =
    Path.Combine(System.AppContext.BaseDirectory, "Python", "python_basic.zip")

  static let bytes =
    use archive = ZipFile.Open(zipPath, ZipArchiveMode.Read)
    let stream = archive.GetEntry("python_basic.pyc").Open()
    use ms = new MemoryStream()
    stream.CopyTo ms
    ms.ToArray()

  static let file = PythonBinFile("", bytes, None)

  /// An address inside a code object, which is what the pre-3.11 absolute
  /// jumps resolve their targets against.
  static let addr = (fst file.Consts[0]).Min

  static let isa = (file :> IBinFile).ISA

  static let versions =
    [| for v in 300 .. 315 -> LanguagePrimitives.EnumOfValue v |]

  /// The instruction the given byte names in the given version. Its argument
  /// is 1 rather than 0 because several opcodes read theirs as a count of the
  /// stack slots they reach past the top.
  static let mkIns version b opcode =
    let opr =
      if Tables.hasOperand version b then OneOperand(1, None) else NoOperand
    let len = Tables.length version b
    let sem = Parsing.semantics
    Instruction(addr, len, opcode, opr, 64<rt>, version, file, sem)

  /// Runs the given check over every instruction all sixteen versions decode,
  /// naming the one that fails.
  static let forEachOpcode check =
    for version in versions do
      for b in 0 .. 0xFF do
        let opcode = Tables.decode version b
        (* EXTENDED_ARG is folded into the instruction it prefixes while
           parsing, so it is the one opcode nothing downstream ever sees. *)
        if opcode = Opcode.InvalidOp || opcode = Opcode.EXTENDED_ARG then
          ()
        else
          try check (mkIns version b opcode)
          with e -> Assert.Fail $"{version} {opcode} (0x%02x{b}): {e.Message}"

  [<TestMethod>]
  member _.``[Python] every decodable opcode lifts``() =
    forEachOpcode <| fun ins ->
      let regs = RegisterFactory isa
      let bld = ILowUIRBuilder.Default(isa, regs, LowUIRStream 16)
      Lifter.translate file ins bld |> ignore

  /// isBranch and targetKind have to agree about which opcodes are jumps:
  /// branchTarget raises on one the first counts and the second has no rule
  /// for, and a jump the first misses gets no CFG edge at all.
  [<TestMethod>]
  member _.``[Python] every branch resolves a target``() =
    forEachOpcode <| fun ins ->
      if Semantics.isBranch ins then
        let ftAddr = ins.Address + uint64 ins.Length
        Semantics.branchTarget ins ftAddr 1 |> ignore
      else
        ()

  [<TestMethod>]
  member _.``[Python] minor version matches the enum``() =
    for version in versions do
      Assert.AreEqual(int version - 300, PythonVersion.minor version)

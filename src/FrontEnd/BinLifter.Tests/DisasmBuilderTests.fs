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

namespace B2R2.FrontEnd.BinLifter.Tests

open B2R2
open B2R2.FrontEnd.BinLifter
open Microsoft.VisualStudio.TestTools.UnitTesting

[<TestClass>]
type DisasmBuilderTests() =
  /// The one address the resolver knows, so that the found and the not-found
  /// paths can be exercised against the same builder.
  static let known = 0x1000UL

  static let resolver =
    { new INameResolvable with
        member _.TryResolveName addr =
          if addr = known then Ok "main" else Error ErrorCase.SymbolNotFound }

  static let prefix = { AsmWordKind = AsmWordKind.String; AsmWordValue = "<" }

  static let suffix = { AsmWordKind = AsmWordKind.String; AsmWordValue = ">" }

  static let mapNoSymbol addr =
    [| { AsmWordKind = AsmWordKind.Value
         AsmWordValue = HexString.ofUInt64 addr } |]

  /// The two builders implement AccumulateSymbol separately, so every case has
  /// to hold for both.
  static let builders (names: INameResolvable | null) =
    [| StringDisasmBuilder(false, names, WordSize.Bit64) :> IDisasmBuilder
       AsmWordDisasmBuilder(false, names, WordSize.Bit64) :> IDisasmBuilder |]

  static let render (builder: IDisasmBuilder) addr =
    builder.AccumulateSymbol(addr, prefix, suffix, mapNoSymbol)
    builder.ToString()

  [<TestMethod>]
  member _.``[DisasmBuilder] a resolved symbol wins test``() =
    for builder in builders resolver do
      Assert.AreEqual<string>("<main>", render builder known)

  (* The three cases below all mean "no symbol to show", and the interface
     promises noSymbolMapper covers exactly that. The implementations kept the
     fallback inside the branch that required both a resolver and ShowSymbol, so
     the other two emitted nothing at all, leaving the caller's already-written
     " ; " dangling with no target behind it. *)
  [<TestMethod>]
  member _.``[DisasmBuilder] an unresolvable address falls back test``() =
    for builder in builders resolver do
      Assert.AreEqual<string>("0x2000", render builder 0x2000UL)

  [<TestMethod>]
  member _.``[DisasmBuilder] hidden symbols fall back test``() =
    for builder in builders resolver do
      builder.ShowSymbol <- false
      Assert.AreEqual<string>("0x1000", render builder known)

  [<TestMethod>]
  member _.``[DisasmBuilder] no resolver falls back test``() =
    for builder in builders null do
      Assert.AreEqual<string>("0x1000", render builder known)

  (* ShowSymbol has a setter, so it can be turned on where there is no resolver
     to consult. That must reach the fallback rather than dereference null. *)
  [<TestMethod>]
  member _.``[DisasmBuilder] symbols asked for without a resolver test``() =
    for builder in builders null do
      builder.ShowSymbol <- true
      Assert.AreEqual<string>("0x1000", render builder known)

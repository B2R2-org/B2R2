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

namespace B2R2.Core.Tests

open Microsoft.VisualStudio.TestTools.UnitTesting
open B2R2

[<TestClass>]
type AddrTests() =
  let bit32 = Addr.toString WordSize.Bit32

  let bit64 = Addr.toString WordSize.Bit64

  /// An address is written out to the width of the word size it belongs to, so
  /// that the addresses of one binary line up against one another.
  [<TestMethod>]
  member _.``An address is padded to the width of its word size``() =
    Assert.AreEqual<string>("00000000", bit32 0UL)
    Assert.AreEqual<string>("00401000", bit32 0x401000UL)
    Assert.AreEqual<string>("ffffffff", bit32 0xffffffffUL)
    Assert.AreEqual<string>("0000000000000000", bit64 0UL)
    Assert.AreEqual<string>("0000000000401000", bit64 0x401000UL)
    Assert.AreEqual<string>("00007fffdeadbeef", bit64 0x7fffdeadbeefUL)

  /// A width is the least an address is written out to and never the most. An
  /// address that does not fit the word size it is read against is still that
  /// address, and one cut down to the width reads as another address
  /// altogether, which is the one thing printing it must not do.
  [<TestMethod>]
  member _.``An address wider than its word size is not cut short``() =
    Assert.AreEqual<string>("100000000", bit32 0x100000000UL)
    Assert.AreEqual<string>("555555554000", bit32 0x555555554000UL)
    Assert.AreEqual<string>("ffffffffffffffff", bit32 0xffffffffffffffffUL)

  /// An address is 64 bits wide whatever the word size says, so every word
  /// size other than the 32-bit one is written out to that full width.
  [<TestMethod>]
  member _.``A word size other than 32 bits takes the full width``() =
    let bit256 = Addr.toString WordSize.Bit256
    Assert.AreEqual<string>("0000000000401000", bit256 0x401000UL)

  /// A function carrying no symbol is named after its address, and reading
  /// that address back out of the name is how a caller undoes the naming.
  [<TestMethod>]
  member _.``A function name carries the address it was made from``() =
    Assert.AreEqual<string>("func_00401000", Addr.toFuncName 0x401000UL)
    for addr in [ 0UL; 0x401000UL; 0x555555554000UL; 0xffffffffffffffffUL ] do
      Assert.AreEqual<Addr>(addr, Addr.ofFuncName (Addr.toFuncName addr))

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
type ISATests() =

  /// Every 32-bit ARM ISA and the name it goes by. Which of the two
  /// instruction sets one means is part of what it is, because nothing in a
  /// word of either says which it belongs to.
  static let arm32 =
    [ "armv7", Architecture.ARMv7, Endian.Little, ARM32Mode.ARM
      "armv7be", Architecture.ARMv7, Endian.Big, ARM32Mode.ARM
      "thumb", Architecture.ARMv7, Endian.Little, ARM32Mode.Thumb
      "thumbbe", Architecture.ARMv7, Endian.Big, ARM32Mode.Thumb
      "aarch32", Architecture.ARMv8, Endian.Little, ARM32Mode.ARM
      "aarch32be", Architecture.ARMv8, Endian.Big, ARM32Mode.ARM
      "aarch32t", Architecture.ARMv8, Endian.Little, ARM32Mode.Thumb
      "aarch32tbe", Architecture.ARMv8, Endian.Big, ARM32Mode.Thumb ]

  /// Every member of the 68000 family and the name it goes by. Which member an
  /// m68k ISA means is part of what it is, because the family shares one
  /// encoding space and a later member reads encodings an earlier one does not.
  static let m68k =
    [ "m68000", M68KModel.M68000
      "m68010", M68KModel.M68010
      "m68020", M68KModel.M68020
      "m68030", M68KModel.M68030
      "m68040", M68KModel.M68040
      "m68060", M68KModel.M68060 ]

  [<TestMethod>]
  member _.``An ARM32 name says which instruction set it means``() =
    for name, arch, endian, mode in arm32 do
      let isa = ISA name
      Assert.AreEqual<Architecture>(arch, isa.Arch, name)
      Assert.AreEqual<Endian>(endian, isa.Endian, name)
      Assert.AreEqual<WordSize>(WordSize.Bit32, isa.WordSize, name)
      Assert.AreEqual<ARM32Mode>(mode, isa.ARM32Mode, name)

  /// An ISA has to print as the name it can be read back from, since that name
  /// is what a tool takes from a command line and what it shows a user.
  [<TestMethod>]
  member _.``An ARM32 ISA prints as the name it is read from``() =
    for name, _, _, _ in arm32 do
      Assert.AreEqual<string>(name, (ISA name).ToString(), name)

  [<TestMethod>]
  member _.``The names of one ARM32 ISA all mean it``() =
    let aliases =
      [ "armv7", [ "armv7le"; "armel"; "armhf"; "arm32"; "arm" ]
        "thumb", [ "t32" ]
        "thumbbe", [ "t32be" ]
        "aarch32", [ "armv8a32" ] ]
    for name, others in aliases do
      for other in others do
        Assert.AreEqual<string>(name, (ISA other).ToString(), other)

  [<TestMethod>]
  member _.``An m68k name says which member of the family it means``() =
    for name, model in m68k do
      let isa = ISA name
      Assert.AreEqual<Architecture>(Architecture.M68K, isa.Arch, name)
      Assert.AreEqual<Endian>(Endian.Big, isa.Endian, name)
      Assert.AreEqual<WordSize>(WordSize.Bit32, isa.WordSize, name)
      Assert.AreEqual<M68KModel>(model, isa.M68KModel, name)

  [<TestMethod>]
  member _.``An m68k ISA prints as the name it is read from``() =
    for name, _ in m68k do
      Assert.AreEqual<string>(name, (ISA name).ToString(), name)

  /// A bare "m68k" has to name a member all the same, and the 68020 is the one
  /// the Linux/m68k port takes as its baseline. Every constructor that leaves
  /// the flags to a default has to agree, or an ISA built without a model named
  /// would quietly mean a 68000 and reject most of what it was given.
  [<TestMethod>]
  member _.``An m68k ISA without a named model is a 68020``() =
    let isas =
      [ ISA "m68k"
        ISA "68k"
        ISA Architecture.M68K
        ISA(Architecture.M68K, Endian.Big)
        ISA(Architecture.M68K, WordSize.Bit32) ]
    for isa in isas do
      Assert.AreEqual<M68KModel>(M68KModel.M68020, isa.M68KModel)
      Assert.AreEqual<string>("m68020", isa.ToString())

  /// The flags an ISA carries mean whatever the architecture they belong to
  /// says they mean, so an architecture that has nothing to say there is read
  /// as saying the one thing a zero says.
  [<TestMethod>]
  member _.``An ISA that is not 32-bit ARM carries no mode``() =
    for name in [ "x86"; "x86-64"; "aarch64"; "mips32"; "ppc32" ] do
      Assert.AreEqual<ARM32Mode>(ARM32Mode.ARM, (ISA name).ARM32Mode, name)

// vim: set tw=80 sts=2 sw=2:

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

namespace B2R2.FrontEnd.BinFile.Tests

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinFile.Wasm
open Microsoft.VisualStudio.TestTools.UnitTesting
open type FileFormat

[<TestClass>]
type WasmTests() =
  static let parseFile fileName =
    let zipFile = fileName + ".zip"
    let fileNameInZip = fileName + ".wasm"
    let bytes = ZIPReader.readBytes WasmBinary zipFile fileNameInZip
    WasmBinFile("", bytes) :> IBinFile

  static let file = parseFile "wasm_basic"

  (* Two functions, the first opening with two local declarations, spelled out
     so the offsets the body test pins stay visible:
       (module
         (func $a (result i32) (local i32 i64) i32.const 7)
         (func $b (result i32) i32.const 9))
     The code section starts at 0x14; func[0] holds its locals at 0x18..0x1c
     and its instructions at 0x1d..0x1f, and func[1] follows with none. *)
  static let twoFunctions =
    "0061736d010000000105016000017f03030200000a0f020802017f017e"
    + "41070b040041090b"
    |> ByteArray.ofHexString

  (* Every section the current spec orders, including the two the original
     numbering did not reach: a tag section (id 13), which sorts between
     memory and global, and a data count section (id 12), which sorts between
     element and code. Its one function holds a nop at 0x2c. *)
  static let modernSections =
    "0061736d010000000104016000000302010005030100010d0301000006"
    + "06017f0141000b0c01010a05010300010b0b07010041000b0100"
    |> ByteArray.ofHexString

  (* Every segment shape bulk memory and reference types added: the element
     section holds one of each of the eight modes and the data section one of
     each of its three. Its one function holds a nop at 0x66. *)
  static let segmentModes =
    "0061736d01000000010401600000030201000407027000047000040503"
    + "010001070501016600000935080041000b010001000100020141000b00"
    + "0100030001000441000b01d2000b057001d2000b060141000b7001d200"
    + "0b077001d2000b0c01030a05010300010b0b11030041000b01aa0101bb"
    + "020041040b01cc"
    |> ByteArray.ofHexString

  [<TestMethod>]
  member _.``[Wasm] format test``() = Assert.AreEqual(WasmBinary, file.Format)

  [<TestMethod>]
  member _.``[Wasm] ISA test``() =
    Assert.AreEqual(Architecture.WASM, file.ISA.Arch)

  [<TestMethod>]
  member _.``[Wasm] kind test``() =
    Assert.AreEqual<BinFileKind>(Unknown, file.Kind)

  [<TestMethod>]
  member _.``[Wasm] base address test``() =
    Assert.AreEqual<uint64>(0UL, file.BaseAddress)

  [<TestMethod>]
  member _.``[Wasm] has no symbol table test``() =
    match file.SymbolTable with
    | None -> ()
    | Some _ -> Assert.Fail "Wasm should not provide a symbol table."

  [<TestMethod>]
  member _.``[Wasm] property defaults test``() =
    Assert.AreEqual<bool>(true, file.IsNXEnabled)
    Assert.AreEqual<bool>(false, file.IsPIE)
    Assert.AreEqual<bool>(false, file.IsBaseRelative)

  [<TestMethod>]
  member _.``[Wasm] sections length test``() =
    Assert.AreEqual<int>(8, (file :?> WasmBinFile).Sections.Length)

  [<TestMethod>]
  member _.``[Wasm] text section address test``() =
    Assert.AreEqual<uint64>(0x47UL, getTextSectionAddr file)

  [<TestMethod>]
  member _.``[Wasm] linkageTableEntries length test``() =
    Assert.AreEqual<int>(1, getLinkageTableEntries file |> Seq.length)

  [<TestMethod>]
  member _.``[Wasm] name section resolves the entry point name``() =
    let resolver = Option.get file.NameResolver
    Assert.AreEqual<Result<string, _>>(
      Ok "__wasm_call_ctors", resolver.TryResolveName file.EntryPoint.Value
    )

  [<TestMethod>]
  member _.``[Wasm] name section resolves an imported function name``() =
    let hasPutcJs =
      getLinkageTableEntries file |> Seq.exists (fun i -> i.Name = "putc_js")
    Assert.AreEqual<bool>(true, hasPutcJs)

  [<TestMethod>]
  member _.``[Wasm] name section resolves a local function name``() =
    let resolver = Option.get file.NameResolver
    let hasMain =
      file.Structure.Value.FunctionAddresses
      |> Array.exists (fun a -> resolver.TryResolveName a = Ok "main")
    Assert.AreEqual<bool>(true, hasMain)

  [<TestMethod>]
  member _.``[Wasm] valid address test``() =
    Assert.AreEqual<bool>(true, file.IsValidAddr 0x49UL)
    Assert.AreEqual<bool>(false, file.IsValidAddr 0x100000UL)

  [<TestMethod>]
  member _.``[Wasm] slice maps offset to content test``() =
    let viaSlice = file.Slice(0x49UL, 4).ToArray()
    let viaRaw = file.RawBytes.Span.Slice(0x49, 4).ToArray()
    CollectionAssert.AreEqual(viaRaw, viaSlice)

  [<TestMethod>]
  member _.``[Wasm] format detector identifies Wasm test``() =
    let bytes =
      ZIPReader.readBytes WasmBinary "wasm_basic.zip" "wasm_basic.wasm"
    let isa = ISA(Architecture.Intel, Endian.Little, WordSize.Bit64)
    let struct (fmt, _) = FormatDetector.identify bytes isa
    Assert.AreEqual(WasmBinary, fmt)

  [<TestMethod>]
  member _.``[Wasm] function body skips the locals test``() =
    (* A function body opens with a vector of local declarations, which are
       not instructions; a dump that starts at the body reads them as code
       and loses sync with the stream for the rest of the section. *)
    let file = WasmBinFile("", twoFunctions)
    let bodies = file.FunctionBodies
    Assert.AreEqual<int>(2, bodies.Length)
    let name, ptr = bodies[0]
    Assert.AreEqual<string>("func[0]", name)
    Assert.AreEqual<Addr>(0x1dUL, ptr.Addr)
    Assert.AreEqual<Addr>(0x1fUL, ptr.MaxAddr)
    let name, ptr = bodies[1]
    Assert.AreEqual<string>("func[1]", name)
    Assert.AreEqual<Addr>(0x22UL, ptr.Addr)
    Assert.AreEqual<Addr>(0x24UL, ptr.MaxAddr)

  [<TestMethod>]
  member _.``[Wasm] section ids past data test``() =
    (* Section order is not id order once the ids run past data: a tag sorts
       ahead of global and a data count ahead of code. Reading the ids as the
       order turns either one into a malformed file, and clang emits a data
       count for any module built with bulk memory. *)
    let file = WasmBinFile("", modernSections)
    let names =
      BinFileOps.getSections file |> Array.map (fun sec -> sec.Name)
    CollectionAssert.Contains(names, "tag")
    CollectionAssert.Contains(names, "datacount")
    let bodies = file.FunctionBodies
    Assert.AreEqual<int>(1, bodies.Length)
    Assert.AreEqual<Addr>(0x2cUL, (snd bodies[0]).Addr)
    Assert.AreEqual<Addr>(0x2dUL, (snd bodies[0]).MaxAddr)

  [<TestMethod>]
  member _.``[Wasm] segment modes test``() =
    (* A segment's mode decides which fields it carries, so a reader that
       assumes the original active form reads the next segment's mode as this
       one's contents. Modes past the first come from bulk memory and
       reference types, which clang and rustc both emit. *)
    let file = WasmBinFile("", segmentModes)
    let elems = file.WASM.ElementSection.Value.Contents.Value
    Assert.AreEqual<uint32>(8u, elems.Length)
    CollectionAssert.AreEqual([| 0u .. 7u |],
                              elems.Elements |> Array.map _.Mode)
    (* Only an active segment carries an offset. *)
    let offsetOf (elems: Vector<Elem>) i = elems.Elements[i].OffsetExpr
    Assert.AreEqual<ConstExpr option>(Some(I32 0u), offsetOf elems 0)
    Assert.AreEqual<ConstExpr option>(None, offsetOf elems 1)
    (* Only mode 2 and mode 6 name their table; only mode 4 and up spell
       their entries out as expressions. *)
    Assert.AreEqual<TableIdx>(1u, elems.Elements[6].TableIndex)
    match elems.Elements[2].Init with
    | ElemFuncs funcs ->
      CollectionAssert.AreEqual([| 0u |], funcs.Elements)
    | ElemExprs _ ->
      Assert.Fail "mode 2 names its entries by index"
    match elems.Elements[4].Init with
    | ElemExprs exprs ->
      CollectionAssert.AreEqual([| RefFunc 0u |], exprs.Elements)
    | ElemFuncs _ ->
      Assert.Fail "mode 4 spells its entries out as expressions"
    let datas = file.WASM.DataSection.Value.Contents.Value
    Assert.AreEqual<uint32>(3u, datas.Length)
    CollectionAssert.AreEqual([| 0u; 1u; 2u |],
                              datas.Elements |> Array.map _.Mode)
    let bytesOf (datas: Vector<Data>) i = datas.Elements[i].InitBytes.Elements
    CollectionAssert.AreEqual([| 0xaauy |], bytesOf datas 0)
    CollectionAssert.AreEqual([| 0xbbuy |], bytesOf datas 1)
    CollectionAssert.AreEqual([| 0xccuy |], bytesOf datas 2)
    Assert.AreEqual<Addr>(0x66UL, (snd file.FunctionBodies[0]).Addr)

  [<TestMethod>]
  member _.``[Wasm] index vector test``() =
    (* A vector's element reader reports where the next element starts, which
       is not what the LEB reader returns. The function section is a vector of
       bare indices, so with the two confused every entry after the first was
       read from the start of the file. *)
    let file = WasmBinFile("", twoFunctions)
    let funcs = file.WASM.FunctionSection.Value.Contents.Value
    Assert.AreEqual<uint32>(2u, funcs.Length)
    CollectionAssert.AreEqual([| 0u; 0u |], funcs.Elements)

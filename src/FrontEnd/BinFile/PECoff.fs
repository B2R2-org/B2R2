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

module internal B2R2.FrontEnd.BinFile.PE.Coff

open System.Reflection.PortableExecutable
open System.Runtime.InteropServices
open B2R2
open B2R2.FrontEnd.BinFile.FileHelper

type CoffSymbolTypeLSB =
  | ImageSymTypeNull = 0uy
  | ImageSymTypeVoid = 1uy
  | ImageSymTypeChar = 2uy
  | ImageSymTypeShort = 3uy
  | ImageSymTypeInt = 4uy
  | ImageSymTypeLong= 5uy
  | ImageSymTypeFloat= 6uy
  | ImageSymTypeDouble = 7uy
  | ImageSymTypeStruct = 8uy
  | ImageSymTypeUnion = 9uy
  | ImageSymTypeEnum = 10uy
  | ImageSymTypeMOE = 11uy
  | ImageSymTypeByte = 12uy
  | ImageSymTypeWord = 13uy
  | ImageSymTypeUInt = 14uy
  | ImageSymTypeDWord = 15uy

type CoffSymbolTypeMSB =
  | ImageSymDTypeNull = 0uy
  | ImageSymDTypePointer = 1uy
  | ImageSymDTypeFunction = 2uy
  | ImageSymDTypeArray = 3uy

type StorageClass =
  | ImageSymClassEndOfFunction = 0xffuy
  | ImageSymClassNull = 0uy
  | ImageSymClassAutomatic = 1uy
  | ImageSymClassExternal = 2uy
  | ImageSymClassStatic = 3uy
  | ImageSymClassRegister = 4uy
  | ImageSymClassExternalDef = 5uy
  | ImageSymClassLabel = 6uy
  | ImageSymClassUndefinedLabel = 7uy
  | ImageSymClassMemberOfStruct = 8uy
  | ImageSymClassArgument = 9uy
  | ImageSymClassStructTag = 10uy
  | ImageSymClassMemberOfUnion = 11uy
  | ImageSymClassUnionTag = 12uy
  | ImageSymClassTypeDefinition = 13uy
  | ImageSymClassUndefinedStatic = 14uy
  | ImageSymClassEnumTag = 15uy
  | ImageSymClassMemberOfEnum = 16uy
  | ImageSymClassRegisterParam = 17uy
  | ImageSymClassBitfield = 18uy
  | ImageSymClassBlock = 100uy
  | ImageSymClassFunction = 101uy
  | ImageSymClassEndOfStruct = 102uy
  | ImageSymClassFile = 103uy
  | ImageSymClassSection = 104uy
  | ImageSymClassWeakExternal = 105uy
  | ImageSymClassCLRToken = 107uy

type CoffSymbol = {
  SymbName: string
  SymbValue: int
  SecNumber: int
  SymbType: CoffSymbolTypeLSB * CoffSymbolTypeMSB
  StorageClass: StorageClass
}

let getWordSize = function
  | Machine.Alpha64
  | Machine.Arm64
  | Machine.Amd64 -> WordSize.Bit64
  | _ -> WordSize.Bit32

let parseLongSymbolName (binReader: BinReader) stroff offset =
  peekCString binReader (stroff + offset)

let parseSymbName (binReader: BinReader) offset stroff =
  let bs = binReader.PeekSpan (8, offset)
  if bs[0] = 0uy && bs[1] = 0uy && bs[2] = 0uy && bs[3] = 0uy then
    MemoryMarshal.Read<int> (bs.Slice 4) |> parseLongSymbolName binReader stroff
  else
    ByteArray.extractCStringFromSpan bs 0

let parseSymType typ =
  let lsb = typ &&& 0xFs |> byte
  let msb = typ >>> 4 |> byte
  LanguagePrimitives.EnumOfValue<byte, CoffSymbolTypeLSB> (lsb),
  LanguagePrimitives.EnumOfValue<byte, CoffSymbolTypeMSB> (msb)

let parseStorageClass b =
  LanguagePrimitives.EnumOfValue<byte, StorageClass> (b)

let accumulateSymbol name v secnum typ storage acc =
  { SymbName = name
    SymbValue = v
    SecNumber = secnum
    SymbType = typ
    StorageClass = storage } :: acc

let toPESymbol symb =
  match symb.SymbType with
  | _, CoffSymbolTypeMSB.ImageSymDTypeFunction ->
    Some { Flags = SymFlags.Function
           Address = symb.SymbValue |> uint64
           Segment = symb.SecNumber |> uint16
           Name = symb.SymbName }
  | _ -> None

let buildSymbolMaps arr =
  arr |> Array.fold (fun (byAddr, byName) symb ->
    Map.add symb.Address symb byAddr,
    Map.add symb.Name symb byName
    ) (Map.empty, Map.empty)

let getSymbols (binReader: BinReader) (coff: CoffHeader) =
  let maxCnt = coff.NumberOfSymbols - 1
  let tbloff = coff.PointerToSymbolTable
  let stroff = tbloff + coff.NumberOfSymbols * 18
  let rec parse acc auxcnt cnt =
    if auxcnt > 0 then (* TODO *)
      if cnt >= maxCnt then acc
      else parse acc (auxcnt - 1) (cnt + 1)
    else
      let offset = tbloff + cnt * 18
      let name = parseSymbName binReader offset stroff
      let v = binReader.PeekInt32 (offset + 8)
      let secnum = binReader.PeekInt16 (offset + 12) |> int
      let typ = binReader.PeekInt16 (offset + 14) |> parseSymType
      let storage = binReader.PeekByte (offset + 16) |> parseStorageClass
      let auxcnt = binReader.PeekByte (offset + 17) |> int
      let acc = accumulateSymbol name v secnum typ storage acc
      if cnt >= maxCnt then acc
      else parse acc auxcnt (cnt + 1)
  if tbloff = 0 then [] else parse [] 0 0
  |> List.choose toPESymbol
  |> fun lst ->
    let arr = Array.ofList lst
    let byAddr, byName = buildSymbolMaps arr
    { SymbolByAddr = byAddr
      SymbolByName = byName
      SymbolArray = arr }

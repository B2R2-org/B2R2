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

namespace B2R2.RearEnd.BinDisasm

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter

/// Represents the main code dumper class.
type BinCodeDumper(hdl, isTable, showSymbol, showColor, dumpMode) =

  let [<Literal>] IllegalStr = "(illegal)"

  let [<Literal>] DataStr = "(data)"

  /// How many bytes of a data region to print on one line, which is a word on
  /// every architecture that marks its data regions.
  let [<Literal>] DataChunkSize = 4

  let wordSize = (hdl: BinHandle).ISA.WordSize

  let liftingUnit = hdl.NewLiftingUnit()

  let archmodes = BinCodeModeTable(BinFileOps.getCodeModeMarkers hdl.File)

  /// Whether the bytes at hand are a data region that a $d marker started.
  let mutable inData = false

  let fnSymbols =
    if isTable then FunctionSymbols.ofLinkageTable hdl
    else FunctionSymbols.ofText hdl

  (* The bytes as "AA BB CC", built in one go: formatting and joining them a
     byte at a time allocated a string per byte per instruction. *)
  let convertToHexStr (bytes: byte[]) =
    if bytes.Length = 0 then
      ""
    else
      let chars = Array.zeroCreate<char>(bytes.Length * 3 - 1)
      for i in 0 .. bytes.Length - 1 do
        let b = int bytes[i]
        if i > 0 then chars[i * 3 - 1] <- ' ' else ()
        chars[i * 3] <- "0123456789ABCDEF"[b >>> 4]
        chars[i * 3 + 1] <- "0123456789ABCDEF"[b &&& 0xF]
      System.String chars

  let printLowUIR (lowUIRStr: string) bytes =
    let hexStr = convertToHexStr bytes |> String.wrapSquareBracket
    printsr [| hexStr |]
    printsr [| lowUIRStr |]

  let printRegularDisasm disasmStr addr bytes =
    let hexStr = convertToHexStr bytes
    let addrStr = Addr.toString wordSize addr + ":"
    printsr [| addrStr; hexStr; disasmStr |]

  let regularDisPrinter ptr ins =
    let disasmStr = liftingUnit.DisasmInstruction(ins = ins)
    let bytes = hdl.ReadBytes(ptr = ptr, nBytes = int ins.Length)
    printRegularDisasm disasmStr ptr.Addr bytes

  let regularIRPrinter optimizer ptr ins =
    let stmts = optimizer (liftingUnit.LiftInstruction(ins = ins))
    let lowUIRStr = PrettyPrinter.ToString(lowuirStmts = stmts)
    let bytes = hdl.ReadBytes(ptr = ptr, nBytes = int ins.Length)
    printLowUIR lowUIRStr bytes

  let convertToDisasmStr (words: AsmWord[]) =
    let cs = ColoredString()
    for word in words do
      match word.AsmWordKind with
      | AsmWordKind.Address -> ()
      | AsmWordKind.Mnemonic -> cs.Append(Green, word.AsmWordValue) |> ignore
      | AsmWordKind.Variable -> cs.Append(Blue, word.AsmWordValue) |> ignore
      | AsmWordKind.Value -> cs.Append(Red, word.AsmWordValue) |> ignore
      | _ -> cs.Append(NoColor, word.AsmWordValue) |> ignore
    cs

  let printColorDisasm words addr bytes =
    let hexStr = convertToHexStr bytes
    let addrStr = Addr.toString wordSize addr + ":"
    let disasStr = convertToDisasmStr words
    printcr [| ColoredString(Green, addrStr)
               ColoredString(NoColor, hexStr)
               disasStr |]

  let colorDisPrinter ptr ins =
    let words = liftingUnit.DecomposeInstruction(ins = ins)
    let bytes = hdl.ReadBytes(ptr = ptr, nBytes = int ins.Length)
    printColorDisasm words ptr.Addr bytes

  (* Only ARM binaries carry mode markers, so an empty table means there is
     nothing to look up per instruction. Testing the table rather than the
     architecture keeps AArch32 covered, which an ARMv7 test missed. A code
     marker of either ARM ABI ends a data region, which is what AArch64 needs
     one for, having no second encoding to switch to. *)
  let checkAndUpdateArchMode =
    if archmodes.IsEmpty then
      fun _addr -> ()
    else
      fun addr ->
        match archmodes.TryFindMode addr with
        | Some ArmMode ->
          liftingUnit.IsThumb <- false
          inData <- false
        | Some ThumbMode ->
          liftingUnit.IsThumb <- true
          inData <- false
        | Some A64Mode ->
          inData <- false
        | Some DataMode ->
          inData <- true
        | _ ->
          ()

  let printFuncSymbol isFirst addr =
    match fnSymbols.TryGetValue addr with
    | true, name ->
      if not isFirst then printsn "" else ()
      printsn (String.wrapAngleBracket name)
    | false, _ ->
      ()

  let printInstr =
    match dumpMode with
    | LowUIR optimizer ->
      regularIRPrinter optimizer
    | Disassembly syntax ->
      liftingUnit.DisassemblySyntax <- syntax
      (* The unit drops a syntax it cannot honour, so compare rather than test
         the architecture here. Saying nothing would print default syntax as
         though the requested one had been applied. *)
      if liftingUnit.DisassemblySyntax <> syntax then
        wprintsn "AT&T syntax applies to Intel only; ignoring it."
      else
        ()
      liftingUnit.ConfigureDisassembly(false, showSymbol)
      if showColor then colorDisPrinter else regularDisPrinter

  let handleInvalidIns ptr =
    let align = liftingUnit.InstructionAlignment
    let bytes = hdl.ReadBytes(ptr = ptr, nBytes = align)
    if dumpMode.IsLowUIR then printLowUIR IllegalStr bytes
    else printRegularDisasm IllegalStr ptr.Addr bytes
    ptr.Advance align

  (* A $d marker says that what follows is data rather than instructions, so
     decoding it would print noise. Print its bytes a word at a time instead,
     never past the marker that ends the region, whose address is where the
     next encoding takes over. *)
  let handleDataRegion (ptr: BinFilePointer) =
    let bound =
      match archmodes.TryFindRegionEnd ptr.Addr with
      | Some regionEnd -> int (regionEnd - ptr.Addr)
      | None -> ptr.ReadableAmount
    let len = min DataChunkSize (min bound ptr.ReadableAmount)
    let bytes = hdl.ReadBytes(ptr = ptr, nBytes = len)
    if dumpMode.IsLowUIR then printLowUIR DataStr bytes
    else printRegularDisasm DataStr ptr.Addr bytes
    ptr.Advance len

  let rec binDump isFirst (ptr: BinFilePointer) =
    if ptr.CanReadFileBytes then
      printFuncSymbol isFirst ptr.Addr
      checkAndUpdateArchMode ptr.Addr
      if inData then
        binDump false (handleDataRegion ptr)
      else
        match liftingUnit.TryParseInstruction(ptr = ptr) with
        | Ok(ins) ->
          printInstr ptr ins
          binDump false (ptr.Advance ins.Length)
        | Error _ ->
          binDump false (handleInvalidIns ptr)
    else
      ()

  interface IBinDumper with
    member _.IsThumb
      with get() = liftingUnit.IsThumb
      and set v = liftingUnit.IsThumb <- v

    member _.Dump ptr =
      (* Each dumped region starts as code: a data region never spans one. *)
      inData <- false
      binDump true ptr

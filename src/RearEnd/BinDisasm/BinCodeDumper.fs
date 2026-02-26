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

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter

/// Represents the main code dumper class.
type BinCodeDumper(hdl, isTable, showSymbol, showColor, dumpMode) =

  let [<Literal>] IllegalStr = "(illegal)"

  let wordSize = (hdl: BinHandle).File.ISA.WordSize

  let liftingUnit = hdl.NewLiftingUnit()

  let archmodes =
    let modes = Dictionary() (* Addr to ArchMode *)
    match hdl.File.Format, hdl.File.ISA with
    | FileFormat.ELFBinary, ARM32 ->
      let elf = hdl.File :?> ELFBinFile
      for s in elf.Symbols.StaticSymbols do
        if s.ARMLinkerSymbol <> ELF.ARMLinkerSymbol.None then
          modes[s.Addr] <- s.ARMLinkerSymbol
        else ()
    | _ -> ()
    modes

  let modeSwitch =
    if hdl.File.ISA.Arch = Architecture.ARMv7 then
      liftingUnit.Parser :?> ARM32.IModeSwitchable
    else
      { new ARM32.IModeSwitchable with
          member _.IsThumb with get() = false and set _ = () }

  let fnSymbols =
    if isTable then FunctionSymbols.ofLinkageTable hdl
    else FunctionSymbols.ofText hdl

  let convertToHexStr bytes =
    bytes
    |> Array.fold (fun s (b: byte) ->
      if String.length s = 0 then b.ToString("X2")
      else s + " " + b.ToString("X2")) ""

  let printLowUIR (lowUIRStr: string) bytes =
    let hexStr = convertToHexStr bytes |> String.wrapSqrdBracket
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
      | AsmWordKind.Mnemonic -> cs.Add(Green, word.AsmWordValue) |> ignore
      | AsmWordKind.Variable -> cs.Add(Blue, word.AsmWordValue) |> ignore
      | AsmWordKind.Value -> cs.Add(Red, word.AsmWordValue) |> ignore
      | _ -> cs.Add(NoColor, word.AsmWordValue) |> ignore
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

  let checkAndUpdateArchMode =
    if hdl.File.ISA.Arch = Architecture.ARMv7 then
      fun addr ->
        match archmodes.TryGetValue addr with
        | true, ELF.ARMLinkerSymbol.ARM -> modeSwitch.IsThumb <- false
        | true, ELF.ARMLinkerSymbol.Thumb -> modeSwitch.IsThumb <- true
        | _ -> ()
    else
      fun _addr -> ()

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
      liftingUnit.SetDisassemblySyntax syntax
      liftingUnit.ConfigureDisassembly(false, showSymbol)
      if showColor then colorDisPrinter
      else regularDisPrinter

  let handleInvalidIns ptr =
    let align = liftingUnit.InstructionAlignment
    let bytes = hdl.ReadBytes(ptr = ptr, nBytes = align)
    if dumpMode.IsLowUIR then printLowUIR IllegalStr bytes
    else printRegularDisasm IllegalStr ptr.Addr bytes
    ptr.Advance align

  let rec binDump isFirst (ptr: BinFilePointer) =
    if ptr.IsValid then
      printFuncSymbol isFirst ptr.Addr
      checkAndUpdateArchMode ptr.Addr
      match liftingUnit.TryParseInstruction(ptr = ptr) with
      | Ok(ins) ->
        printInstr ptr ins
        let ptr' = ptr.Advance(ins.Length)
        binDump false ptr'
      | Error _ ->
        let ptr' = handleInvalidIns ptr
        binDump false ptr'
    else ()

  interface IBinDumper with
    member _.ModeSwitch with get() = modeSwitch

    member _.Dump ptr =
      binDump true ptr

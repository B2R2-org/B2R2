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

namespace B2R2.RearEnd.BinDump

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.Logging
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter

/// Represents the main code dumper class.
type BinCodeDumper(hdl, cfg, isTable, showSymbol, showColor, dumpMode) =

  let [<Literal>] IllegalStr = "(illegal)"

  let convertToHexStr bytes =
    bytes
    |> Array.fold (fun s (b: byte) ->
      if String.length s = 0 then b.ToString("X2")
      else s + " " + b.ToString("X2")) ""

  let printLowUIR (lowUIRStr: string) bytes =
    let hexStr = convertToHexStr bytes |> String.wrapSqrdBracket
    Log.COut.PrintRow([ hexStr ])
    Log.COut.PrintRow([ lowUIRStr ])

  let printRegularDisasm disasmStr wordSize addr bytes =
    let hexStr = convertToHexStr bytes
    let addrStr = Addr.toString wordSize addr + ":"
    Log.COut.PrintRow([ addrStr; hexStr; disasmStr ])

  let regularDisPrinter hdl liftingUnit wordSize showSymbs ptr ins =
    (liftingUnit: LiftingUnit).ConfigureDisassembly(false, showSymbs)
    let disasmStr = liftingUnit.DisasmInstruction(ins = ins)
    let bytes = (hdl: BinHandle).ReadBytes(ptr = ptr, nBytes = int ins.Length)
    printRegularDisasm disasmStr wordSize ptr.Addr bytes

  let regularIRPrinter hdl (liftingUnit: LiftingUnit) optimizer ptr ins =
    let stmts = optimizer (liftingUnit.LiftInstruction(ins = ins))
    let lowUIRStr = PrettyPrinter.ToString(lowuirStmts = stmts)
    let bytes = (hdl: BinHandle).ReadBytes(ptr = ptr, nBytes = int ins.Length)
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

  let printColorDisasm words wordSize addr bytes =
    Log.COut.Flush()
    let hexStr = convertToHexStr bytes
    let addrStr = Addr.toString wordSize addr + ":"
    let disasStr = convertToDisasmStr words
    Log.Out.SetTableConfig(cfg = cfg)
    Log.Out.PrintRow([ ColoredString(Green, addrStr)
                       ColoredString(NoColor, hexStr)
                       disasStr ])

  let colorDisPrinter (hdl: BinHandle) liftingUnit wordSize _ ptr ins =
    (liftingUnit: LiftingUnit).ConfigureDisassembly false
    let words = liftingUnit.DecomposeInstruction(ins = ins)
    let bytes = hdl.ReadBytes(ptr = ptr, nBytes = int ins.Length)
    printColorDisasm words wordSize ptr.Addr bytes

  let liftingUnit = (hdl: BinHandle).NewLiftingUnit()

  let makeFunctionSymbolDictionary (hdl: BinHandle) =
    let funcs = Dictionary()
    for addr in hdl.File.GetFunctionAddresses() do
      match hdl.File.TryFindName addr with
      | Ok name -> funcs.TryAdd(addr, name) |> ignore
      | Error _ -> funcs.TryAdd(addr, Addr.toFuncName addr) |> ignore
    for entry in hdl.File.GetLinkageTableEntries() do
      if entry.TrampolineAddress = 0UL then ()
      else funcs.TryAdd(entry.TrampolineAddress, entry.FuncName) |> ignore
    funcs

  let makeLinkageTblSymbolDic (hdl: BinHandle) =
    let funcs = Dictionary()
    for entry in hdl.File.GetLinkageTableEntries() do
      if entry.TrampolineAddress = 0UL then ()
      else funcs.TryAdd(entry.TrampolineAddress, entry.FuncName) |> ignore
    funcs

  let makeArchModeDictionary (hdl: BinHandle) =
    let modes = Dictionary()
    match hdl.File.Format, hdl.File.ISA with
    | FileFormat.ELFBinary, ARM32 ->
      let elf = hdl.File :?> ELFBinFile
      for s in elf.Symbols.StaticSymbols do
        if s.ARMLinkerSymbol <> ELF.ARMLinkerSymbol.None then
          modes[s.Addr] <- s.ARMLinkerSymbol
        else ()
    | _ -> ()
    modes

  let archmodes = makeArchModeDictionary hdl

  let modeSwitch =
    if hdl.File.ISA.Arch = Architecture.ARMv7 then
      liftingUnit.Parser :?> ARM32.IModeSwitchable
    else
      { new ARM32.IModeSwitchable with
          member _.IsThumb with get() = false and set _ = () }

  let updateMode addr =
    match archmodes.TryGetValue addr with
    | true, ELF.ARMLinkerSymbol.ARM -> modeSwitch.IsThumb <- false
    | true, ELF.ARMLinkerSymbol.Thumb -> modeSwitch.IsThumb <- true
    | _ -> ()

  let symbols =
    if isTable then makeLinkageTblSymbolDic hdl
    else makeFunctionSymbolDictionary hdl

  let printFuncSymbol isFirst addr =
    match symbols.TryGetValue(addr) with
    | true, name ->
      if not isFirst then Log.COut.PrintLine() else ()
      Log.COut.PrintLine(String.wrapAngleBracket name)
    | false, _ -> ()

  let wordSize = hdl.File.ISA.WordSize

  let printInstr =
    match dumpMode with
    | LowUIR optimizer -> regularIRPrinter hdl liftingUnit optimizer
    | Disassembly syntax ->
      liftingUnit.SetDisassemblySyntax syntax
      if showColor then colorDisPrinter hdl liftingUnit wordSize showSymbol
      else regularDisPrinter hdl liftingUnit wordSize showSymbol

  let handleInvalidIns ptr =
    let wordSize = hdl.File.ISA.WordSize
    let align = liftingUnit.InstructionAlignment
    let bytes = hdl.ReadBytes(ptr = ptr, nBytes = align)
    if dumpMode.IsLowUIR then printLowUIR IllegalStr bytes
    else printRegularDisasm IllegalStr wordSize ptr.Addr bytes
    ptr.Advance align

  let rec binDump isFirst ptr =
    if (ptr: BinFilePointer).IsValid then
      printFuncSymbol isFirst ptr.Addr
      updateMode ptr.Addr
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
      Log.COut.SetTableConfig(cfg = cfg)
      binDump true ptr

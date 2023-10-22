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

module internal B2R2.RearEnd.BinDump.DisasmLiftHelper

open System.Collections.Generic
open B2R2
open B2R2.BinIR
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter

/// The monotonic console printer.
let internal out = ConsoleCachedPrinter () :> Printer

/// The colorful console printer.
let internal colorout = ConsolePrinter () :> Printer

let [<Literal>] IllegalStr = "(illegal)"

let getOptimizer (opts: BinDumpOpts) =
  match opts.DoOptimization with
  | NoOptimize -> id
  | Optimize -> LocalOptimizer.Optimize

let makeFuncSymbolDic (hdl: BinHandle) =
  let funcs = Dictionary ()
  hdl.File.GetFunctionSymbols ()
  |> Seq.iter (fun s -> funcs.Add (s.Address, s.Name) |> ignore)
  hdl.File.GetFunctionAddresses ()
  |> Seq.iter (fun a ->
    if funcs.ContainsKey a then ()
    else funcs[a] <- Addr.toFuncName a)
  hdl.File.GetLinkageTableEntries ()
  |> Seq.iter (fun e ->
    if e.TrampolineAddress = 0UL then ()
    else funcs.TryAdd (e.TrampolineAddress, e.FuncName) |> ignore)
  funcs

let makeLinkageTblSymbolDic (hdl: BinHandle) =
  let funcs = Dictionary ()
  hdl.File.GetLinkageTableEntries ()
  |> Seq.iter (fun e ->
    if e.TrampolineAddress = 0UL then ()
    else funcs.TryAdd (e.TrampolineAddress, e.FuncName) |> ignore)
  funcs

let makeArchModeDic (hdl: BinHandle) =
  let modes = Dictionary ()
  match hdl.File.Format, hdl.File.ISA.Arch with
  | FileFormat.ELFBinary, Arch.ARMv7
  | FileFormat.ELFBinary, Arch.AARCH32 ->
    hdl.File.GetSymbols ()
    |> Seq.iter (fun s ->
      if s.ArchOperationMode <> ArchOperationMode.NoMode then
        modes[s.Address] <- s.ArchOperationMode
      else ())
  | _ -> ()
  modes

let getInstructionAlignment (isa: ISA) mode =
  match isa.Arch with
  | Arch.IntelX86 | Arch.IntelX64 -> 1
  | Arch.ARMv7 | Arch.AARCH32 ->
    match mode with
    | ArchOperationMode.ThumbMode -> 2
    | _ -> 4
  | Arch.AARCH64 -> 4
  | Arch.MIPS32 | Arch.MIPS64 -> 4
  | Arch.EVM -> 1
  | Arch.AVR -> 2
  | Arch.SH4 -> 2
  | Arch.PPC32 -> 4
  | Arch.RISCV64 -> 2
  | Arch.WASM -> 1
  | Arch.SPARC -> 2
  | _ -> Utils.futureFeature ()

let convertToHexStr bytes =
  bytes
  |> Array.fold (fun s (b: byte) ->
    if String.length s = 0 then b.ToString ("X2")
    else s + " " + b.ToString ("X2")) ""

let printLowUIR (lowUIRStr: string) bytes cfg =
  let hexStr = convertToHexStr bytes |> String.wrapSqrdBracket
  out.PrintRow (false, cfg, [ hexStr ])
  out.PrintRow (false, cfg, [ lowUIRStr ])

let printRegularDisasm disasmStr wordSize addr bytes cfg =
  let hexStr = convertToHexStr bytes
  let addrStr = Addr.toString wordSize addr + ":"
  out.PrintRow (false, cfg, [ addrStr; hexStr; disasmStr ])

let regularDisPrinter hdl wordSize showSymbs ptr (ins: Instruction) cfg =
  let disasmStr = (hdl: BinHandle).DisasmInstr (ins, false, showSymbs)
  let bytes = hdl.ReadBytes (ptr=ptr, nBytes=int ins.Length)
  printRegularDisasm disasmStr wordSize ptr.Addr bytes cfg

let regularIRPrinter (hdl: BinHandle) optimizer ptr ins cfg =
  let stmts = optimizer (hdl.LiftInstr (ins=ins))
  let lowUIRStr = LowUIR.Pp.stmtsToString stmts
  let bytes = hdl.ReadBytes (ptr=ptr, nBytes=int ins.Length)
  printLowUIR lowUIRStr bytes cfg

let convertToDisasmStr (words: AsmWord []) =
  words
  |> Array.choose (fun word ->
    match word.AsmWordKind with
    | AsmWordKind.Address -> None
    | AsmWordKind.Mnemonic -> Some [ Green, word.AsmWordValue ]
    | AsmWordKind.Variable -> Some [ Blue, word.AsmWordValue ]
    | AsmWordKind.Value -> Some [ Red, word.AsmWordValue ]
    | _ -> Some [ NoColor, word.AsmWordValue ])
  |> List.concat

let printColorDisasm words wordSize addr bytes cfg =
  out.Flush ()
  let hexStr = convertToHexStr bytes
  let addrStr = Addr.toString wordSize addr + ":"
  let disasStr = convertToDisasmStr words
  colorout.PrintRow (false, cfg,
    [ [ Green, addrStr ]; [ NoColor, hexStr ]; disasStr ])

let colorDisPrinter (hdl: BinHandle) wordSize _ ptr (ins: Instruction) cfg =
  let words = ins.Decompose (false)
  let bytes = hdl.ReadBytes (ptr=ptr, nBytes=int ins.Length)
  printColorDisasm words wordSize ptr.Addr bytes cfg

let handleInvalidIns (hdl: BinHandle) ptr isLift cfg =
  let wordSize = hdl.File.ISA.WordSize
  let align = getInstructionAlignment hdl.File.ISA hdl.Parser.OperationMode
  let bytes = hdl.ReadBytes (ptr=ptr, nBytes=align)
  if isLift then printLowUIR IllegalStr bytes cfg
  else printRegularDisasm IllegalStr wordSize ptr.Addr bytes cfg
  BinFilePointer.Advance ptr align

let printFuncSymbol (dict: Dictionary<Addr, string>) addr =
  match (dict: Dictionary<Addr, string>).TryGetValue (addr) with
  | true, name ->
    out.PrintLineIfPrevLineWasNotEmpty ()
    out.PrintLine (String.wrapAngleBracket name)
  | false, _ -> ()

let updateMode dict (hdl: BinHandle) addr =
  match (dict: Dictionary<Addr, ArchOperationMode>).TryGetValue addr with
  | true, mode -> hdl.Parser.OperationMode <- mode
  | false, _ -> ()

type ISymbolPrinter =
  abstract member PrintSymbol: Addr -> unit

type IInstrPrinter =
  abstract member PrintInstr: BinHandle -> BinFilePointer -> Instruction -> unit

[<AbstractClass>]
type BinPrinter (hdl, cfg, isLift) =
  abstract member PrintFuncSymbol: Addr -> unit
  abstract member PrintInstr: BinHandle -> BinFilePointer -> Instruction -> unit
  abstract member UpdateMode: BinHandle -> Addr -> unit

  member __.Print ptr =
    if BinFilePointer.IsValid ptr then
      __.PrintFuncSymbol ptr.Addr
      __.UpdateMode hdl ptr.Addr
      match hdl.TryParseInstr (ptr=ptr) with
      | Ok (ins) ->
        __.PrintInstr hdl ptr ins
        let ptr' = BinFilePointer.Advance ptr (int ins.Length)
        __.Print ptr'
      | Error _ ->
        __.Print (handleInvalidIns hdl ptr isLift cfg)
    else ()

[<AbstractClass>]
type BinFuncPrinter (hdl, cfg, isLift) =
  inherit BinPrinter (hdl, cfg, isLift)
  let dict = makeFuncSymbolDic hdl
  override _.PrintFuncSymbol addr = printFuncSymbol dict addr

[<AbstractClass>]
type BinTablePrinter (hdl, cfg, isLift) =
  inherit BinPrinter (hdl, cfg, isLift)
  let dict = makeLinkageTblSymbolDic hdl
  override _.PrintFuncSymbol addr = printFuncSymbol dict addr

type BinCodeDisasmPrinter (hdl, cfg, showSym, showColor) =
  inherit BinFuncPrinter (hdl, cfg, false)
  let wordSize = hdl.File.ISA.WordSize
  let disPrinter = if showColor then colorDisPrinter else regularDisPrinter
  override _.PrintInstr hdl ptr ins =
    disPrinter hdl wordSize showSym ptr ins cfg
  override _.UpdateMode _ _ = ()

type BinCodeIRPrinter (hdl, cfg, optimizer) =
  inherit BinFuncPrinter (hdl, cfg, true)
  override _.PrintInstr hdl ptr ins = regularIRPrinter hdl optimizer ptr ins cfg
  override _.UpdateMode _ _ = ()

type BinTableDisasmPrinter (hdl, cfg) =
  inherit BinTablePrinter (hdl, cfg, false)
  let wordSize = hdl.File.ISA.WordSize
  override _.PrintInstr hdl ptr ins =
    regularDisPrinter hdl wordSize true ptr ins cfg
  override _.UpdateMode _ _ = ()

type BinTableIRPrinter (hdl, cfg, optimizer) =
  inherit BinTablePrinter (hdl, cfg, true)
  override _.PrintInstr hdl ptr ins = regularIRPrinter hdl optimizer ptr ins cfg
  override _.UpdateMode _ _ = ()

type ContextSensitiveCodeDisasmPrinter (hdl, cfg, showSym, showColor) =
  inherit BinFuncPrinter (hdl, cfg, false)
  let wordSize = hdl.File.ISA.WordSize
  let disPrinter = if showColor then colorDisPrinter else regularDisPrinter
  let archmodes = makeArchModeDic hdl
  override _.PrintInstr hdl ptr ins =
    disPrinter hdl wordSize showSym ptr ins cfg
  override _.UpdateMode hdl addr = updateMode archmodes hdl addr

type ContextSensitiveCodeIRPrinter (hdl, cfg, optimizer) =
  inherit BinFuncPrinter (hdl, cfg, true)
  let archmodes = makeArchModeDic hdl
  override _.PrintInstr hdl ptr ins = regularIRPrinter hdl optimizer ptr ins cfg
  override _.UpdateMode hdl addr = updateMode archmodes hdl addr

type ContextSensitiveTableDisasmPrinter (hdl, cfg) =
  inherit BinTablePrinter (hdl, cfg, false)
  let archmodes = makeArchModeDic hdl
  let wordSize = hdl.File.ISA.WordSize
  override _.PrintInstr hdl ptr ins =
    regularDisPrinter hdl wordSize true ptr ins cfg
  override _.UpdateMode hdl addr = updateMode archmodes hdl addr

type ContextSensitiveTableIRPrinter (hdl, cfg, optimizer) =
  inherit BinTablePrinter (hdl, cfg, true)
  let archmodes = makeArchModeDic hdl
  override _.PrintInstr hdl ptr ins = regularIRPrinter hdl optimizer ptr ins cfg
  override _.UpdateMode hdl addr = updateMode archmodes hdl addr

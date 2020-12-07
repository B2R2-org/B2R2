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
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinInterface
open B2R2.RearEnd.StringUtils

/// The monotonic console printer.
let internal out = ConsoleCachedPrinter () :> Printer

/// The colorful console printer.
let internal colorout = ConsolePrinter () :> Printer

let [<Literal>] illegalStr = "(illegal)"

let getOptimizer (opts: BinDumpOpts) =
  match opts.DoOptimization with
  | NoOptimize -> id
  | Optimize -> BinHandle.Optimize

let makeFuncSymbolDic hdl =
  let funcs = Dictionary ()
  hdl.FileInfo.GetFunctionSymbols ()
  |> Seq.iter (fun s -> funcs.Add (s.Address, s.Name) |> ignore)
  hdl.FileInfo.GetFunctionAddresses ()
  |> Seq.iter (fun a ->
    if funcs.ContainsKey a then ()
    else funcs.[a] <- Addr.toFuncName a)
  funcs

let makeLinkageTblSymbolDic hdl =
  let funcs = Dictionary ()
  hdl.FileInfo.GetLinkageTableEntries ()
  |> Seq.iter (fun e ->
    if e.TrampolineAddress = 0UL then ()
    else funcs.TryAdd (e.TrampolineAddress, e.FuncName) |> ignore)
  funcs

let makeArchModeDic hdl =
  let modes = Dictionary ()
  match hdl.FileInfo.FileFormat, hdl.ISA.Arch with
  | FileFormat.ELFBinary, Arch.ARMv7
  | FileFormat.ELFBinary, Arch.AARCH32 ->
    hdl.FileInfo.GetSymbols ()
    |> Seq.iter (fun s ->
      if s.ArchOperationMode <> ArchOperationMode.NoMode then
        modes.[s.Address] <- s.ArchOperationMode
      else ())
  | _ -> ()
  modes

let getInstructionAlignment hdl (ctxt: ParsingContext) =
  match hdl.ISA.Arch with
  | Arch.IntelX86 | Arch.IntelX64 -> 1
  | Arch.ARMv7 | Arch.AARCH32 ->
    match ctxt.ArchOperationMode with
    | ArchOperationMode.ThumbMode -> 2
    | _ -> 4
  | _ -> 4

let convertToHexStr bytes =
  bytes
  |> Array.fold (fun s (b: byte) ->
    if String.length s = 0 then b.ToString ("X2")
    else s + " " + b.ToString ("X2")) ""

let printLowUIR (lowUIRStr: string) bytes cfg =
  let hexStr = convertToHexStr bytes |> wrapSqrdBracket
  out.PrintRow (false, cfg, [ hexStr ])
  out.PrintRow (false, cfg, [ lowUIRStr ])

let printRegularDisasm disasmStr wordSize addr bytes cfg =
  let hexStr = convertToHexStr bytes
  let addrStr = addrToString wordSize addr + ":"
  out.PrintRow (false, cfg, [ addrStr; hexStr; disasmStr ])

let regularDisPrinter (hdl: BinHandle) showSymbs bp ins cfg =
  let disasmStr = BinHandle.DisasmInstr hdl false showSymbs ins
  let wordSize = hdl.FileInfo.WordSize
  let bytes = BinHandle.ReadBytes (hdl, bp=bp, nBytes=int ins.Length)
  printRegularDisasm disasmStr wordSize bp.Addr bytes cfg

let regularIRPrinter (hdl: BinHandle) optimizer bp ins cfg =
  let stmts = optimizer (BinHandle.LiftInstr hdl ins)
  let lowUIRStr = LowUIR.Pp.stmtsToString stmts
  let bytes = BinHandle.ReadBytes (hdl, bp=bp, nBytes=int ins.Length)
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
  let hexStr = convertToHexStr bytes
  let addrStr = addrToString wordSize addr + ":"
  let disasStr = convertToDisasmStr words
  colorout.PrintRow (false, cfg,
    [ [ Green, addrStr ]; [ NoColor, hexStr ]; disasStr ])

let colorDisPrinter (hdl: BinHandle) _ bp (ins: Instruction) cfg =
  let words = ins.Decompose (false)
  let wordSize = hdl.FileInfo.WordSize
  let bytes = BinHandle.ReadBytes (hdl, bp=bp, nBytes=int ins.Length)
  printColorDisasm words wordSize bp.Addr bytes cfg

let handleInvalidIns (hdl: BinHandle) ctxt bp isLift cfg =
  let wordSize = hdl.FileInfo.WordSize
  let align = getInstructionAlignment hdl ctxt
  let bytes = BinHandle.ReadBytes (hdl, bp=bp, nBytes=align)
  if isLift then printLowUIR illegalStr bytes cfg
  else printRegularDisasm illegalStr wordSize bp.Addr bytes cfg
  BinaryPointer.Advance bp align

let printFuncSymbol (dict: Dictionary<Addr, string>) addr =
  match (dict: Dictionary<Addr, string>).TryGetValue (addr) with
  | true, name ->
    out.PrintLineIfPrevLineWasNotEmpty ()
    out.PrintLine (wrapAngleBracket name)
  | false, _ -> ()

let getContext dict (ctxt: ParsingContext) addr =
  match (dict: Dictionary<Addr, ArchOperationMode>).TryGetValue addr with
  | true, mode ->
    if ctxt.ArchOperationMode = mode then ctxt
    else ParsingContext.ARMSwitchOperationMode ctxt
  | false, _ -> ctxt

type ISymbolPrinter =
  abstract member PrintSymbol: Addr -> unit

type IInstrPrinter =
  abstract member PrintInstr: BinHandle -> BinaryPointer -> Instruction -> unit

[<AbstractClass>]
type BinPrinter (hdl, cfg) =
  let mutable ctxt = hdl.DefaultParsingContext

  abstract member PrintFuncSymbol: Addr -> unit
  abstract member PrintInstr: BinHandle -> BinaryPointer -> Instruction -> unit
  abstract member GetContext: ParsingContext -> Addr -> ParsingContext

  member __.Print bp =
    if BinaryPointer.IsValid bp then
      __.PrintFuncSymbol bp.Addr
      ctxt <- __.GetContext ctxt bp.Addr
      match BinHandle.TryParseInstr (hdl, ctxt, bp=bp) with
      | Ok (ins) ->
        __.PrintInstr hdl bp ins
        let bp' = BinaryPointer.Advance bp (int ins.Length)
        __.Print bp'
      | Error _ ->
        __.Print (handleInvalidIns hdl ctxt bp false cfg)
    else ()

[<AbstractClass>]
type BinFuncPrinter (hdl, cfg) =
  inherit BinPrinter (hdl, cfg)
  let dict = makeFuncSymbolDic hdl
  override _.PrintFuncSymbol addr = printFuncSymbol dict addr

[<AbstractClass>]
type BinTablePrinter (hdl, cfg) =
  inherit BinPrinter (hdl, cfg)
  let dict = makeLinkageTblSymbolDic hdl
  override _.PrintFuncSymbol addr = printFuncSymbol dict addr

type BinCodeDisasmPrinter (hdl, cfg, showSym, showColor) =
  inherit BinFuncPrinter (hdl, cfg)
  let disPrinter = if showColor then colorDisPrinter else regularDisPrinter
  override _.PrintInstr hdl bp ins = disPrinter hdl showSym bp ins cfg
  override _.GetContext ctxt _ = ctxt

type BinCodeIRPrinter (hdl, cfg, optimizer) =
  inherit BinFuncPrinter (hdl, cfg)
  override _.PrintInstr hdl bp ins = regularIRPrinter hdl optimizer bp ins cfg
  override _.GetContext ctxt _ = ctxt

type BinTableDisasmPrinter (hdl, cfg) =
  inherit BinTablePrinter (hdl, cfg)
  override _.PrintInstr hdl bp ins = regularDisPrinter hdl true bp ins cfg
  override _.GetContext ctxt _ = ctxt

type BinTableIRPrinter (hdl, cfg, optimizer) =
  inherit BinTablePrinter (hdl, cfg)
  override _.PrintInstr hdl bp ins = regularIRPrinter hdl optimizer bp ins cfg
  override _.GetContext ctxt _ = ctxt

type ContextSensitiveCodeDisasmPrinter (hdl, cfg, showSym, showColor) =
  inherit BinFuncPrinter (hdl, cfg)
  let disPrinter = if showColor then colorDisPrinter else regularDisPrinter
  let archmodes = makeArchModeDic hdl
  override _.PrintInstr hdl bp ins = disPrinter hdl showSym bp ins cfg
  override _.GetContext ctxt addr = getContext archmodes ctxt addr

type ContextSensitiveCodeIRPrinter (hdl, cfg, optimizer) =
  inherit BinFuncPrinter (hdl, cfg)
  let archmodes = makeArchModeDic hdl
  override _.PrintInstr hdl bp ins = regularIRPrinter hdl optimizer bp ins cfg
  override _.GetContext ctxt addr = getContext archmodes ctxt addr

type ContextSensitiveTableDisasmPrinter (hdl, cfg) =
  inherit BinTablePrinter (hdl, cfg)
  let archmodes = makeArchModeDic hdl
  override _.PrintInstr hdl bp ins = regularDisPrinter hdl true bp ins cfg
  override _.GetContext ctxt addr = getContext archmodes ctxt addr

type ContextSensitiveTableIRPrinter (hdl, cfg, optimizer) =
  inherit BinTablePrinter (hdl, cfg)
  let archmodes = makeArchModeDic hdl
  override _.PrintInstr hdl bp ins = regularIRPrinter hdl optimizer bp ins cfg
  override _.GetContext ctxt addr = getContext archmodes ctxt addr

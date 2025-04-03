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
  |> Seq.iter (fun s -> funcs.TryAdd (s.Address, s.Name) |> ignore)
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
  | FileFormat.ELFBinary, Architecture.ARMv7
  | FileFormat.ELFBinary, Architecture.AARCH32 ->
    hdl.File.GetSymbols ()
    |> Seq.iter (fun s ->
      if s.ArchOperationMode <> ArchOperationMode.NoMode then
        modes[s.Address] <- s.ArchOperationMode
      else ())
  | _ -> ()
  modes

let getInstructionAlignment (isa: ISA) mode =
  match isa.Arch with
  | Architecture.IntelX86 | Architecture.IntelX64 -> 1
  | Architecture.ARMv7 | Architecture.AARCH32 ->
    match mode with
    | ArchOperationMode.ThumbMode -> 2
    | _ -> 4
  | Architecture.AARCH64 -> 4
  | Architecture.MIPS32 | Architecture.MIPS64 -> 4
  | Architecture.EVM -> 1
  | Architecture.TMS320C6000 -> 4
  | Architecture.AVR -> 2
  | Architecture.SH4 -> 2
  | Architecture.PPC32 -> 4
  | Architecture.RISCV64 -> 2
  | Architecture.WASM -> 1
  | Architecture.SPARC -> 2
  | Architecture.PARISC | Architecture.PARISC64 -> 4
  | _ -> Terminator.futureFeature ()

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

let regularDisPrinter hdl liftingUnit wordSize showSymbs ptr ins cfg =
  let disasmStr =
    (liftingUnit: LiftingUnit).DisasmInstruction (ins, false, showSymbs)
  let bytes = (hdl: BinHandle).ReadBytes (ptr=ptr, nBytes=int ins.Length)
  printRegularDisasm disasmStr wordSize ptr.Addr bytes cfg

let regularIRPrinter hdl (liftingUnit: LiftingUnit) optimizer ptr ins cfg =
  let stmts = optimizer (liftingUnit.LiftInstruction (ins=ins))
  let lowUIRStr = LowUIR.Pp.stmtsToString stmts
  let bytes = (hdl: BinHandle).ReadBytes (ptr=ptr, nBytes=int ins.Length)
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

let colorDisPrinter (hdl: BinHandle) _ wordSize _ ptr (ins: Instruction) cfg =
  let words = ins.Decompose (false)
  let bytes = hdl.ReadBytes (ptr=ptr, nBytes=int ins.Length)
  printColorDisasm words wordSize ptr.Addr bytes cfg

let handleInvalidIns hdl mode ptr isLift cfg =
  let wordSize = (hdl: BinHandle).File.ISA.WordSize
  let align = getInstructionAlignment hdl.File.ISA mode
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

let updateMode dict (liftingUnit: LiftingUnit) addr =
  match (dict: Dictionary<Addr, ArchOperationMode>).TryGetValue addr with
  | true, mode -> liftingUnit.Parser.OperationMode <- mode
  | false, _ -> ()

[<AbstractClass>]
type BinPrinter (hdl: BinHandle, cfg, isLift) =
  let liftingUnit = hdl.NewLiftingUnit ()

  abstract PrintFuncSymbol: Addr -> unit

  abstract PrintInstr: BinHandle -> BinFilePointer -> Instruction -> unit

  abstract UpdateMode: LiftingUnit -> Addr -> unit

  member __.LiftingUnit with get() = liftingUnit

  member __.Print ptr =
    if BinFilePointer.IsValid ptr then
      __.PrintFuncSymbol ptr.Addr
      __.UpdateMode liftingUnit ptr.Addr
      match liftingUnit.TryParseInstruction (ptr=ptr) with
      | Ok (ins) ->
        __.PrintInstr hdl ptr ins
        let ptr' = BinFilePointer.Advance ptr (int ins.Length)
        __.Print ptr'
      | Error _ ->
        let mode = liftingUnit.Parser.OperationMode
        __.Print (handleInvalidIns hdl mode ptr isLift cfg)
    else ()

[<AbstractClass>]
type BinFuncPrinter (hdl: BinHandle, cfg, isLift) =
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
  override __.PrintInstr hdl ptr ins =
    disPrinter hdl __.LiftingUnit wordSize showSym ptr ins cfg
  override _.UpdateMode _ _ = ()

type BinCodeIRPrinter (hdl, cfg, optimizer) =
  inherit BinFuncPrinter (hdl, cfg, true)
  override __.PrintInstr hdl ptr ins =
    regularIRPrinter hdl __.LiftingUnit optimizer ptr ins cfg
  override _.UpdateMode _ _ = ()

type BinTableDisasmPrinter (hdl, cfg) =
  inherit BinTablePrinter (hdl, cfg, false)
  let wordSize = hdl.File.ISA.WordSize
  override __.PrintInstr hdl ptr ins =
    regularDisPrinter hdl __.LiftingUnit wordSize true ptr ins cfg
  override _.UpdateMode _ _ = ()

type BinTableIRPrinter (hdl, cfg, optimizer) =
  inherit BinTablePrinter (hdl, cfg, true)
  override __.PrintInstr hdl ptr ins =
    regularIRPrinter hdl __.LiftingUnit optimizer ptr ins cfg
  override _.UpdateMode _ _ = ()

type ContextSensitiveCodeDisasmPrinter (hdl, cfg, showSym, showColor) =
  inherit BinFuncPrinter (hdl, cfg, false)
  let wordSize = hdl.File.ISA.WordSize
  let disPrinter = if showColor then colorDisPrinter else regularDisPrinter
  let archmodes = makeArchModeDic hdl
  override __.PrintInstr hdl ptr ins =
    disPrinter hdl __.LiftingUnit wordSize showSym ptr ins cfg
  override _.UpdateMode hdl addr = updateMode archmodes hdl addr

type ContextSensitiveCodeIRPrinter (hdl, cfg, optimizer) =
  inherit BinFuncPrinter (hdl, cfg, true)
  let archmodes = makeArchModeDic hdl
  override __.PrintInstr hdl ptr ins =
    regularIRPrinter hdl __.LiftingUnit optimizer ptr ins cfg
  override _.UpdateMode hdl addr = updateMode archmodes hdl addr

type ContextSensitiveTableDisasmPrinter (hdl, cfg) =
  inherit BinTablePrinter (hdl, cfg, false)
  let archmodes = makeArchModeDic hdl
  let wordSize = hdl.File.ISA.WordSize
  override __.PrintInstr hdl ptr ins =
    regularDisPrinter hdl __.LiftingUnit wordSize true ptr ins cfg
  override _.UpdateMode hdl addr = updateMode archmodes hdl addr

type ContextSensitiveTableIRPrinter (hdl, cfg, optimizer) =
  inherit BinTablePrinter (hdl, cfg, true)
  let archmodes = makeArchModeDic hdl
  override __.PrintInstr hdl ptr ins =
    regularIRPrinter hdl __.LiftingUnit optimizer ptr ins cfg
  override _.UpdateMode hdl addr = updateMode archmodes hdl addr

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
open B2R2.RearEnd.Utils

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
  match hdl.File.Format, hdl.File.ISA with
  | FileFormat.ELFBinary, ARM32 ->
    hdl.File.GetSymbols ()
    |> Seq.iter (fun s ->
      if s.ARMLinkerSymbol <> ARMLinkerSymbol.None then
        modes[s.Address] <- s.ARMLinkerSymbol
      else ())
  | _ -> ()
  modes

let getInstructionAlignment (isa: ISA) isThumb =
  match isa with
  | Intel -> 1
  | ARM32 -> if isThumb then 2 else 4
  | AArch64 -> 4
  | MIPS -> 4
  | EVM -> 1
  | TMS320C6000 -> 4
  | AVR -> 2
  | SH4 -> 2
  | PPC32 -> 4
  | RISCV64 -> 2
  | WASM -> 1
  | SPARC -> 2
  | PARISC -> 4
  | Python -> 1
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
  (liftingUnit: LiftingUnit).ConfigureDisassembly (false, showSymbs)
  let disasmStr = liftingUnit.DisasmInstruction (ins=ins)
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

let colorDisPrinter (hdl: BinHandle) liftingUnit wordSize _ ptr ins cfg =
  (liftingUnit: LiftingUnit).ConfigureDisassembly false
  let words = liftingUnit.DecomposeInstruction (ins=ins)
  let bytes = hdl.ReadBytes (ptr=ptr, nBytes=int ins.Length)
  printColorDisasm words wordSize ptr.Addr bytes cfg

let handleInvalidIns hdl (modeSwitch: ARM32.IModeSwitchable) ptr isLift cfg =
  let wordSize = (hdl: BinHandle).File.ISA.WordSize
  let align = getInstructionAlignment hdl.File.ISA modeSwitch.IsThumb
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

let updateMode dict (modeSwitch: ARM32.IModeSwitchable) addr =
  match (dict: Dictionary<Addr, ARMLinkerSymbol>).TryGetValue addr with
  | true, ARMLinkerSymbol.ARM -> modeSwitch.IsThumb <- false
  | true, ARMLinkerSymbol.Thumb -> modeSwitch.IsThumb <- true
  | _ -> ()

[<AbstractClass>]
type BinPrinter (hdl: BinHandle, cfg, isLift) =
  let liftingUnit = hdl.NewLiftingUnit ()
  let modeSwitch =
    if hdl.File.ISA.Arch = Architecture.ARMv7 then
      liftingUnit.Parser :?> ARM32.IModeSwitchable
    else
      { new ARM32.IModeSwitchable with
          member _.IsThumb with get () = false and set _ = () }

  abstract PrintFuncSymbol: Addr -> unit

  abstract PrintInstr: BinHandle -> BinFilePointer -> IInstruction -> unit

  abstract UpdateMode: LiftingUnit -> Addr -> unit

  member _.LiftingUnit with get () = liftingUnit

  member _.ModeSwitch with get () = modeSwitch

  member this.Print (ptr: BinFilePointer) =
    if ptr.IsValid then
      this.PrintFuncSymbol ptr.Addr
      this.UpdateMode liftingUnit ptr.Addr
      match liftingUnit.TryParseInstruction (ptr=ptr) with
      | Ok (ins) ->
        this.PrintInstr hdl ptr ins
        let ptr' = BinFilePointer.Advance ptr (int ins.Length)
        this.Print ptr'
      | Error _ ->
        this.Print (handleInvalidIns hdl modeSwitch ptr isLift cfg)
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
  override this.PrintInstr hdl ptr ins =
    disPrinter hdl this.LiftingUnit wordSize showSym ptr ins cfg
  override _.UpdateMode _ _ = ()

type BinCodeIRPrinter (hdl, cfg, optimizer) =
  inherit BinFuncPrinter (hdl, cfg, true)
  override this.PrintInstr hdl ptr ins =
    regularIRPrinter hdl this.LiftingUnit optimizer ptr ins cfg
  override _.UpdateMode _ _ = ()

type BinTableDisasmPrinter (hdl, cfg) =
  inherit BinTablePrinter (hdl, cfg, false)
  let wordSize = hdl.File.ISA.WordSize
  override this.PrintInstr hdl ptr ins =
    regularDisPrinter hdl this.LiftingUnit wordSize true ptr ins cfg
  override _.UpdateMode _ _ = ()

type BinTableIRPrinter (hdl, cfg, optimizer) =
  inherit BinTablePrinter (hdl, cfg, true)
  override this.PrintInstr hdl ptr ins =
    regularIRPrinter hdl this.LiftingUnit optimizer ptr ins cfg
  override _.UpdateMode _ _ = ()

type ContextSensitiveCodeDisasmPrinter (hdl, cfg, showSym, showColor) =
  inherit BinFuncPrinter (hdl, cfg, false)
  let wordSize = hdl.File.ISA.WordSize
  let disPrinter = if showColor then colorDisPrinter else regularDisPrinter
  let archmodes = makeArchModeDic hdl
  override this.PrintInstr hdl ptr ins =
    disPrinter hdl this.LiftingUnit wordSize showSym ptr ins cfg
  override _.UpdateMode hdl addr = updateMode archmodes base.ModeSwitch addr

type ContextSensitiveCodeIRPrinter (hdl, cfg, optimizer) =
  inherit BinFuncPrinter (hdl, cfg, true)
  let archmodes = makeArchModeDic hdl
  override this.PrintInstr hdl ptr ins =
    regularIRPrinter hdl this.LiftingUnit optimizer ptr ins cfg
  override _.UpdateMode hdl addr = updateMode archmodes base.ModeSwitch addr

type ContextSensitiveTableDisasmPrinter (hdl, cfg) =
  inherit BinTablePrinter (hdl, cfg, false)
  let archmodes = makeArchModeDic hdl
  let wordSize = hdl.File.ISA.WordSize
  override this.PrintInstr hdl ptr ins =
    regularDisPrinter hdl this.LiftingUnit wordSize true ptr ins cfg
  override _.UpdateMode hdl addr = updateMode archmodes base.ModeSwitch addr

type ContextSensitiveTableIRPrinter (hdl, cfg, optimizer) =
  inherit BinTablePrinter (hdl, cfg, true)
  let archmodes = makeArchModeDic hdl
  override this.PrintInstr hdl ptr ins =
    regularIRPrinter hdl this.LiftingUnit optimizer ptr ins cfg
  override _.UpdateMode hdl addr = updateMode archmodes base.ModeSwitch addr

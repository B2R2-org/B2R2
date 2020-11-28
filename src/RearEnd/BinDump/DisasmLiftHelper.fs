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
open B2R2.RearEnd
open B2R2.RearEnd.StringUtils

let [<Literal>] illegalStr = "(illegal)"

let getOptimizer (opts: BinDumpOpts) =
  match opts.DoOptimization with
  | NoOptimize -> id
  | Optimize -> BinHandle.Optimize

let createFuncSymbolDic hdl =
  let funcs = Dictionary ()
  hdl.FileInfo.GetFunctionSymbols ()
  |> Seq.iter (fun s -> funcs.Add (s.Address, s.Name) |> ignore)
  funcs

let createLinkageTableSymbolDic hdl =
  let funcs = Dictionary ()
  hdl.FileInfo.GetLinkageTableEntries ()
  |> Seq.iter (fun e ->
    if e.TrampolineAddress = 0UL then ()
    else funcs.TryAdd (e.TrampolineAddress, e.FuncName) |> ignore)
  funcs

let getInstructionAlignment hdl =
  match hdl.ISA.Arch with
  | Arch.IntelX86 | Arch.IntelX64 -> 1
  | Arch.ARMv7 | Arch.AARCH32 ->
    match hdl.DefaultParsingContext.ArchOperationMode with
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
  Printer.printrow (false, cfg, [ hexStr ])
  Printer.printrow (false, cfg, [ lowUIRStr ])

let inline printFuncSymbol (symDict: Dictionary<Addr, string>) addr =
  match symDict.TryGetValue (addr) with
  | false, _ -> ()
  | true, name ->
    Printer.println ()
    Printer.println (wrapAngleBracket name)

let printRegularDisasm disasmStr wordSize addr bytes cfg =
  let hexStr = convertToHexStr bytes
  let addrStr = addrToString wordSize addr + ":"
  Printer.printrow (false, cfg, [ addrStr; hexStr; disasmStr ])

let regularDisPrinter (hdl: BinHandle) showSymbs bp ins cfg =
  let disasmStr = BinHandle.DisasmInstr hdl false showSymbs ins
  let wordSize = hdl.FileInfo.WordSize
  let bytes = BinHandle.ReadBytes (hdl, bp=bp, nBytes=int ins.Length)
  printRegularDisasm disasmStr wordSize bp.Addr bytes cfg

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
  Printer.printrow (false, cfg,
    [ [ Green, addrStr ]; [ NoColor, hexStr ]; disasStr ])

let colorDisPrinter (hdl: BinHandle) _ bp (ins: Instruction) cfg =
  let words = ins.Decompose (false)
  let wordSize = hdl.FileInfo.WordSize
  let bytes = BinHandle.ReadBytes (hdl, bp=bp, nBytes=int ins.Length)
  printColorDisasm words wordSize bp.Addr bytes cfg

let handleInvalidIns (hdl: BinHandle) bp isLift cfg =
  let wordSize = hdl.FileInfo.WordSize
  let align = getInstructionAlignment hdl
  let bytes = BinHandle.ReadBytes (hdl, bp=bp, nBytes=align)
  if isLift then printLowUIR illegalStr bytes cfg
  else printRegularDisasm illegalStr wordSize bp.Addr bytes cfg
  BinaryPointer.Advance bp align

let printBlkDisasm hdl cfg (opts: BinDumpOpts) (bp: BinaryPointer) funcs =
  let showSymbs = opts.ShowSymbols
  let align = getInstructionAlignment hdl
  let printer = if opts.ShowColor then colorDisPrinter else regularDisPrinter
  let funcs = Option.defaultWith (fun () -> Dictionary ()) funcs
  let rec loop hdl ctxt bp =
    if BinaryPointer.IsValid bp then
      printFuncSymbol funcs bp.Addr
      match BinHandle.TryParseInstr (hdl, ctxt, bp=bp) with
      | Ok (ins) ->
        printer hdl showSymbs bp ins cfg
        loop hdl ctxt (BinaryPointer.Advance bp (int ins.Length))
      | Error _ -> loop hdl ctxt (handleInvalidIns hdl bp false cfg)
    else ()
  loop hdl hdl.DefaultParsingContext bp

let rec lift hdl cfg optimizer bp = function
  | [] -> bp
  | (ins: Instruction) :: tail ->
    let stmts = optimizer (BinHandle.LiftInstr hdl ins)
    let lowUIRStr = LowUIR.Pp.stmtsToString stmts
    let nBytes = int ins.Length
    let bytes = BinHandle.ReadBytes (hdl, bp=bp, nBytes=nBytes)
    let nextbp = BinaryPointer.Advance bp nBytes
    printLowUIR lowUIRStr bytes cfg
    lift hdl cfg optimizer nextbp tail

let printBlkLowUIR hdl cfg optimizer (bp: BinaryPointer) =
  let rec loop hdl ctxt bp =
    if BinaryPointer.IsValid bp then
      match BinHandle.ParseBBlock (hdl, ctxt, bp=bp) with
      | Ok (bbl, _) ->
        loop hdl ctxt (lift hdl cfg optimizer bp bbl)
      | Error bbl ->
        let nextbp = lift hdl cfg optimizer bp bbl
        if nextbp.Offset < bp.MaxOffset then
          loop hdl ctxt (handleInvalidIns hdl nextbp true cfg)
  loop hdl hdl.DefaultParsingContext bp

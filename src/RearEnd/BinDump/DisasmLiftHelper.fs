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
  let hexStr = convertToHexStr bytes |> wrapSqrdBrac
  Printer.printrow (false, cfg, [ hexStr ])
  Printer.printrow (false, cfg, [ lowUIRStr ])

let printRegularDisasm disasmStr wordSize addr bytes cfg =
  let hexStr = convertToHexStr bytes
  let addrStr = addrToString wordSize addr + ":"
  Printer.printrow (false, cfg, [ addrStr; hexStr; disasmStr ])

let rec regularDisPrinter (hdl: BinHandle) showSymbs addr bbl cfg =
  match bbl with
  | [] -> addr
  | (ins: Instruction) :: tail ->
    let disasmStr = BinHandle.DisasmInstr hdl false showSymbs ins
    let wordSize = hdl.FileInfo.WordSize
    let bytes = BinHandle.ReadBytes (hdl, ins.Address, int ins.Length)
    let nextAddr = ins.Address + uint64 ins.Length
    printRegularDisasm disasmStr wordSize addr bytes cfg
    regularDisPrinter hdl showSymbs nextAddr tail cfg

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

let rec colorDisPrinter (hdl: BinHandle) showSymbs addr bbl cfg =
  match bbl with
  | [] -> addr
  | (ins: Instruction) :: tail ->
    let words = ins.Decompose (false)
    let wordSize = hdl.FileInfo.WordSize
    let bytes = BinHandle.ReadBytes (hdl, ins.Address, int ins.Length)
    let nextAddr = ins.Address + uint64 ins.Length
    printColorDisasm words wordSize addr bytes cfg
    colorDisPrinter hdl showSymbs nextAddr tail cfg

let handleInvalidIns (hdl: BinHandle) addr isLift cfg =
  let wordSize = hdl.FileInfo.WordSize
  let align = getInstructionAlignment hdl
  let bytes = BinHandle.ReadBytes (hdl, addr, align)
  if isLift then printLowUIR illegalStr bytes cfg
  else printRegularDisasm illegalStr wordSize addr bytes cfg
  addr + uint64 align

let inline printSymbol (funcs: Dictionary<Addr, string>) addr =
  match funcs.TryGetValue (addr) with
  | false, _ -> ()
  | true, name -> Printer.println (wrapSqrdBrac name)

let printBlkDisasm hdl cfg (opts: BinDumpOpts) (addrRange: AddrRange) =
  let showSymbs = opts.ShowSymbols
  let printer = if opts.ShowColor then colorDisPrinter else regularDisPrinter
  let funcs = Dictionary ()
  hdl.FileInfo.GetFunctionSymbols ()
  |> Seq.iter (fun s -> funcs.Add (s.Address, s.Name) |> ignore)
  let rec loop hdl ctxt addr =
    if addr < addrRange.Max then
      printSymbol funcs addr
      match BinHandle.ParseBBlock hdl ctxt addr with
      | Ok (bbl, _) ->
        loop hdl ctxt (printer hdl showSymbs addr bbl cfg)
      | Error bbl ->
        let nextAddr = printer hdl showSymbs addr bbl cfg
        if nextAddr < addrRange.Max then
          loop hdl ctxt (handleInvalidIns hdl nextAddr false cfg)
  loop hdl hdl.DefaultParsingContext addrRange.Min

let rec lift hdl cfg optimizer addr = function
  | [] -> addr
  | (ins: Instruction) :: tail ->
    let stmts = optimizer (BinHandle.LiftInstr hdl ins)
    let lowUIRStr = LowUIR.Pp.stmtsToString stmts
    let bytes = BinHandle.ReadBytes (hdl, ins.Address, int ins.Length)
    let nextAddr = ins.Address + uint64 ins.Length
    printLowUIR lowUIRStr bytes cfg
    lift hdl cfg optimizer nextAddr tail

let printBlkLowUIR hdl cfg optimizer (addrRange: AddrRange) =
  let rec loop hdl ctxt addr =
    if addr < addrRange.Max then
      match BinHandle.ParseBBlock hdl ctxt addr with
      | Ok (bbl, _) ->
        loop hdl ctxt (lift hdl cfg optimizer addr bbl)
      | Error bbl ->
        let nextAddr = lift hdl cfg optimizer addr bbl
        if nextAddr < addrRange.Max then
          loop hdl ctxt (handleInvalidIns hdl nextAddr true cfg)
  loop hdl hdl.DefaultParsingContext addrRange.Min

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

module B2R2.RearEnd.BinDump.DisasmLiftHelper

open B2R2
open B2R2.BinIR
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinInterface
open B2R2.RearEnd

let addrToString size addr = Addr.toString size addr

let bytesToHexStr addSpace addBracket (bytes: byte []) =
  let hexStr =
    Array.fold (fun hexStr (b: byte) ->
    if addSpace then hexStr + " " + b.ToString ("X2")
    else hexStr + b.ToString ("X2")) "" bytes
  if addBracket then "[" + hexStr + "]" else hexStr

let printSymbol (hdl: BinHandle) addr =
  match hdl.FileInfo with
  | :? ELFFileInfo as fi ->
    match fi.ELF.SymInfo.AddrToSymbTable.TryFind addr with
    | Some sym ->
      if sym.SymType = ELF.SymbolType.STTFunc && sym.SymName <> "" then
        Printer.println ""
        let isPltFunc =
          match fi.ELF.SecInfo.SecByName.TryFind ".plt" with
          | Some plt ->
            addr >= plt.SecAddr && addr <= (plt.SecAddr + plt.SecSize)
          | None -> false
        if isPltFunc then
          Printer.println
            [ ColoredSegment.yellow ("[" + sym.SymName + "@plt]") ]
        else
          Printer.println
            [ ColoredSegment.yellow ("[" + sym.SymName + "]") ]
    | None -> ()
  | :? PEFileInfo as fi ->
    match fi.PE.SymbolInfo.SymbolByAddr.TryFind addr with
    | Some sym ->
      if sym.Flags = PE.SymFlags.Function && sym.Name <> "" then
        Printer.println ""
        [ ColoredSegment.yellow ("[" + sym.Name + "]") ] |> Printer.println
    | None -> ()
  | :? MachFileInfo as fi ->
    match fi.Mach.SymInfo.SymbolMap.TryFind addr with
    | Some sym ->
      if sym.SymType = Mach.SymbolType.NFun && sym.SymName <> "" then
        Printer.println ""
        [ ColoredSegment.yellow ("[" + sym.SymName + "]") ] |> Printer.println
    | None -> ()
  | _ -> ()

let printLowUIR lowUIRStr bytesList =
  let hexStr =
    List.foldBack (fun bytes hexStr ->
      hexStr + (bytesToHexStr false true bytes)) bytesList ""
  let cfg = [ LeftAligned 10 ]
  if hexStr <> "" then
    Printer.printrow false cfg [ hexStr ]
  Printer.printrow false cfg [ lowUIRStr ]

let printDisasm disasmStr showAddr wordSize addr bytesList addSpace =
  let addrSize =
    if wordSize = WordSize.Bit32 then 8 else 16
  let hexStr =
    List.foldBack (fun bytes hexStr->
      hexStr + " " + (bytesToHexStr addSpace false bytes)) bytesList ""
  if hexStr <> "" then
    if showAddr then
      let cfg = [ LeftAligned addrSize; LeftAligned 32; LeftAligned 10 ]
      let addrStr = addrToString wordSize addr + ":"
      Printer.printrow false cfg [ addrStr; hexStr; disasmStr]
    else
      let cfg = [ LeftAligned 32; LeftAligned 10 ]
      Printer.printrow false cfg [ hexStr; disasmStr]
  else
    if showAddr then
      let cfg = [ LeftAligned addrSize; LeftAligned 10 ]
      let addrStr = addrToString wordSize addr + ":"
      Printer.printrow false cfg [ addrStr; disasmStr ]
    else
      let cfg = [ LeftAligned 10 ]
      Printer.printrow false cfg [ disasmStr ]

let rearrangeInsBytes hdl insLen offset =
  let isRev = hdl.ISA.Endian = Endian.Little
  let insLen', isRev, addSpace =
    match hdl.ISA.Arch with
    | Arch.IntelX86 | Arch.IntelX64 ->
      if insLen = 0 then 1, false, true else insLen, false, true
    | Arch.ARMv7 ->
      match hdl.DefaultParsingContext.ArchOperationMode with
      | ArchOperationMode.ARMMode -> 4, isRev, false
      | ArchOperationMode.ThumbMode -> 2, isRev, false
      | _ -> 4, isRev, false
    | Arch.AARCH32 | Arch.AARCH64 -> 4, isRev, false
    | _ -> 4, false, false
  let checkLen = if insLen = 0 then insLen' else insLen
  let rec loop checkLen offset acc =
    if checkLen <= 0 then acc
    else
      let bytes = hdl.FileInfo.BinReader.PeekBytes (int insLen', offset)
      let bytes = if isRev then Array.rev bytes else bytes
      loop (checkLen - insLen') (offset + insLen') (bytes :: acc)
  loop checkLen offset [], insLen', addSpace

let rec disasm (hdl: BinHandle) showAddr showSymbs addr bbl =
  match bbl with
  | [] -> addr
  | (ins: Instruction) :: tail ->
    printSymbol hdl addr
    let disasmStr = BinHandle.DisasmInstr hdl false showSymbs ins
    let wordSize = hdl.FileInfo.WordSize
    let offset = hdl.FileInfo.TranslateAddress ins.Address
    let bytesList, _, addSpace = rearrangeInsBytes hdl (int ins.Length) offset
    let nextAddr = ins.Address + uint64 ins.Length
    printDisasm disasmStr showAddr wordSize addr bytesList addSpace
    disasm hdl showAddr showSymbs nextAddr tail

let handleInvalidIns (hdl: BinHandle) showAddr addr isLift =
  let wordSize = hdl.FileInfo.WordSize
  let offset = hdl.FileInfo.TranslateAddress addr
  let bytesList, insLen', addSpace = rearrangeInsBytes hdl 0 offset
  if isLift then printLowUIR "(illegal)" bytesList
  else printDisasm "(illegal)" showAddr wordSize addr bytesList addSpace
  addr + uint64 insLen'

let printBlkDisasm hdl (opts: BinDumpOpts) (addrRange: AddrRange) =
  let showAddr = opts.ShowAddress
  let showSymbs = opts.ShowSymbols
  let rec loop hdl ctxt addr =
    if addr < addrRange.Max then
      match BinHandle.ParseBBlock hdl ctxt addr with
      | Ok (bbl, _) ->
        loop hdl ctxt (disasm hdl showAddr showSymbs addr bbl)
      | Error bbl ->
        let nextAddr = disasm hdl showAddr showSymbs addr bbl
        if nextAddr < addrRange.Max then
          loop hdl ctxt (handleInvalidIns hdl showAddr nextAddr false)
  loop hdl hdl.DefaultParsingContext addrRange.Min

let rec lift hdl optimizer addr bbl =
  match bbl with
  | [] -> addr
  | (ins: Instruction) :: tail ->
    printSymbol hdl addr
    let stmts = optimizer (BinHandle.LiftInstr hdl ins)
    let lowUIRStr = LowUIR.Pp.stmtsToString stmts
    let offset = hdl.FileInfo.TranslateAddress ins.Address
    let bytesList, _, _ = rearrangeInsBytes hdl (int ins.Length) offset
    let nextAddr = ins.Address + uint64 ins.Length
    printLowUIR lowUIRStr bytesList
    lift hdl optimizer nextAddr tail

let printBlkLowUIR hdl (opts: BinDumpOpts) (addrRange: AddrRange) =
  let optimizer =
    match opts.DoOptimization with
    | NoOpt -> (fun x -> x)
    | Opt -> (BinHandle.Optimize)
    | OptPar -> Utils.futureFeature ()
  let rec loop hdl ctxt addr =
    if addr < addrRange.Max then
      match BinHandle.ParseBBlock hdl ctxt addr with
      | Ok (bbl, _) ->
        loop hdl ctxt (lift hdl optimizer addr bbl)
      | Error bbl ->
        let nextAddr = lift hdl optimizer addr bbl
        if nextAddr < addrRange.Max then
          loop hdl ctxt (handleInvalidIns hdl false nextAddr true)
  loop hdl hdl.DefaultParsingContext addrRange.Min

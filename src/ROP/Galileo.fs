(*
  B2R2 - the Next-Generation Reversing Platform

  Author: HyungSeok Han <hyungseok.han@kaist.ac.kr>

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

module B2R2.ROP.Galileo

open B2R2
open B2R2.BinFile
open B2R2.FrontEnd
open B2R2.BinIR.LowUIR

let filter = function
  | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ -> false
  | _ -> true

let inline updateGadgets cur pre ins gadgets =
  match Map.tryFind pre gadgets with
  | Some pGadget ->
    let g = { Instrs = ins :: pGadget.Instrs
              Offset = cur
              PreOff = pre }
    Map.add cur g gadgets, true
  | _ -> gadgets, false

let private toTail isa bytes =
  let hdl = BinHandler.Init (isa, bytes=bytes)
  let lastAddr = Array.length bytes |> uint64
  let rec parseInstrs acc addr =
    if lastAddr > addr then
      let ins = BinHandler.ParseInstr hdl addr
      parseInstrs (ins :: acc) (addr + uint64 ins.Length)
    else List.rev acc
  { Pattern = bytes
    TailInstrs = parseInstrs [] 0UL }

let getTailPatterns hdl =
  match hdl.ISA.Arch, hdl.ISA.Endian with
  | Arch.IntelX86, Endian.Little ->
    [ [| 0xC3uy |] (* RET *)
      [| 0xCDuy; 0x80uy |] (* INT 0x80 *)
      [| 0xCDuy; 0x80uy; 0xC3uy |] (* INT 0x80; RET *) ]
  | Arch.IntelX64, Endian.Little ->
    [ [| 0xC3uy |] (* RET *)
      [| 0x0Fuy; 0x05uy |] (* SYSCALL *)
      [| 0x0Fuy; 0x05uy; 0xC3uy |] (* SYSCALL; RET *) ]
  | _ -> failwith "Unsupported arch."
  |> List.map (toTail hdl.ISA)

let private getExecutableSegs hdl =
  let fi = hdl.FileInfo
  let rxRanges =
    fi.GetSegments (Permission.Readable ||| Permission.Executable)
  if not fi.IsNXEnabled then
    fi.GetSegments (Permission.Readable)
    |> Seq.append rxRanges
    |> Seq.distinct
  else
    rxRanges

let getNext minaddr cur (ins: Instruction) last map =
  let pre = cur + (uint64 ins.Length)
  if ins.IsExit () then
    if pre < last then (minaddr - 1UL, last, map)
    else (cur - 1UL, last, map)
  else
    match updateGadgets cur pre ins map with
    | map, true -> (cur - 1UL, cur, map)
    | map, false -> (cur - 1UL, last, map)

let rec addBackward hdl minaddr cur last map =
  if cur < minaddr || (cur + 1UL) = 0UL then map
  else
    match BinHandler.TryParseInstr hdl cur with
    | Some ins ->
      getNext minaddr cur ins last map |||> addBackward hdl minaddr
    | None -> addBackward hdl minaddr (cur - 1UL) last map

let private buildGadgetMapFromSeg hdl (tail: Tail) map (seg: Segment) =
  let minaddr = seg.Address
  let folder map idx =
    let sGadget = Gadget.create idx tail
    Map.add idx sGadget map
    |> addBackward hdl minaddr (idx - 1UL) idx
  BinHandler.ReadBytes (hdl, seg.Address, int (seg.Size))
  |> ByteArray.findIdxs minaddr tail.Pattern
  |> List.fold folder map

let findGadgets hdl =
  let executableSegs = getExecutableSegs hdl
  let buildGadgetMapPerTail acc tail =
    executableSegs |> Seq.fold (buildGadgetMapFromSeg hdl tail) acc
  getTailPatterns hdl
  |> List.fold buildGadgetMapPerTail GadgetMap.empty

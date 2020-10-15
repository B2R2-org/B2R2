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

module B2R2.RearEnd.ROP.Galileo

open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.FrontEnd.BinInterface
open B2R2.BinIR.LowUIR

let filter = function
  | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ -> false
  | _ -> true

let private toTail bytes = { Pattern = bytes }

let private instrMaxLen hdl =
  match hdl.ISA.Arch with
  | Arch.IntelX86 | Arch.IntelX64 -> 15UL
  | Arch.AARCH32 | Arch.AARCH64 | Arch.ARMv7 -> 4UL
  | _ -> raise InvalidISAException

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
  |> List.map toTail

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

let inline updateGadgets curAddr nextAddr ins gadgets =
  match Map.tryFind nextAddr gadgets with
  | Some pGadget ->
    let g = { Instrs = ins :: pGadget.Instrs
              Offset = curAddr
              NextOff = nextAddr }
    Map.add curAddr g gadgets |> Some
  | _ -> None

let rec buildBackward hdl minAddr curAddr lastAddr map =
  if curAddr < minAddr || (curAddr + 1UL) = 0UL then map
  else
    match BinHandle.TryParseInstr hdl hdl.DefaultParsingContext curAddr with
    | Ok ins ->
      let nextAddr = curAddr + (uint64 ins.Length)
      if ins.IsExit () then
        if nextAddr < lastAddr then map
        else buildBackward hdl minAddr (curAddr - 1UL) lastAddr map
      else
        match updateGadgets curAddr nextAddr ins map with
        | Some map ->
          let minAddr' = curAddr - instrMaxLen hdl
          buildBackward hdl minAddr' (curAddr - 1UL) curAddr map
        | None -> buildBackward hdl minAddr (curAddr - 1UL) lastAddr map
    | Error _ -> buildBackward hdl minAddr (curAddr - 1UL) lastAddr map

let parseTail hdl addr bytes =
  let lastAddr = (Array.length bytes |> uint64) + addr
  let rec parseLoop acc addr =
    if lastAddr > addr then
      let ins = BinHandle.ParseInstr hdl hdl.DefaultParsingContext addr
      parseLoop (ins :: acc) (addr + uint64 ins.Length)
    else List.rev acc
  parseLoop [] addr

let private buildGadgetMap hdl (tail: Tail) map (seg: Segment) =
  let minAddr = seg.Address
  let build map idx =
    let sGadget = parseTail hdl idx tail.Pattern |> Gadget.create idx
    Map.add idx sGadget map
    |> buildBackward hdl (min 0UL (minAddr - instrMaxLen hdl)) (idx - 1UL) idx
  BinHandle.ReadBytes (hdl, seg.Address, int (seg.Size))
  |> ByteArray.findIdxs minAddr tail.Pattern
  |> List.fold build map

let findGadgets hdl =
  let segs = getExecutableSegs hdl
  let buildGadgetMapPerTail acc tail =
    Seq.fold (buildGadgetMap hdl tail) acc segs
  getTailPatterns hdl
  |> List.fold buildGadgetMapPerTail GadgetMap.empty

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
open B2R2.FrontEnd
open B2R2.FrontEnd.BinFile
open B2R2.BinIR.LowUIR

let filter = function
  | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ -> false
  | _ -> true

let private toTail bytes = { Pattern = bytes }

let private instrMaxLen (liftingUnit: LiftingUnit) =
  match liftingUnit.File.ISA with
  | Intel -> 15UL
  | ARMv7 | AArch64 -> 4UL
  | _ -> raise InvalidISAException

let getTailPatterns (liftingUnit: LiftingUnit) =
  match liftingUnit.File.ISA with
  | X86 ->
    [ [| 0xC3uy |] (* RET *)
      [| 0xCDuy; 0x80uy |] (* INT 0x80 *)
      [| 0xCDuy; 0x80uy; 0xC3uy |] (* INT 0x80; RET *) ]
  | X64 ->
    [ [| 0xC3uy |] (* RET *)
      [| 0x0Fuy; 0x05uy |] (* SYSCALL *)
      [| 0x0Fuy; 0x05uy; 0xC3uy |] (* SYSCALL; RET *) ]
  | _ -> failwith "Unsupported arch."
  |> List.map toTail

let private getExecutableSegs (liftingUnit: LiftingUnit) =
  let file = liftingUnit.File
  let rxRanges =
    file.GetSegments (Permission.Readable ||| Permission.Executable)
  if not file.IsNXEnabled then
    file.GetSegments (Permission.Readable)
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

let rec buildBackward (liftingUnit: LiftingUnit) minAddr curAddr lastAddr map =
  if curAddr < minAddr || (curAddr + 1UL) = 0UL then map
  else
    match liftingUnit.TryParseInstruction curAddr with
    | Ok ins ->
      let nextAddr = curAddr + (uint64 ins.Length)
      if ins.IsTerminator () then
        if nextAddr < lastAddr then map
        else buildBackward liftingUnit minAddr (curAddr - 1UL) lastAddr map
      else
        match updateGadgets curAddr nextAddr ins map with
        | Some map ->
          let minAddr' = curAddr - instrMaxLen liftingUnit
          buildBackward liftingUnit minAddr' (curAddr - 1UL) curAddr map
        | None -> buildBackward liftingUnit minAddr (curAddr - 1UL) lastAddr map
    | Error _ -> buildBackward liftingUnit minAddr (curAddr - 1UL) lastAddr map

let parseTail (liftingUnit: LiftingUnit) addr bytes =
  let lastAddr = (Array.length bytes |> uint64) + addr
  let rec parseLoop acc addr =
    if lastAddr > addr then
      let ins = liftingUnit.ParseInstruction addr
      parseLoop (ins :: acc) (addr + uint64 ins.Length)
    else List.rev acc
  parseLoop [] addr

let private buildGadgetMap hdl (liftingUnit: LiftingUnit) tail map seg =
  let minAddr = (seg: Segment).Address
  let build map idx =
    let sGadget = parseTail liftingUnit idx tail.Pattern |> Gadget.create idx
    Map.add idx sGadget map
    |> buildBackward liftingUnit
                     (min 0UL (minAddr - instrMaxLen liftingUnit))
                     (idx - 1UL)
                     idx
  (hdl: BinHandle).ReadBytes (seg.Address, int (seg.Size))
  |> ByteArray.findIdxs minAddr tail.Pattern
  |> List.fold build map

let findGadgets (hdl: BinHandle) =
  let liftingUnit = hdl.NewLiftingUnit ()
  let segs = getExecutableSegs liftingUnit
  let buildGadgetMapPerTail acc tail =
    Seq.fold (buildGadgetMap hdl liftingUnit tail) acc segs
  getTailPatterns liftingUnit
  |> List.fold buildGadgetMapPerTail GadgetMap.empty

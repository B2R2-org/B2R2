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
open B2R2.ByteArray
open B2R2.BinFile
open B2R2.FrontEnd
open B2R2.BinIR.LowUIR

let inline addGadget offset gadget gadgets = Map.add offset gadget gadgets

let inline initGadget idx (tail: Tail) = {
  Instrs = tail.Instrs
  IRs    = tail.IRs
  Offset = idx
  PreOff = idx
}

let filter = function
  | Jmp _ | CJmp _ | InterJmp _ | InterCJmp _ -> false
  | _ -> true

let inline tryLift hdl ins =
  try
    let stmts = BinHandler.LiftInstr hdl ins
    if Array.forall filter stmts then Some stmts
    else None
  with
  | _ -> None

let inline updateGadgets hdl cur pre ins gadgets =
  match Map.tryFind pre gadgets, tryLift hdl ins with
  | Some pGadget, Some stmts ->
    let g = { Instrs = ins :: pGadget.Instrs
              IRs = Array.append stmts pGadget.IRs
              Offset = cur
              PreOff = pre }
    addGadget cur g gadgets, true
  | _, _ -> gadgets, false

let private toTail isa bytes =
  let hdl = BinHandler.Init (isa, bytes=bytes)
  let lastAddr = Array.length bytes |> uint64
  let rec parseLoop acc addr =
    if lastAddr > addr then
      let ins = BinHandler.ParseInstr hdl addr
      parseLoop (ins :: acc) (addr + uint64 ins.Length)
    else
      let instrs = List.rev acc
      let irs =
        List.fold (fun acc ins -> BinHandler.LiftInstr hdl ins
                                  |> Array.append acc)
                  [||] instrs
      { Instrs = instrs; Pattern = bytes; IRs = irs }
  parseLoop [] 0UL

let getTailPatterns hdl =
  match hdl.ISA.Arch, hdl.ISA.Endian with
  | Arch.IntelX86, Endian.Little ->
    [ [| 0xC3uy |]; [| 0xCDuy; 0x80uy |]; [| 0xCDuy; 0x80uy; 0xC3uy |] ]
  | Arch.IntelX64, Endian.Little ->
    [ [| 0xC3uy |]; [| 0x0Fuy; 0x05uy |]; [| 0x0Fuy; 0x05uy; 0xC3uy |] ]
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

let private findInRange hdl (tail: Tail) acc (seg: Segment) =
  let min = seg.Address
  let bytes = BinHandler.ReadBytes (hdl, seg.Address, int (seg.Size))
  let getNext cur (ins: Instruction) last acc =
    let pre = cur + (uint64 ins.Length)
    if ins.IsExit () then
      if pre < last then (min - 1UL, last, acc)
      else (cur - 1UL, last, acc)
    else
      match updateGadgets hdl cur pre ins acc with
      | acc, true -> (cur - 1UL, cur, acc)
      | acc, false -> (cur - 1UL, last, acc)
  let rec getGadgets cur last acc =
    if cur < min || (cur + 1UL) = 0UL then acc
    else
      match BinHandler.TryParseInstr hdl cur with
      | Some ins -> getNext cur ins last acc |||> getGadgets
      | None -> getGadgets (cur - 1UL) last acc
  let folder acc idx =
    let sGadget = initGadget idx tail
    addGadget idx sGadget acc |> getGadgets (idx - 1UL) idx
  findIdxs min tail.Pattern bytes |> List.fold folder acc

let findGadgets hdl =
  let executableSegs = getExecutableSegs hdl
  let folder acc tail =
    Seq.fold (findInRange hdl tail) acc executableSegs
  getTailPatterns hdl |> List.fold folder GadgetMap.empty

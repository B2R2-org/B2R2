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

module B2R2.Assembler.Intel.FixInsInfo

open System
open System.Text
open B2R2
open B2R2.FrontEnd
open B2R2.FrontEnd.Intel
open B2R2.Assembler.Intel.AsmOpcode

type AssemblyInfo = {
  Index         : int
  PC            : Addr
  ByteStr       : string
  LabeledBytes  : LabeledByte []
  Label         : string option
}

let encodeInstruction isa ins =
  match ins.Opcode with
  | Opcode.AAA -> aaa isa.Arch ins.Operands
  | Opcode.AAD -> aad isa.Arch ins.Operands
  | Opcode.AAM -> aam isa.Arch ins.Operands
  | Opcode.AAS -> aas isa.Arch ins.Operands
  | Opcode.ADC -> adc isa.Arch ins
  | Opcode.ADD -> add isa.Arch ins
  | Opcode.MOV -> mov isa.Arch ins
  | Opcode.PALIGNR -> palignr isa.Arch ins
  | Opcode.VPALIGNR -> vpalignr isa.Arch ins
  | _ -> Utils.futureFeature ()

let private getValue enBytes (sb: StringBuilder) =
  Array.rev enBytes
  |> Array.fold (fun acc byte ->
    match byte with
    | Normal b -> b.ToString("X2") + acc
    | Label -> "00" + acc)"" // FIXME: assumed (32bit)
  |> sb.Append

let private getValue2 enBytes =
  Array.rev enBytes
  |> Array.fold (fun acc byte ->
    match byte with
    | Normal b -> b.ToString("X2") + acc
    | Label -> "00" + acc)"" // FIXME: assumed (32bit)

let private eByteCodeToStr (eIns: EncodedByteCode) =
  let sb = StringBuilder ()
  getValue eIns.Prefix sb
  |> getValue eIns.REXPrefix
  |> getValue eIns.Opcode
  |> getValue eIns.ModRM
  |> getValue eIns.SIB
  |> getValue eIns.Displacement
  |> getValue eIns.Immediate
  |> (fun sb -> sb.ToString ())

let rec updatePC acc addr = function
  | [] -> acc |> List.rev
  | (i, len, b, e) :: t -> updatePC ((i, addr, b, e) :: acc) (addr + len) t

let private findPC idx pcMap =
  match Map.tryFind idx pcMap with
  | Some pc -> pc
  | None -> 0xffffffffUL // -1

let private disassembly (isa: ISA) addr bCode =
  let handler = BinHandler.Init (isa, ByteArray.ofHexString bCode)
  let ins = BinHandler.ParseInstr handler 0UL
  printfn "%-4x: %-20s     %s" addr bCode (ins.Disasm ())

let private parseAsmInfo idx pc byteStr lblBytes operands =
  let label =
    match operands with
    | OneOperand (GoToLabel str) -> Some str
    | _ -> None
  {
    Index = idx
    PC = pc
    ByteStr = byteStr
    LabeledBytes = lblBytes
    Label = label
  }

let private getDispBytes addr (asmInfo: AssemblyInfo) =
  let opByte = [| asmInfo.LabeledBytes.[0] |]
  let dispBytes =
    (int32 addr) - (int32 asmInfo.PC + (String.length asmInfo.ByteStr / 2))
    |> BitConverter.GetBytes |> Array.map Normal // FIXME: assumed (int32)
  Array.append opByte dispBytes

let private getLabeledBytes str asmInfo lbls =
  match Map.tryFind str lbls with
  | Some addr -> getDispBytes addr asmInfo
  | None -> Utils.impossible ()

let private updateByteStr lblBytes =
  Array.fold (fun acc lblByte ->
    match lblByte with
    | Normal byte -> byte.ToString ("X2") + acc
    | _ -> Utils.impossible ()) "" (lblBytes |> Array.rev)

let private updateByteCodeAndStr str lbls asmInfo =
  let lblBytes = getLabeledBytes str asmInfo lbls
  let byteStr = updateByteStr lblBytes
  { asmInfo with LabeledBytes = lblBytes; ByteStr = byteStr }

let private updateLabeledByte lbls (asmInfo: AssemblyInfo) =
  match asmInfo.Label with
  | Some str -> updateByteCodeAndStr str lbls asmInfo
  | None -> asmInfo

let private updateLabeledInstr ins encodedInfo lbls =
  List.map2 (fun (idx, pc, bStr, eInfo) ins ->
    parseAsmInfo idx pc bStr eInfo ins.Operands
    |> updateLabeledByte lbls) encodedInfo ins

// KILL THIS
let private prettyPrint isa asmInfos lbls =
  printfn ""
  printfn "<Assembly>"
  List.fold (fun acc asmInfo -> asmInfo.ByteStr + acc) "" (asmInfos |> List.rev)
  |> printfn "%s"
  printfn ""
  printfn "<Disassembly>"
  List.iter (fun asmInfo -> disassembly isa asmInfo.PC asmInfo.ByteStr) asmInfos
  printfn ""
  printfn "<Label>"
  Map.iter (fun lbl addr -> printfn "%04x <%s>:" addr lbl) lbls

let lblByteArrToString byteArr =
  getValue2 byteArr

// FixMe: Should complete the fields of InsInfo. Should call vexInfoFromOpcode
// for every insInfo and complete the InsInfo size. It should also look for and
// substitue label operands.
let updateInsInfos (ins: InsInfo list) (lbls: Map<string, int>) isa =
  let encodedInfo =
    List.map (fun ins -> let eByteCodes = encodeInstruction isa ins
                         eByteCodes, lblByteArrToString eByteCodes) ins
    |> List.mapi (fun i (e, str) -> i, String.length str / 2 |> uint64, str, e)
    |> updatePC [] 0UL

  let pcMap = List.map (fun (i, pc, _, _) -> i, pc) encodedInfo |> Map.ofList
  let lbls = Map.map (fun _ idx -> findPC idx pcMap) lbls

  let asmInfos = updateLabeledInstr ins encodedInfo lbls

  prettyPrint isa asmInfos lbls

  asmInfos

// vim: set tw=80 sts=2 sw=2:

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

namespace B2R2.ROP

open System
open B2R2.FrontEnd

/// Tail is a instruction sequence that needs to be placed at the end of each
/// ROP gadget.
type Tail = {
  Pattern: byte []
  TailInstrs: Instruction list
}

type Offset = uint64

/// ROP gadget is a list of instructions.
type Gadget = {
  Instrs : Instruction list
  Offset : Offset
  PreOff : Offset
}

/// GadgetMap is a mapping from an offset to an ROP gadget.
type GadgetMap = Map<Offset, Gadget>

module Gadget =
  let create offset tail =
    { Instrs = tail.TailInstrs
      Offset = offset
      PreOff = offset }

  let toString hdl (gadget: Gadget) =
    let s = sprintf "[*] Offset = %x\n" gadget.Offset
    gadget.Instrs
    |> List.fold (fun acc i ->
                   let disasm = BinHandler.DisasmInstr hdl true false i
                   acc + disasm + Environment.NewLine) s

module GadgetMap =
  let empty = Map.empty

  let toString hdl (gadgets: GadgetMap) =
    Map.fold (fun acc _ gadget ->
               acc + Gadget.toString hdl gadget + "\n") "" gadgets

type GadgetArr = Gadget array

module GadgetArr =
  let private pickHelper chooser (falseSet, acc) (gadget: Gadget) =
    let pre = gadget.PreOff
    let cur = gadget.Offset
    if pre <> cur && (Set.contains pre falseSet) then
      (Set.add cur falseSet, acc)
    else
      match chooser gadget with
      | true, Some v -> (falseSet, (gadget, v) :: acc)
      | true, None -> (falseSet, acc)
      | false, Some v -> (Set.add cur falseSet, (gadget, v) :: acc)
      | false, None -> (Set.add cur falseSet, acc)

  let pickAll chooser gadgets =
    Array.fold (pickHelper chooser) (Set.empty, []) gadgets |> snd

  let sort gadgets =
    Array.map snd gadgets |> Array.sortBy (fun g -> List.length g.Instrs)

  let tryFind = Array.tryFind

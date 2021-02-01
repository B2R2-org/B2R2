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

namespace B2R2.MiddleEnd.ControlFlowGraph

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.MiddleEnd.BinGraph

/// Basic block type for a disassembly-based CFG (DisasmCFG).
type DisasmBasicBlock (instrs: Instruction [], pp(*, ?funcID*)) =
  inherit BasicBlock (pp)

  let mutable instructions = instrs

  /// Temporarily disable this
  (*
  let symbolize (words: AsmWord []) =
    match funcID with
    | Some funcID ->
      words.[words.Length - 1] <-
        { AsmWordKind = AsmWordKind.Value; AsmWordValue = funcID }
    | None -> ()
    words
  *)

  override __.Range =
    let last = instructions.[instructions.Length - 1]
    AddrRange (pp.Address, last.Address + uint64 last.Length)

  override __.IsFakeBlock () = Array.isEmpty instructions

  override __.ToVisualBlock () =
    instructions
    |> Array.mapi (fun idx i ->
      if idx = Array.length instructions - 1 then
        i.Decompose (true)(* |> symbolize *)
      else i.Decompose (true))

  member __.Instructions
    with get () = instructions
    and set (i) = instructions <- i

  member __.Disassemblies
    with get () =
      instructions |> Array.map (fun i -> i.Disasm ())

  override __.ToString () =
    if instrs.Length = 0 then "DisasmBBLK(Dummy)"
    else "DisasmBBLK(" + String.u64ToHexNoPrefix __.PPoint.Address + ")"

type DisasmVertex = Vertex<DisasmBasicBlock>

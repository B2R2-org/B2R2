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

/// Basic block type for a disassembly-based CFG (DisasmCFG).
type DisasmBasicBlock (ppoint, instrs) =
  inherit BasicBlock (ppoint)

  /// Instructions.
  member __.Instructions with get(): Instruction[] = instrs

  /// Disassembled instructions.
  member __.Disassemblies with get () =
    instrs |> Array.map (fun i -> i.Disasm ())

  override __.Range with get() =
    let last = instrs[instrs.Length - 1]
    AddrRange (ppoint.Address, last.Address + uint64 last.Length - 1UL)

  override __.Cut (cutPoint: Addr) =
    assert (__.Range.IsIncluding cutPoint)
    let before, after =
      instrs
      |> Array.partition (fun ins -> ins.Address < cutPoint)
    DisasmBasicBlock (ppoint, before), DisasmBasicBlock (ppoint, after)

  override __.ToVisualBlock () =
    instrs
    |> Array.mapi (fun idx ins ->
      if idx = Array.length instrs - 1 then ins.Decompose (true)
      else ins.Decompose (true))

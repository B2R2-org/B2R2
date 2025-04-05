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

namespace B2R2.FrontEnd.BinLifter

open System.Text
open B2R2

/// Builder for disassembled strings.
[<AbstractClass>]
type DisasmBuilder (showAddr, resolveSymb, wordSz, addr, len) =
  abstract Accumulate: AsmWordKind -> string -> unit
  abstract AccumulateAddr: unit -> unit
  member _.ShowAddr with get(): bool = showAddr
  member _.ResolveSymbol with get(): bool = resolveSymb
  member _.WordSize with get(): WordSize = wordSz
  member _.Address with get(): Addr = addr
  member _.InsLength with get(): uint32 = len

type DisasmStringBuilder (showAddr, resolveSymb, wordSz, addr, len) =
  inherit DisasmBuilder (showAddr, resolveSymb, wordSz, addr, len)

  let sb = StringBuilder ()

  override _.Accumulate _kind s =
    sb.Append (s) |> ignore

  override _.AccumulateAddr () =
    sb.Append (Addr.toString wordSz addr) |> ignore
    sb.Append (": ") |> ignore

  override _.ToString () = sb.ToString ()

type DisasmWordBuilder (showAddr, resolveSymb, wordSz, addr, len, n) =
  inherit DisasmBuilder (showAddr, resolveSymb, wordSz, addr, len)

  let ab = AsmWordBuilder (n)

  override _.Accumulate kind s =
    ab.Append ({ AsmWordKind = kind; AsmWordValue = s }) |> ignore

  override _.AccumulateAddr () =
    ab.Append ({ AsmWordKind = AsmWordKind.Address
                 AsmWordValue = Addr.toString wordSz addr }) |> ignore
    ab.Append ({ AsmWordKind = AsmWordKind.String
                 AsmWordValue = ": " }) |> ignore

  member _.ToArray () = ab.ToArray ()

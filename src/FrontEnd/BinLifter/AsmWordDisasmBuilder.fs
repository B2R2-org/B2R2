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

open System.Collections.Generic
open B2R2

/// Represents a disassembly builder that accumulates <see
/// cref='T:B2R2.FrontEnd.BinLifter.AsmWord'/>.
type AsmWordDisasmBuilder (showAddr, symbolReader: INameReadable, wordSz) =
  let lst = List<AsmWord> ()
  let hasSymbolReader = isNull symbolReader |> not
  let mutable showSymb = hasSymbolReader
  let mutable showAddr = showAddr

  interface IDisasmBuilder with
    member _.WordSize with get () = wordSz

    member _.ShowAddress with get () = showAddr and set v = showAddr <- v

    member _.ShowSymbol with get () = showSymb and set v = showSymb <- v

    member _.Accumulate kind value =
      lst.Add { AsmWordKind = kind; AsmWordValue = value }

    member _.AccumulateSymbol (addr, prefix, suffix, noSymbolMapper) =
      if hasSymbolReader && showSymb then
        match symbolReader.TryFindName addr with
        | Ok name when name.Length > 0 ->
          lst.Add prefix
          lst.Add { AsmWordKind = AsmWordKind.Value; AsmWordValue = name }
          lst.Add suffix
        | _ -> for asmWord in noSymbolMapper addr do lst.Add asmWord
      else ()

    member _.AccumulateAddrMarker addr =
      if showAddr then
        lst.Add { AsmWordKind = AsmWordKind.Address
                  AsmWordValue = Addr.toString wordSz addr }
        lst.Add { AsmWordKind = AsmWordKind.String
                  AsmWordValue = ": " }
      else ()

    member this.ToString () =
      (this :> IDisasmBuilder).ToAsmWords ()
      |> Array.map AsmWord.ToString
      |> String.concat ""

    member _.ToAsmWords () =
      let arr = lst.ToArray ()
      lst.Clear ()
      arr

  override this.ToString () =
    (this :> IDisasmBuilder).ToString ()

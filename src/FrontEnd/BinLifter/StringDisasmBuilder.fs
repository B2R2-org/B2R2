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

/// Disassembly builder that simply accumulates strings without any type
/// annotation.
type StringDisasmBuilder (showAddr, symbolReader: INameReadable, wordSz) =
  let sb = StringBuilder ()
  let hasSymbolReader = isNull symbolReader |> not
  let mutable showSymb = hasSymbolReader
  let mutable showAddr = showAddr

  interface IDisasmBuilder with
    member _.WordSize with get () = wordSz

    member _.ShowAddress with get () = showAddr and set v = showAddr <- v

    member _.ShowSymbol with get () = showSymb and set v = showSymb <- v

    member _.Accumulate _ (value: string) =
      sb.Append value |> ignore

    member _.AccumulateSymbol (addr, prefix, suffix, noSymbolMapper) =
      if hasSymbolReader && showSymb then
        match symbolReader.TryFindName addr with
        | Ok name when name.Length > 0 ->
          sb.Append prefix.AsmWordValue |> ignore
          sb.Append name |> ignore
          sb.Append suffix.AsmWordValue |> ignore
        | _ ->
          for asmWord in noSymbolMapper addr do
            sb.Append asmWord.AsmWordValue |> ignore
      else ()

    member _.AccumulateAddrMarker addr =
      if showAddr then
        sb.Append (Addr.toString wordSz addr) |> ignore
        sb.Append (": ") |> ignore
      else ()

    member _.ToString () =
      let s = sb.ToString ()
      sb.Clear () |> ignore
      s

    member this.ToAsmWords () =
      [| { AsmWordKind = AsmWordKind.String
           AsmWordValue = (this :> IDisasmBuilder).ToString () } |]

  override this.ToString () =
    (this :> IDisasmBuilder).ToString ()

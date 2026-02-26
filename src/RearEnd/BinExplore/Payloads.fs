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

namespace B2R2.RearEnd.BinExplore

open System.Text.Json.Serialization
open B2R2

[<CLIMutable>]
type FuncInfo =
  { [<JsonPropertyName("id")>]
    FuncID: string
    [<JsonPropertyName("name")>]
    FuncName: string }

[<CLIMutable>]
type DataColoredHexAscii =
  { [<JsonPropertyName("color")>]
    Color: string
    [<JsonPropertyName("hex")>]
    Hex: string
    [<JsonPropertyName("ascii")>]
    Ascii: string }

[<CLIMutable>]
type SegInfo =
  { [<JsonPropertyName("addr")>]
    SegAddr: Addr
    [<JsonPropertyName("bytes")>]
    SegBytes: byte[]
    [<JsonPropertyName("coloredHexAscii")>]
    SegColoredHexAscii: DataColoredHexAscii[] }

[<CLIMutable>]
type VarPoint =
  { [<JsonPropertyName("addr")>]
    VarAddr: Addr
    [<JsonPropertyName("name")>]
    VarNames: string[] }

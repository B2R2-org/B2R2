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

namespace B2R2.Utilities.BinExplorer

open System

type Color = Red | Green | Yellow | Blue | NoColor

module Color =
  let toString color =
    match color with
    | NoColor -> "nocolor"
    | Red -> "red"
    | Green -> "green"
    | Yellow -> "yellow"
    | Blue -> "blue"

type RepresentationGroup = Null | Printable | Whitespace | Control | Else

type ColoredString = Color * string

module ColoredString =
  let isNull b = b = 0uy

  let isPrintable b = b >= 33uy && b <= 126uy

  let isWhitespace b = b = 32uy || (b >= 9uy && b <= 13uy)

  let isControl b =
    b = 127uy || (b >= 1uy && b <= 8uy) || (b >= 14uy && b <= 31uy)

  let getColor b =
    if isNull b then NoColor
    elif isPrintable b then Green
    elif isWhitespace b then Blue
    elif isControl b then Red
    else Yellow

  let mapHex (b: byte) _ = b.ToString ("X2")

  let mapAscii (b: byte) grp =
    match grp with
    | Null -> "0"
    | Printable -> (char b).ToString ()
    | Whitespace -> "_"
    | Control -> "*"
    | Else -> "."

  let getRepresentation mapper b =
    if isNull b then Null
    elif isPrintable b then Printable
    elif isWhitespace b then Whitespace
    elif isControl b then Control
    else Else
    |> mapper b

  let convertByte mapper b =
    (getColor b, getRepresentation mapper b) |> ColoredString

  let rec reduceColoredString (prev: ColoredString) acc list =
    let reduce pc ps s =
      ColoredString (pc, ps + s)
    match list with
    | [] -> prev :: acc |> List.rev
    | c, s as cur :: t ->
      let pc, ps = prev
      if prev = (NoColor, "") then reduceColoredString cur acc t
      elif c = pc then reduceColoredString (reduce pc ps s) acc t
      else reduceColoredString cur (prev :: acc) t

  let setConsoleColor color =
    match color with
    | NoColor -> Console.ResetColor ()
    | Red -> Console.ForegroundColor <- ConsoleColor.Red
    | Green -> Console.ForegroundColor <- ConsoleColor.Green
    | Yellow -> Console.ForegroundColor <- ConsoleColor.Yellow
    | Blue -> Console.ForegroundColor <- ConsoleColor.Blue

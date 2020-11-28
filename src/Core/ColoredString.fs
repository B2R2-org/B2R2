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

namespace B2R2

open System

type Color = Red | Green | Yellow | Blue | DarkCyan | DarkYellow | NoColor

module Color =
  let toString = function
    | NoColor -> "nocolor"
    | Red -> "red"
    | Green -> "green"
    | Yellow -> "yellow"
    | Blue -> "blue"
    | DarkCyan -> "darkcyan"
    | DarkYellow -> "darkyellow"

type ColoredSegment = Color * string

[<RequireQualifiedAccess>]
module ColoredSegment =
  let private isNull b = b = 0uy

  let private isPrintable b = b >= 33uy && b <= 126uy

  let private isWhitespace b = b = 32uy || (b >= 9uy && b <= 13uy)

  let private isControl b =
    b = 127uy || (b >= 1uy && b <= 8uy) || (b >= 14uy && b <= 31uy)

  let private getColor b =
    if isNull b then NoColor
    elif isPrintable b then Green
    elif isWhitespace b then Blue
    elif isControl b then Red
    else Yellow

  let getRepresentation b =
    if isNull b then "."
    elif isPrintable b then (char b).ToString ()
    elif isWhitespace b then "_"
    elif isControl b then "*"
    else "."

  let byteToHex b =
    getColor b, b.ToString ("X2")

  let byteToHexWithTail b tail =
    getColor b, (b.ToString ("X2") + tail)

  let byteToAscii b =
    getColor b, getRepresentation b

  let colorBytes (bs: byte []) =
    let lastIdx = bs.Length - 1
    bs
    |> Array.mapi (fun i b ->
      if i = lastIdx then byteToHex b
      else byteToHexWithTail b " ")
    |> Array.toList

  let inline nocolor str: ColoredSegment = NoColor, str
  let inline red str: ColoredSegment = Red, str
  let inline green str: ColoredSegment = Green, str
  let inline yellow str: ColoredSegment = Yellow, str
  let inline blue str: ColoredSegment = Blue, str
  let inline dcyan str: ColoredSegment = DarkCyan, str
  let inline dyellow str: ColoredSegment = DarkYellow, str

type ColoredString = ColoredSegment list

[<RequireQualifiedAccess>]
module ColoredString =
  /// Set the color.
  let private setColor = function
    | NoColor -> Console.ResetColor ()
    | Red -> Console.ForegroundColor <- ConsoleColor.Red
    | Green -> Console.ForegroundColor <- ConsoleColor.Green
    | Yellow -> Console.ForegroundColor <- ConsoleColor.Yellow
    | Blue -> Console.ForegroundColor <- ConsoleColor.Blue
    | DarkCyan -> Console.ForegroundColor <- ConsoleColor.DarkCyan
    | DarkYellow -> Console.ForegroundColor <- ConsoleColor.DarkYellow

  let compile (s: ColoredString): ColoredString =
    let rec loop prev acc = function
      | [] -> prev :: acc |> List.rev |> List.choose id
      | col, str as cur :: rest ->
        match prev with
        | Some (prevCol, prevStr) when prevCol = col ->
          loop (Some (prevCol, prevStr + str)) acc rest
        | Some (_, _) -> loop (Some cur) (prev :: acc) rest
        | None -> loop (Some cur) acc rest
    loop None [] s

  let internal toConsole (s: ColoredString) =
    s
    |> List.iter (fun (c, s) ->
      setColor c
      Console.Write s)
    Console.ResetColor ()

  let internal toConsoleLine s =
    toConsole s
    Console.WriteLine ()

  let toString (s: ColoredString) =
    s |> List.map snd |> String.concat ""

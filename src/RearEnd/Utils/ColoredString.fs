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

namespace B2R2.RearEnd.Utils

open System

/// String that can be printed out in the console with colors. A colored string
/// is a list of colored segments, each of which represents a string with a
/// specific color.
type ColoredString = ColoredSegment list

[<RequireQualifiedAccess>]
module ColoredString =
  /// Set the color.
  let private setColor = function
    | NoColor -> Console.ResetColor()
    | Red ->
      Console.ForegroundColor <- ConsoleColor.Red
    | Green ->
      Console.ForegroundColor <- ConsoleColor.Green
    | Yellow ->
      Console.ForegroundColor <- ConsoleColor.Yellow
    | Blue ->
      Console.ForegroundColor <- ConsoleColor.Blue
    | DarkCyan ->
      Console.ForegroundColor <- ConsoleColor.DarkCyan
    | DarkYellow ->
      Console.ForegroundColor <- ConsoleColor.DarkYellow
    | RedHighlight ->
      Console.ForegroundColor <- ConsoleColor.Red
      Console.BackgroundColor <- ConsoleColor.Red
    | GreenHighlight ->
      Console.ForegroundColor <- ConsoleColor.Green
      Console.BackgroundColor <- ConsoleColor.Green

  /// Compile the given colored string into a concise form.
  let compile (s: ColoredString): ColoredString =
    let rec loop prev acc = function
      | [] -> prev :: acc |> List.rev |> List.choose id
      | col, str as cur :: rest ->
        match prev with
        | Some(prevCol, prevStr) when prevCol = col ->
          loop (Some(prevCol, prevStr + str)) acc rest
        | Some(_) -> loop (Some cur) (prev :: acc) rest
        | None -> loop (Some cur) acc rest
    loop None [] s

  let internal toConsole (s: ColoredString) =
    s
    |> List.iter (fun (c, s) ->
      setColor c
      Console.Write s)
    Console.ResetColor()

  let internal toConsoleLine s =
    toConsole s
    Console.WriteLine()

  /// Colored string to a normal string.
  [<CompiledName "ToString">]
  let toString (s: ColoredString) =
    s |> List.map snd |> String.concat ""

  /// Construct a colored string from a byte array.
  [<CompiledName "OfBytes">]
  let ofBytes (bs: byte[]) =
    let lastIdx = bs.Length - 1
    bs
    |> Array.mapi (fun i b ->
      if i = lastIdx then ColoredSegment.hexOfByte b
      else ColoredSegment.hexOfByte b |> ColoredSegment.appendString " ")
    |> Array.toList


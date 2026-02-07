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
open System.Collections.Generic

/// Represent a string that can be printed out in the console with colors. A
/// colored string is a list of colored segments, each of which represents a
/// string with a specific color.
type ColoredString internal(inputSegs: IEnumerable<ColoredSegment>) =
  let segments = LinkedList<ColoredSegment>()

  let add col str =
    if segments.Count = 0 then
      segments.AddLast(ColoredSegment(col, str)) |> ignore
    else
      let lastCol, lastStr = segments.Last.Value
      if lastCol = col then
        segments.Last.Value <- ColoredSegment(col, lastStr + str)
      else
        segments.AddLast(ColoredSegment(col, str)) |> ignore

  do for col, str in inputSegs do add col str

  new() = ColoredString []

  /// Constructs a colored string from given a tuple of a color and a string.
  new(col, str) = ColoredString [ ColoredSegment(col, str) ]

  /// Constructs a colored string from a byte array.
  new(bs: byte[]) =
    let lastIdx = bs.Length - 1
    ColoredString
      [| for i in 0 .. bs.Length - 1 do
           if i = lastIdx then
             ColoredSegment.hexOfByte bs[i]
           else
             ColoredSegment.hexOfByte bs[i]
             |> ColoredSegment.appendString " " |]

  /// Returns the length of the colored string.
  member _.Length with get() =
    segments |> Seq.fold (fun len (_, s) -> String.length s + len) 0

  /// Adds a colored segment to the string.
  member this.Add(col, str) =
    add col str
    this

  member private this.Pad(width, fn) =
    let len = this.Length
    if len >= width then
      ()
    else
      let padding = String(' ', width - len)
      fn (ColoredSegment(NoColor, padding))

  /// Adds a padded string to the colored string. The string is padded with
  /// spaces to the right if it is shorter than the given width.
  member this.PadLeft(width) =
    this.Pad(width, fun seg -> segments.AddFirst seg |> ignore)
    this

  /// Adds a padded string to the colored string. The string is padded with
  /// spaces to the left if it is shorter than the given width.
  member this.PadRight(width) =
    this.Pad(width, fun seg -> segments.AddLast seg |> ignore)
    this

  /// Renders the colored string by applying the given function to each
  /// colored segment.
  member _.Render fn =
    for col, s in segments do fn col s
    Console.ResetColor()

  override _.ToString() =
    let sb = Text.StringBuilder()
    for _, s in segments do sb.Append s |> ignore done
    sb.ToString()

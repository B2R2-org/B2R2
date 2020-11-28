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

/// Define a column of a table with a specified width in bytes (# of chars).
type TableColumn =
  | RightAligned of width: int
  | LeftAligned of width: int
with
  static member ofPaddedString isLast (s: string) = function
    | RightAligned w -> let s = s.PadLeft (w) in if isLast then s else s + " "
    | LeftAligned w -> if isLast then s else s.PadRight (w) + " "

/// Define a output configuration of a table.
type TableConfig = TableColumn list

module CS = ColoredSegment

module private PrinterConst =
  let [<Literal>] colWidth = 24

/// Any B2R2's layers should *not* use System.Console or `printfn` to directly
/// output strings. Instead, they should resort to the Printer to "indirectly"
/// print out strings.
[<AbstractClass>]
type Printer () =
  /// Print out the given OutString.
  abstract Print: OutString -> unit

  /// Print out the given ColoredString.
  abstract Print: ColoredString -> unit

  /// Print out the formated string.
  abstract Print: string * [<ParamArray>] args: obj [] -> unit

  /// Print out the given OutString with newline.
  abstract PrintLine: OutString -> unit

  /// Print out the given ColoredString with newline.
  abstract PrintLine: ColoredString -> unit

  /// Print out the formated string with newline.
  abstract PrintLine: string * [<ParamArray>] args: obj [] -> unit

  /// Print out a newline.
  abstract PrintLine: unit -> unit

  /// Print out table row for the given ColoredString list.
  abstract PrintRow: bool * TableConfig * ColoredString list -> unit

  /// Print out table row for the given string list.
  abstract PrintRow: bool * TableConfig * string list -> unit

  /// Print out the section title.
  abstract PrintSectionTitle: string -> unit

  /// Print out the subsection title.
  abstract PrintSubsectionTitle: string -> unit

  /// Print out the subsubsection title.
  abstract PrintSubsubsectionTitle: string -> unit

  /// Print out a line with two columns. Each column has a predefined width.
  abstract PrintTwoCols: string -> string -> unit

  /// Print out a line with two columns. Each column has a predefined width, and
  /// the second column will be colored.
  abstract PrintTwoColsWithColorOnSnd: string -> ColoredString -> unit

  /// Flush out everything.
  abstract Flush: unit -> unit

  [<CompiledName "PrintErrorToConsole">]
  static member printErrorToConsole str =
    [ CS.nocolor "[*] Error: "; CS.red str ] |> Printer.printToConsoleLine
    Printer.printToConsoleLine ()

  [<CompiledName "PrintToConsole">]
  static member printToConsole s =
    ColoredString.toConsole s

  [<CompiledName "PrintToConsole">]
  static member printToConsole (s: string, [<ParamArray>] args) =
    Console.Write (s, args)

  [<CompiledName "PrintToConsoleLine">]
  static member printToConsoleLine s =
    ColoredString.toConsoleLine s

  [<CompiledName "PrintToConsoleLine">]
  static member printToConsoleLine (s: string, [<ParamArray>] args) =
    Console.WriteLine (s, args)

  [<CompiledName "PrintToConsoleLine">]
  static member printToConsoleLine () =
    Console.WriteLine ()

/// ConsolePrinter simply prints out strings to console whenever a print method
/// is called. This printer does not perform any caching, so it immediately
/// flushes out all the strings to console.
type ConsolePrinter () =
  inherit Printer ()

  override __.Print s =
    OutString.toConsole s

  override __.Print s =
    ColoredString.toConsole s

  override __.Print (s: string, [<ParamArray>] args) =
    Console.Write (s, args)

  override __.PrintLine s =
    OutString.toConsoleLine s

  override __.PrintLine s =
    ColoredString.toConsoleLine s

  override __.PrintLine (s: string, [<ParamArray>] args) =
    Console.WriteLine (s, args)

  override __.PrintLine () =
    Console.WriteLine ()

  override __.PrintRow (indent, cfg: TableConfig, css: ColoredString list) =
    let lastIdx = List.length cfg - 1
    List.zip cfg css
    |> List.iteri (fun i (col, cs) ->
      if indent then Console.Write ("  ") else ()
      match cs with
      | (c, s) :: rest ->
        (c, TableColumn.ofPaddedString (i = lastIdx) s col) :: rest
        |> __.Print
      | [] -> ())
    Console.WriteLine ()

  override __.PrintRow (indent, cfg: TableConfig, strs: string list) =
    let lastIdx = List.length cfg - 1
    List.zip cfg strs
    |> List.iteri (fun i (c, s) ->
      if indent then
        Console.Write ("  ")
      Console.Write (TableColumn.ofPaddedString (i = lastIdx) s c))
    Console.WriteLine ()

  override __.PrintSectionTitle title =
    [ CS.red "# "; CS.nocolor title ]
    |> __.PrintLine
    __.PrintLine ()

  override __.PrintSubsectionTitle (str: string) =
    __.PrintLine ("    - " + str)

  override __.PrintSubsubsectionTitle (str: string) =
    __.PrintLine ("         * " + str)

  override __.PrintTwoCols (col1: string) (col2: string) =
    __.Print (col1.PadLeft PrinterConst.colWidth + " ")
    __.PrintLine col2

  override __.PrintTwoColsWithColorOnSnd (col1: string) (col2: ColoredString) =
    __.Print (col1.PadLeft PrinterConst.colWidth + " ")
    __.PrintLine col2

  override __.Flush () = ()

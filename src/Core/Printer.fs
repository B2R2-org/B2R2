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
open System.Text

/// Define a column of a table with a specified width in bytes (# of chars).
type TableColumn =
  | RightAligned of width: int
  | LeftAligned of width: int
with
  static member ofPaddedString isLast (s: string) column =
    match column with
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

  /// Print out a newline only if the previous output was not empty (i.e., a
  /// line with only a newline). In other words, this function will not output
  /// anything if the previous output was an empty line. This is to make sure we
  /// output only one single empty line in some situations.
  abstract PrintLineIfPrevLineWasNotEmpty: unit -> unit

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

  let mutable lastLineWasEmpty = false

  override __.Print s =
    OutString.toConsole s

  override __.Print s =
    ColoredString.toConsole s

  override __.Print (s: string, [<ParamArray>] args) =
    Console.Write (s, args)

  override __.PrintLine s =
    OutString.toConsoleLine s
    lastLineWasEmpty <- false

  override __.PrintLine s =
    ColoredString.toConsoleLine s
    lastLineWasEmpty <- false

  override __.PrintLine (s: string, [<ParamArray>] args) =
    Console.WriteLine (s, args)
    lastLineWasEmpty <- s.Length = 0

  override __.PrintLine () =
    Console.WriteLine ()
    lastLineWasEmpty <- true

  override __.PrintLineIfPrevLineWasNotEmpty () =
    if lastLineWasEmpty then ()
    else Console.WriteLine ()
    lastLineWasEmpty <- true

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
    lastLineWasEmpty <- false

  override __.PrintRow (indent, cfg: TableConfig, strs: string list) =
    let lastIdx = List.length cfg - 1
    List.zip cfg strs
    |> List.iteri (fun i (c, s) ->
      if indent then
        Console.Write ("  ")
      Console.Write (TableColumn.ofPaddedString (i = lastIdx) s c))
    Console.WriteLine ()
    lastLineWasEmpty <- false

  override __.PrintSectionTitle title =
    [ CS.red "# "; CS.nocolor title ]
    |> __.PrintLine
    __.PrintLine ()
    lastLineWasEmpty <- true

  override __.PrintSubsectionTitle (str: string) =
    __.PrintLine ("    - " + str)
    lastLineWasEmpty <- false

  override __.PrintSubsubsectionTitle (str: string) =
    __.PrintLine ("         * " + str)
    lastLineWasEmpty <- false

  override __.PrintTwoCols (col1: string) (col2: string) =
    __.Print (col1.PadLeft PrinterConst.colWidth + " ")
    __.PrintLine col2
    lastLineWasEmpty <- false

  override __.PrintTwoColsWithColorOnSnd (col1: string) (col2: ColoredString) =
    __.Print (col1.PadLeft PrinterConst.colWidth + " ")
    __.PrintLine col2
    lastLineWasEmpty <- false

  override __.Flush () = ()

/// ConsoleCachedPrinter prints out non-colored strings only when the Flush
/// method is called. All the colored strings will be normalized to plain
/// strings. It will simply stack up all the output candidates before Flush is
/// called. This is useful for performance-critical applications.
type ConsoleCachedPrinter () =
  inherit Printer ()

  let mutable lastLineWasEmpty = false
  let cache = StringBuilder ()
  let add (s: string) = cache.Append (s) |> ignore

  override __.Print s =
    OutString.toString s |> add

  override __.Print s =
    ColoredString.toString s |> add

  override __.Print (s: string, [<ParamArray>] args) =
    String.Format (s, args) |> add

  override __.PrintLine s =
    OutString.toString s + Environment.NewLine |> add
    lastLineWasEmpty <- false

  override __.PrintLine s =
    ColoredString.toString s + Environment.NewLine |> add
    lastLineWasEmpty <- false

  override __.PrintLine (s: string, [<ParamArray>] args) =
    String.Format (s, args) + Environment.NewLine |> add
    lastLineWasEmpty <- s.Length = 0

  override __.PrintLine () =
    add Environment.NewLine
    lastLineWasEmpty <- true

  override __.PrintLineIfPrevLineWasNotEmpty () =
    if lastLineWasEmpty then ()
    else add Environment.NewLine
    lastLineWasEmpty <- true

  override __.PrintRow (indent, cfg: TableConfig, css: ColoredString list) =
    let lastIdx = List.length cfg - 1
    List.zip cfg css
    |> List.iteri (fun i (col, cs) ->
      if indent then add ("  ") else ()
      match cs with
      | (_, s) :: rest ->
        (TableColumn.ofPaddedString (i = lastIdx) s col
        + ColoredString.toString rest)
        |> add
      | [] -> ())
    add Environment.NewLine
    lastLineWasEmpty <- false

  override __.PrintRow (indent, cfg: TableConfig, strs: string list) =
    let lastIdx = List.length cfg - 1
    List.zip cfg strs
    |> List.iteri (fun i (c, s) ->
      if indent then add ("  ")
      TableColumn.ofPaddedString (i = lastIdx) s c |> add)
    add Environment.NewLine
    lastLineWasEmpty <- false

  override __.PrintSectionTitle title =
    "# " + title + Environment.NewLine + Environment.NewLine |> add
    lastLineWasEmpty <- true

  override __.PrintSubsectionTitle (str: string) =
    ("    - " + str) |> add
    add Environment.NewLine
    lastLineWasEmpty <- false

  override __.PrintSubsubsectionTitle (str: string) =
    ("         * " + str) |> add
    add Environment.NewLine
    lastLineWasEmpty <- false

  override __.PrintTwoCols (col1: string) (col2: string) =
    col1.PadLeft PrinterConst.colWidth + " " |> add
    col2 |> add
    add Environment.NewLine
    lastLineWasEmpty <- false

  override __.PrintTwoColsWithColorOnSnd (col1: string) (col2: ColoredString) =
    col1.PadLeft PrinterConst.colWidth + " " |> add
    ColoredString.toString col2 |> add
    add Environment.NewLine
    lastLineWasEmpty <- false

  override __.Flush () =
    cache.ToString () |> Console.Write

/// ConsoleCachedPrinter does not print anything. This is the same as
/// redirecting outputs to /dev/null.
type ConsoleNullPrinter () =
  inherit Printer ()

  override __.Print (_: OutString) = ()

  override __.Print (_: ColoredString) = ()

  override __.Print (_: string, [<ParamArray>] _args) = ()

  override __.PrintLine (_: OutString) = ()

  override __.PrintLine (_: ColoredString) = ()

  override __.PrintLine (_: string, [<ParamArray>] _args) = ()

  override __.PrintLine () = ()

  override __.PrintLineIfPrevLineWasNotEmpty () = ()

  override __.PrintRow (_: bool, _: TableConfig, _: ColoredString list) = ()

  override __.PrintRow (_: bool, _: TableConfig, _: string list) = ()

  override __.PrintSectionTitle _ = ()

  override __.PrintSubsectionTitle (_: string) = ()

  override __.PrintSubsubsectionTitle (_: string) = ()

  override __.PrintTwoCols (_: string) (_: string) = ()

  override __.PrintTwoColsWithColorOnSnd (_: string) (_: ColoredString) = ()

  override __.Flush () = ()

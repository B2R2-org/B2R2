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

module internal B2R2.RearEnd.BinExplorer.CmdSpec

/// Command specification in *alphabetic* order. The entries in this list
/// should match with the KeyWords of help commands (in defaultCmds).
let speclist =
  [ CmdBinInfo () :> Cmd
    CmdCredits () :> Cmd
    CmdDemangle () :> Cmd
    CmdEvalExpr ("?", ["?x"], "hex", "", HexadecimalF) :> Cmd
    CmdEvalExpr ("?d", [], "decimal", "d", DecimalF) :> Cmd
    CmdEvalExpr ("?b", [], "binary", "b", BinaryF) :> Cmd
    CmdEvalExpr ("?o", [], "octal", "o", OctalF) :> Cmd
    CmdEvalExpr ("?f", [], "float", "f", FloatingPointF) :> Cmd
    CmdEvalExpr ("?c", [], "character", "c", CharacterF) :> Cmd
    CmdDisasm () :> Cmd
    CmdGadgetSearch () :> Cmd
    CmdROP () :> Cmd
    CmdList () :> Cmd
    CmdSearch () :> Cmd
    CmdShow () :> Cmd
    CmdHexDump () :> Cmd
    CmdPrint () :> Cmd
    (* Default commands *)
    CmdHelp () :> Cmd
    CmdExit () :> Cmd ]

// vim: set tw=80 sts=2 sw=2:

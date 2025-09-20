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

namespace B2R2.RearEnd.BinExplorer

open B2R2.MiddleEnd
open B2R2.RearEnd.Utils

/// Represents a command that can be invoked within BinExplorer's CLI.
type ICmd =
  /// The name of the command.
  abstract CmdName: string

  /// Aliases for the command.
  abstract CmdAlias: string list

  /// Short command description.
  abstract CmdDescr: string

  /// Command-specific help string.
  abstract CmdHelp: string

  /// A list of sub-command strings that can be used with this command. This
  /// list provides a way to tab-complete a keyword.
  abstract SubCommands: string list

  /// A command callback function. This function takes in an Agent (arbiter), a
  /// list of arguments as input, and produces some side effects.
  abstract CallBack: BinaryBrew<_, _> * string list -> OutString[]
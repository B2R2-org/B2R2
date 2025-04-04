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

open System.Text
open B2R2
open B2R2.RearEnd.Utils

type CmdShow () =
  inherit Cmd ()

  override __.CmdName = "show"

  override __.CmdAlias = []

  override __.CmdDescr = "Show information about an abstract component."

  override __.CmdHelp =
    "Usage: show <component> [option(s)]\n\n\
     Show information about an abstract component.\n\
     <component> is an abstract component in the binary, and subcommands are:\n\
       - caller <instruction addr in hex>\n\
       - callee/function <callee name or addr in hex>"

  override __.SubCommands = []

  member private __.CallerToString (sb: StringBuilder) (addr: Addr) =
    sb.Append $"  - referenced by {addr:x}\n"

  // member private __.CalleeToSimpleString prefix (sb: StringBuilder) callee =
  //   let noret =
  //     match (callee: Function).NoReturnProperty with
  //     | NoRet -> " [no return]"
  //     | ConditionalNoRet _ -> " [conditional no return]"
  //     | NotNoRetConfirmed | NotNoRet -> ""
  //     | UnknownNoRet -> ""
  //   if callee.FunctionKind <> FunctionKind.Regular then
  //     sb.Append (prefix + callee.FunctionName + noret + "\n")
  //   else
  //     sb.Append (prefix + callee.FunctionName
  //              + noret + $" @ {callee.EntryPoint:x}\n")

  // member private __.CalleeToString ess (sb: StringBuilder) callee =
  //   __.CalleeToSimpleString "" sb callee
  //   |> (fun sb -> callee.Callers |> Seq.fold __.CallerToString sb)

  // member __.ShowCaller ess = function
  //   | (expr: string) :: _ ->
  //     let addr = CmdUtils.convHexString expr |> Option.defaultValue 0UL
  //     match ess.CodeManager.FunctionMaintainer.TryFind addr with
  //     | None -> [| "[*] Not found." |]
  //     | Some func ->
  //       let sb = StringBuilder ()
  //       let sb = sb.Append (expr + " calls:\n")
  //       let sb =
  //         func.Callers
  //         |> Seq.fold (fun sb (addr: Addr) ->
  //           match ess.CodeManager.FunctionMaintainer.TryFind addr with
  //           | Some callee -> __.CalleeToSimpleString "  - " sb callee
  //           | None -> sb) sb
  //       [| sb.ToString () |]
  //   | _ -> [| __.CmdHelp |]

  // member __.ShowCallee ess = function
  //   | (expr: string) :: _ ->
  //     let addr = CmdUtils.convHexString expr |> Option.defaultValue 0UL
  //     let sb = StringBuilder ()
  //     if Char.IsDigit expr[0] then
  //       ess.CodeManager.FunctionMaintainer.TryFind (addr)
  //     else ess.CodeManager.FunctionMaintainer.TryFind (expr)
  //     |> Option.map (fun callee ->
  //       (__.CalleeToString ess sb callee).ToString ())
  //     |> Option.defaultValue "[*] Not found."
  //     |> Array.singleton
  //   | _ -> [| __.CmdHelp |]

  // member __.CmdHandle ess opts = function
  //   | "caller" -> __.ShowCaller ess opts
  //   | "callee"
  //   | "function" -> __.ShowCallee ess opts
  //   | _ -> [| __.CmdHelp |]

  override __.CallBack _ ess args =
    match args with
    | _ -> [| __.CmdHelp |]
    |> Array.map OutputNormal

// vim: set tw=80 sts=2 sw=2:

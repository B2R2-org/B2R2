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

namespace B2R2.RearEnd.BinExplore.Commands

open System
open System.Globalization
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.RearEnd.BinExplore

type Show() =
  let [<Literal>] CmdName = "show"

  let [<Literal>] Desc = "Show callers or direct callees of a function."

  let wordSize (brew: BinaryBrew<_, _>) = brew.BinHandle.ISA.WordSize

  let tryParseAddress (value: string) =
    let digits =
      if value.StartsWith("0x", StringComparison.OrdinalIgnoreCase) then
        value[2..]
      else
        value
    let style = NumberStyles.HexNumber
    match UInt64.TryParse(digits, style, CultureInfo.InvariantCulture) with
    | true, addr -> Some addr
    | _ -> None

  let tryFindFunction (brew: BinaryBrew<_, _>) (addr: Addr) =
    try brew.Functions.Find(addr) |> Some
    with :? System.Collections.Generic.KeyNotFoundException -> None

  let describeFunction (brew: BinaryBrew<_, _>) addr =
    let address = Addr.toString (wordSize brew) addr
    match tryFindFunction brew addr with
    | Some fn -> address + ": " + fn.Name
    | None -> address + ": (unknown)"

  let showCallers (brew: BinaryBrew<_, _>) addrArg =
    match tryParseAddress addrArg with
    | None ->
      [| $"Invalid function entry address: {addrArg}" |]
    | Some addr ->
      match tryFindFunction brew addr with
      | None ->
        [| $"Function not found: {addrArg}" |]
      | Some fn when isNull fn.Callers || fn.Callers.Count = 0 ->
        [| "No callers found." |]
      | Some fn ->
        fn.Callers
        |> Seq.map (describeFunction brew)
        |> Seq.sort
        |> Seq.toArray

  let findFunctions (brew: BinaryBrew<_, _>) nameOrAddr =
    let byAddress =
      tryParseAddress nameOrAddr
      |> Option.bind (tryFindFunction brew)
    match byAddress with
    | Some fn ->
      [ fn ]
    | None ->
      try brew.Functions.Find(nameOrAddr) |> Seq.toList
      with :? System.Collections.Generic.KeyNotFoundException -> []

  let showCallees (brew: BinaryBrew<_, _>) nameOrAddr =
    match findFunctions brew nameOrAddr with
    | [] ->
      [| $"Function not found: {nameOrAddr}" |]
    | fns ->
      fns
      |> List.toArray
      |> Array.collect (fun fn ->
        let address = Addr.toString (wordSize brew) fn.EntryPoint
        let header =
          if fn.IsExternal then
            $"{address}: {fn.Name} (external)"
          else
            $"{address}: {fn.Name}"
        let callees =
          if isNull fn.Callees then
            [||]
          else
            fn.Callees.Values
            |> Seq.choose (function
              | RegularCallee target -> Some target
              | _ -> None)
            |> Seq.distinct
            |> Seq.map (describeFunction brew)
            |> Seq.sort
            |> Seq.map (fun line -> "  " + line)
            |> Seq.toArray
        if Array.isEmpty callees then
          [| header; "  (no direct callees)" |]
        else
          Array.append [| header |] callees)

  interface ICmd with

    member _.CmdName = CmdName

    member _.CmdAlias = []

    member _.CmdDescr = Desc

    member _.CmdHelp =
      let extra =
        "Available subcommands:\n\
         - caller <function entry address in hex>\n\
         - callee <function name or entry address in hex>\n\
         - function <function name or entry address in hex> (alias for callee)"
      ColoredString()
        .Append(NoColor, "Usage: ")
        .Append(DarkCyan, $"{CmdName}")
        .Append(NoColor, " <subcommand> <function>\n\n")
        .Append(NoColor, $"{Desc}\n\n{extra}")

    member _.SubCommands = [ "caller"; "callee"; "function" ]

    member this.CallBack(arbiter, args) =
      match args, arbiter.GetBinaryBrew() with
      | "caller" :: addr :: _, Ok brew ->
        showCallers brew addr |> Array.map OutputNormal
      | "callee" :: nameOrAddr :: _, Ok brew
      | "function" :: nameOrAddr :: _, Ok brew ->
        showCallees brew nameOrAddr |> Array.map OutputNormal
      | _, Error _ ->
        ICmd.buildErrorOutput "No binary is currently loaded."
      | _ ->
        [| (this :> ICmd).CmdHelp |]
        |> Array.map OutputColored

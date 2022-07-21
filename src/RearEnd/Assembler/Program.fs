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

module B2R2.RearEnd.Assembler.Program

open System
open B2R2
open B2R2.FrontEnd.BinInterface
open B2R2.RearEnd
open B2R2.BinIR.LowUIR
open B2R2.Peripheral.Assembly

/// The console printer.
let internal out = ConsolePrinter () :> Printer

let [<Literal>] private NormalPrompt = "> "

let private printIns hdl addr bs =
  let bCode = (BitConverter.ToString (bs)).Replace ("-", "")
  let hdl = BinHandle.UpdateCode hdl addr bs
  let ins = BinHandle.ParseInstr (hdl, addr)
  out.PrintLine (sprintf "%08x: %-20s     %s" addr bCode (ins.Disasm ()))
  addr + uint64 (Array.length bs)

let inline private printResult fn = function
  | Ok res -> fn res
  | Error err -> Printer.PrintErrorToConsole err

let getAssemblyPrinter (opts: AssemblerOpts) =
  match opts.Mode with
  | GeneralMode (isa) ->
    let hdl = BinHandle.Init (isa)
    let baseAddr = opts.BaseAddress
    let asm = AsmInterface (hdl, baseAddr)
    fun str ->
      asm.AssembleBin str
      |> printResult (fun res ->
        List.fold (printIns hdl) baseAddr res
        |> ignore)
  | LowUIRMode (isa) ->
    let asm = AsmInterface (isa, opts.BaseAddress)
    fun str ->
      asm.LiftLowUIR true str
      |> printResult (Array.iter (Pp.stmtToString >> out.PrintLine))

let rec private asmFromStdin (console: FsReadLine.Console) printer str =
  match console.ReadLine () with
  | "" -> asmFromStdin console printer str
  | input when isNull input || input = "q" || input = "quit" ->
    out.PrintLine ("Bye!")
    out.Flush ()
  | input ->
    let input = input.Trim ()
    let str =
      if input.EndsWith (";;") then
        console.UpdatePrompt NormalPrompt
        printer <| str + input.TrimEnd (';')
        ""
      else
        console.UpdatePrompt " "
        str + input + Environment.NewLine
    asmFromStdin console printer str

let showBasicInfo (opts: AssemblerOpts) =
  match opts.Mode with
  | GeneralMode (isa) ->
    out.PrintLine [ Blue, ISA.ArchToString isa.Arch; Green, " General Mode" ]
  | LowUIRMode (isa) ->
    out.PrintLine [ Blue, ISA.ArchToString isa.Arch ; Green, " LowUIR Mode" ]

let private asmFromFiles files printer =
  files
  |> List.iter (IO.File.ReadAllText >> printer)

let asmMain files opts =
  let printer = getAssemblyPrinter opts
  if List.isEmpty files then
    let console = FsReadLine.Console (NormalPrompt, ["quit"])
    showBasicInfo opts
    asmFromStdin console printer ""
  else asmFromFiles files printer

[<EntryPoint>]
let main args =
  let opts = AssemblerOpts ()
  CmdOpts.ParseAndRun asmMain "assembler" "" Cmd.spec opts args

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

namespace B2R2.RearEnd.BinExplorer.Commands

open System
open B2R2.FrontEnd
open B2R2.FrontEnd.BinLifter
open B2R2.RearEnd.Utils
open B2R2.RearEnd.BinExplorer

type Disasm() =
  let convertCount (str: string) =
    try Convert.ToInt32 str |> Ok
    with _ -> Error "[*] Invalid disassembly count given."

  let convertAddr (str: string) count =
    try Ok(count, Convert.ToUInt64(str, 16))
    with _ -> Error "[*] Invalid address is given."

  let rec disasmLoop acc bld (instrs: InstructionCollection) addr count =
    if count <= 0 then List.rev acc |> List.toArray
    else
      match instrs.TryFind addr with
      | Ok ins ->
        let d = ins.Disasm bld
        disasmLoop (d :: acc) bld instrs (addr + uint64 ins.Length) (count - 1)
      | Error _ ->
        disasmLoop ("(invalid)" :: acc) bld instrs (addr + 1UL) (count - 1)

  let render bld instrs = function
    | Ok(count, addr: uint64) -> disasmLoop [] bld instrs addr count
    | Error str -> [| str |]

  let disasm (hdl: BinHandle) instrs count addr =
    let bld = StringDisasmBuilder(true, hdl.File, hdl.File.ISA.WordSize)
    convertCount count
    |> Result.bind (convertAddr addr)
    |> render bld instrs

  interface ICmd with

    member _.CmdName = "disasm"

    member _.CmdAlias = [ "d" ]

    member _.CmdDescr = "Display disassembly of the binary."

    member _.CmdHelp =
      "Usage: disasm <addr>\n\
              disasm <cnt> <addr>\n\n\
      Print <cnt> disassembled instructions starting from the given address.\n\
      When the <cnt> argument is not given, it will print one instruction."

    member _.SubCommands = []

    member this.CallBack(brew, args) =
      match args with
      | cnt :: addr :: _ -> disasm brew.BinHandle brew.Instructions cnt addr
      | addr :: _ -> disasm brew.BinHandle brew.Instructions "1" addr
      | _ -> [| (this :> ICmd).CmdHelp |]
      |> Array.map OutputNormal
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

namespace B2R2.Utilities.BinExplorer

open System
open B2R2.FrontEnd
open B2R2.BinEssence

type CmdDisasm () =
  inherit Cmd ()

  let convertCount (str: string) =
    try Convert.ToInt32 str |> Ok
    with _ -> Error "[*] Invalid disassembly count given."

  let convertAddr (str: string) count =
    try Ok (count, Convert.ToUInt64 (str, 16))
    with _ -> Error "[*] Invalid address is given."

  let rec disasmLoop acc (ess: BinEssence) addr count =
    if count <= 0 then List.rev acc |> List.toArray
    else
      match BinHandler.TryParseInstr ess.BinHandler addr with
      | Some ins ->
        let d = ins.Disasm (true, true, ess.BinHandler.FileInfo)
        disasmLoop (d :: acc) ess (addr + uint64 ins.Length) (count - 1)
      | None ->
        disasmLoop ("(invalid)" :: acc) ess (addr + 1UL) (count - 1)

  let render (ess: BinEssence) = function
    | Ok (count, addr: uint64) -> disasmLoop [] ess addr count
    | Error str -> [| str |]

  let disasm ess count addr =
    convertCount count
    |> Result.bind (convertAddr addr)
    |> render ess

  override __.CmdName = "disasm"

  override __.CmdAlias = [ "d" ]

  override __.CmdDescr = "Display disassembly of the binary."

  override __.CmdHelp =
    "Usage: disasm <addr>\n\
            disasm <cnt> <addr>\n\n\
     Print <cnt> disassembled instructions starting from the given address.\n\
     When the <cnt> argument is not given, it will print one instruction."

  override __.SubCommands = []

  override __.CallBack _ ess args =
    match args with
    | cnt :: addr :: _ -> disasm ess cnt addr
    | addr :: _ -> disasm ess "1" addr
    | _ -> [| __.CmdHelp |]

// vim: set tw=80 sts=2 sw=2:

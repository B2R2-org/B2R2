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

module B2R2.MiddleEnd.ControlFlowAnalysis.ExternalFunctionLoader

open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.BinFile
open B2R2.MiddleEnd.ControlFlowGraph

[<RequireQualifiedAccess>]
module internal ELF = begin
  open B2R2.FrontEnd.BinFile.ELF

  let findInternalFuncReloc (elf: ELFBinFile) (entry: LinkageTableEntry) =
    let reloc = elf.RelocationInfo.RelocByAddr[entry.TableAddress]
    match reloc.RelSymbol with
    | Some relSym ->
      if relSym.SymType = SymbolType.STT_FUNC then
        match relSym.ParentSection with
        | Some parent ->
          if parent.SecName = ".text" then Ok relSym.Addr
          else Error ErrorCase.SymbolNotFound
        | _ -> Error ErrorCase.SymbolNotFound
      else Error ErrorCase.SymbolNotFound
    | None ->
      match reloc.RelType with
      | RelocationX64 (RelocationX64.R_X86_64_IRELATIVE) -> Ok reloc.RelAddend
      | _ -> Error ErrorCase.SymbolNotFound

  /// Known non-returning function names.
  let private knownNoReturnFuncs =
    HashSet [| "__assert"
               "__assert_fail"
               "__stack_chk_fail"
               "abort"
               "_abort"
               "exit"
               "_exit"
               "__longjmp_chk"
               "__cxa_bad_cast"
               "__cxa_rethrow"
               "__cxa_throw"
               "__cxa_throw_bad_array_new_length"
               "_Unwind_Resume"
               "_gfortran_os_error"
               "_gfortran_runtime_error"
               "_gfortran_runtime_error_at"
               "_gfortran_stop_numeric"
               "_gfortran_stop_string"
               "__libc_start_main"
               "_ZSt20__throw_length_errorPKc"
               "_ZSt17__throw_bad_allocv"
               "_ZSt16__throw_bad_castv"
               "longjmp" |]

  /// A mapping from known conditionally-not-returning function names to the
  /// index of the argument that determines the return status.
  let private knownCondNoReturnFuncMap =
    [ ("error", 1)
      ("error_at_line", 1) ]
    |> Map.ofList

  let getNoReturnStatusFromKnownFunc (name: string) =
    if knownNoReturnFuncs.Contains name then NoRet
    else
      match knownCondNoReturnFuncMap.TryGetValue name with
      | true, nth -> ConditionalNoRet nth
      | false, _ -> NotNoRet (* For common cases. *)
end

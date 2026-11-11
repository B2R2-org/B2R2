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
open B2R2.ABI
open B2R2.MiddleEnd.ControlFlowGraph

[<RequireQualifiedAccess>]
module internal ELF = begin
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
  /// zero-based index of the argument that determines the return status.
  let private knownCondNoReturnFuncMap =
    [ ("error", 0)
      ("error_at_line", 0) ]
    |> Map.ofList

  /// Gets the status of the known function of the given name, locating the
  /// argument that decides it by the given calling convention.
  let getNoReturnStatusFromKnownFunc (cc: CallingConvention) name =
    if knownNoReturnFuncs.Contains name then
      NoRet
    else
      match knownCondNoReturnFuncMap.TryGetValue name with
      | true, i -> ConditionalNoRet(cc.GetIntArgLocation i)
      | false, _ -> NotNoRet (* For common cases. *)

  /// A mapping from known function names to the zero-based indices of the
  /// arguments that pass the functions they call, as __libc_start_main calls
  /// main and qsort calls its comparison.
  let private knownCallbackFuncMap =
    [ ("__libc_start_main", [ 0; 3; 4 ])
      ("__cxa_atexit", [ 0 ])
      ("__cxa_thread_atexit_impl", [ 0 ])
      ("at_quick_exit", [ 0 ])
      ("atexit", [ 0 ])
      ("on_exit", [ 0 ])
      ("bsearch", [ 4 ])
      ("qsort", [ 3 ])
      ("qsort_r", [ 3 ])
      ("lfind", [ 4 ])
      ("lsearch", [ 4 ])
      ("tsearch", [ 2 ])
      ("tfind", [ 2 ])
      ("tdelete", [ 2 ])
      ("twalk", [ 1 ])
      ("twalk_r", [ 1 ])
      ("tdestroy", [ 1 ])
      ("scandir", [ 2; 3 ])
      ("scandirat", [ 3; 4 ])
      ("ftw", [ 1 ])
      ("nftw", [ 1 ])
      ("dl_iterate_phdr", [ 0 ])
      ("pthread_create", [ 2 ])
      ("pthread_once", [ 1 ])
      ("pthread_atfork", [ 0; 1; 2 ])
      ("pthread_key_create", [ 1 ])
      ("signal", [ 1 ])
      ("bsd_signal", [ 1 ])
      ("sigset", [ 1 ])
      ("_obstack_begin", [ 3; 4 ])
      ("_obstack_begin_1", [ 3; 4 ]) ]
    |> Map.ofList

  /// Gets the zero-based indices of the arguments that pass the functions which
  /// the known function of the given name calls.
  let getCallbackArgsOfKnownFunc name =
    match knownCallbackFuncMap.TryGetValue name with
    | true, idxs -> idxs
    | false, _ -> []
end

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

namespace B2R2.MiddleEnd.LLVM

open System
open System.Text
open B2R2
open B2R2.FrontEnd.BinInterface

/// Exception raised when the LLVM IR builder is destroyed.
exception LLVMIRBuilderDestroyedException

/// LLVM IR builder, which takes in a series of LowUIR stmts and creates an LLVM
/// function that corresponds to the LowUIR stmts.
type LLVMIRBuilder (fname: string, hdl: BinHandle, ctxt: LLVMContext) =
  let sb = StringBuilder ()
  let [<Literal>] IndentSize = 2
  let mutable isDone = false
  let mutable indentLevel = 1
  let mutable identifier = 2
  let addrSize = hdl.ISA.WordSize |> WordSize.toRegType
  let [<Literal>] ASpace = "addrspace(1)"
  let attr = $"noalias nocapture {ctxt.DereferenceableAttribute}"
  let (!!) (str: string) = sb.Append str |> ignore
  let (!+) (str: string) = identifier <- identifier + 1; sb.Append str |> ignore
  do !! "define void @B2R2_"
     !! fname
     !! $"(i8 {ASpace}* {attr} %%0) {{\n"

  member __.Indent () =
    indentLevel <- indentLevel + 1

  member __.Dedent () =
    indentLevel <- indentLevel - 1

  member __.GetIndent () =
    String (' ', indentLevel * IndentSize)

  member __.EmitComment (s: string) =
    let indent = __.GetIndent ()
    !! $"{indent}; {s}\n"

  member __.EmitStmt (s: string) =
    let indent = __.GetIndent ()
    !! $"{indent}{s}\n"

  member private __.ToLLVMIdentifier (id: int) =
    $"%%{id}"

  member private __.GetRegisterInfo reg =
    let elm = Map.find reg ctxt.Context
    match elm.Size with
    | 1 -> elm.Offset, "i8"
    | 2 -> elm.Offset, "i16"
    | 4 -> elm.Offset, "i32"
    | 8 -> elm.Offset, "i64"
    | _ -> Utils.futureFeature ()

  member inline private __.GetID () = identifier

  member private __.LoadRegisterPtr indent reg =
    let id = __.GetID ()
    let ofs, sz = __.GetRegisterInfo reg
    !+ $"{indent}%%{id} = getelementptr i8, i8 {ASpace}* %%0, i64 {ofs}\n"
    !+ $"{indent}%%{id+1} = bitcast i8 {ASpace}* %%{id} to {sz} {ASpace}*\n"
    struct (id + 1, ofs, sz)

  member __.EmitRegLoad reg =
    let indent = __.GetIndent ()
    let struct (id, _, sz) = __.LoadRegisterPtr indent reg
    let rname = hdl.RegisterBay.RegIDToString reg
    !+ $"{indent}%%{id+1} = load {sz}, {sz} {ASpace}* %%{id} ; {rname}\n"
    id + 1 |> __.ToLLVMIdentifier

  member __.EmitPCLoad () =
    let pc = hdl.RegisterBay.ProgramCounter
    __.EmitRegLoad pc

  member __.EmitRegStore lreg rid =
    let indent = __.GetIndent ()
    let struct (lid, _, sz) = __.LoadRegisterPtr indent lreg
    let rname = hdl.RegisterBay.RegIDToString lreg
    !! $"{indent}store {sz} {rid}, {sz} {ASpace}* %%{lid} ; {rname}\n"

  member __.EmitPCStore target =
    let pc = hdl.RegisterBay.ProgramCounter
    __.EmitRegStore pc target

  member private __.GetLLVMType mtyp =
    match mtyp with
    | 1<rt> -> "i1"
    | 8<rt> -> "i8"
    | 16<rt> -> "i16"
    | 32<rt> -> "i32"
    | 64<rt> -> "i64"
    | _ -> Utils.futureFeature ()

  member __.EmitMemLoad mid mtyp =
    let id = __.GetID ()
    let indent = __.GetIndent ()
    let ptrType = __.GetLLVMType addrSize
    let sz = __.GetLLVMType mtyp
    !+ $"{indent}%%{id} = inttoptr {ptrType} {mid} to {sz} {ASpace}*\n"
    !+ $"{indent}%%{id+1} = load {sz}, {sz} {ASpace}* %%{id}\n"
    id + 1 |> __.ToLLVMIdentifier

  member __.EmitMemStore addr mtyp v =
    let id = __.GetID ()
    let indent = __.GetIndent ()
    let ptrType = __.GetLLVMType addrSize
    let sz = __.GetLLVMType mtyp
    !+ $"{indent}%%{id} = inttoptr {ptrType} {addr} to {sz} {ASpace}*\n"
    !! $"{indent}store {sz} {v}, {sz} {ASpace}* %%{id}\n"

  member __.EmitBinOp opstr typ lhs rhs =
    let id = __.GetID ()
    let indent = __.GetIndent ()
    let sz = __.GetLLVMType typ
    !+ $"{indent}%%{id} = {opstr} {sz} {lhs}, {rhs}\n"
    id |> __.ToLLVMIdentifier

  member __.EmitExtract e (etyp: RegType) len pos =
    let id = __.GetID ()
    let indent = __.GetIndent ()
    Utils.futureFeature () // FIXME
    id |> __.ToLLVMIdentifier

  /// Emit the LLVM IR string and destroy the builder.
  member __.Finalize () =
    __.EmitStmt "ret void"
    __.Dedent ()
    __.EmitStmt "}"
    let s = sb.ToString ()
    sb.Clear () |> ignore
    isDone <- true
    s

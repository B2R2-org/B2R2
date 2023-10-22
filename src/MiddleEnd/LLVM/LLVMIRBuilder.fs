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

open System.Text
open System.Collections.Generic
open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd.LLVM.LLVMExpr

/// LLVM IR builder, which takes in a series of LowUIR stmts and creates an LLVM
/// function that corresponds to the LowUIR stmts.
type LLVMIRBuilder (fname: string, addr, hdl: BinHandle, ctxt: LLVMContext) =
  let stmts = List<LLVMStmt> ()
  let sb = StringBuilder ()
  let mutable hasJumpToFinal = false
  let [<Literal>] Indent = "  "
  let [<Literal>] ASpace = "addrspace(1)"
  let addrSize = hdl.File.ISA.WordSize |> WordSize.toRegType
  let attr = $"noalias nocapture {ctxt.DereferenceableAttribute}"
  let newID typ = { Num = 0; IDType = typ }
  let renameID id (cnt: byref<int>) = cnt <- cnt + 1; id.Num <- cnt; $"%%{cnt}"
  let ctxtParam = newID $"i8 {ASpace}*"
  let (<+) (sb: StringBuilder) (s: string) = sb.Append(s).Append("\n") |> ignore

  member __.Address with get(): Addr = addr

  member __.EmitStmt (s: LLVMStmt) =
    stmts.Add s

  member __.EmitComment (s: string) =
    Comment $"{Indent}; {s}" |> __.EmitStmt

  member private __.GetRegisterInfo reg =
    let elm = Map.find reg ctxt.Context
    match elm.Size with
    | 1 -> elm, "i8"
    | 2 -> elm, "i16"
    | 4 -> elm, "i32"
    | 8 -> elm, "i64"
    | _ -> Utils.futureFeature ()

  member private __.GetLLVMType mtyp =
    match mtyp with
    | 1<rt> -> "i1"
    | 8<rt> -> "i8"
    | 16<rt> -> "i16"
    | 32<rt> -> "i32"
    | 64<rt> -> "i64"
    | _ -> Utils.futureFeature ()

  member private __.AddrToLabel (addr: Addr) =
    $"bbl.{addr:x}"

  member __.EmitLabel addr =
    __.AddrToLabel addr |> LMark |> __.EmitStmt

  member __.Number (num: uint64) (len: RegType) =
    Number (num, __.GetLLVMType len)

  member private __.LoadRegisterPtr reg =
    let elm, sz = __.GetRegisterInfo reg
    let ofs = elm.Offset
    let var1 = newID $"i8 {ASpace}*"
    let var2 = newID $"{sz} {ASpace}*"
    __.EmitStmt <| LLVMStmt.mkGetElementPtr var1 ctxtParam ofs
    __.EmitStmt <| LLVMStmt.mkBitcast var2 (mkTypedId var1) $"{sz} {ASpace}*"
    struct (var2, elm, sz)

  member __.EmitRegLoad reg =
    let struct (ptr, elm, sz) = __.LoadRegisterPtr reg
    let rname = hdl.RegisterBay.RegIDToString reg
    let rvar = newID sz
    __.EmitStmt <| LLVMStmt.mkLoad rvar ptr (Some $"; {rname}")
    if RegType.toBitWidth elm.RType = elm.Size * 8 then
      Ident rvar
    else
      let rtype = __.GetLLVMType elm.RType
      let rvar' = newID rtype
      __.EmitStmt <| LLVMStmt.mkTrunc rvar' (mkTypedId rvar) rtype
      Ident rvar'

  member __.EmitPCLoad () =
    let pc = hdl.RegisterBay.ProgramCounter
    __.EmitRegLoad pc

  member __.EmitRegStore lreg rexp =
    let struct (ptr, elm, sz) = __.LoadRegisterPtr lreg
    let rname = hdl.RegisterBay.RegIDToString lreg
    if RegType.toBitWidth elm.RType = elm.Size * 8 then (* normal case *)
      __.EmitStmt <| LLVMStmt.mkStore rexp ptr None (Some rname)
    else
      let extendedReg = newID sz
      let rexp =
        match rexp with
        | Ident r -> mkTypedId r
        | Number _ -> TypedExpr (__.GetLLVMType elm.RType, rexp)
        | _ -> Utils.futureFeature ()
      __.EmitStmt <| LLVMStmt.mkZExt extendedReg rexp sz
      __.EmitStmt <| LLVMStmt.mkStore (Ident extendedReg) ptr None (Some rname)

  member __.EmitBranchToFinal () =
    hasJumpToFinal <- true
    Branch (None, [| Label "final" |]) |> __.EmitStmt

  member __.EmitPCStore target =
    let pc = hdl.RegisterBay.ProgramCounter
    __.EmitRegStore pc target
    __.EmitBranchToFinal ()

  member __.EmitBranch targets succs =
    let targets = targets |> List.filter (fun t -> List.contains t succs)
    if List.isEmpty targets then ()
    else
      let lbl = targets |> List.map (__.AddrToLabel >> Label) |> List.toArray
      Branch (None, lbl) |> __.EmitStmt

  member __.EmitInterJmp target succs =
    match target with
    | Number (addr, _) -> __.EmitBranch [ addr ] succs
    | _ -> __.EmitPCStore target

  member __.EmitCondBranch cond t f succs =
    match List.contains t succs, List.contains f succs with
    | true, true ->
      let lbls = [| Label (__.AddrToLabel t); Label (__.AddrToLabel f) |]
      Branch (Some cond, lbls) |> __.EmitStmt
    | true, false ->
      hasJumpToFinal <- true
      let lbls = [| Label (__.AddrToLabel t); Label "final" |]
      Branch (Some cond, lbls) |> __.EmitStmt
    | false, true ->
      hasJumpToFinal <- true
      let lbls = [| Label "final"; Label (__.AddrToLabel f) |]
      Branch (Some cond, lbls) |> __.EmitStmt
    | _ ->
      hasJumpToFinal <- true
      let lbls = [| Label "final"; Label "final" |]
      Branch (Some cond, lbls) |> __.EmitStmt

  member __.EmitInterCJmp typ cond t f succs =
    match t, f with
    | Number (t, _), Number (f, _) -> __.EmitCondBranch cond t f succs
    | _ ->
      let pc = newID <| __.GetLLVMType typ
      let addrType = __.GetLLVMType addrSize
      __.EmitStmt <| LLVMStmt.mkSelect pc cond addrType t f
      __.EmitPCStore (Ident pc)

  member __.EmitMemLoad mexpr mtyp =
    let intType = __.GetLLVMType addrSize
    let sz = __.GetLLVMType mtyp
    let ptr = newID $"{sz} {ASpace}*"
    let loadVal = newID sz
    __.EmitStmt <| LLVMStmt.mkIntToPtr ptr intType mexpr ptr.IDType
    __.EmitStmt <| LLVMStmt.mkLoad loadVal ptr None
    Ident loadVal

  member __.EmitMemStore addr mtyp v =
    let intType = __.GetLLVMType addrSize
    let sz = __.GetLLVMType mtyp
    let ptr = newID $"{sz} {ASpace}*"
    __.EmitStmt <| LLVMStmt.mkIntToPtr ptr intType addr ptr.IDType
    __.EmitStmt <| LLVMStmt.mkStore v ptr None None

  member __.EmitUnOp opstr exp etyp =
    let sz = __.GetLLVMType etyp
    match opstr, exp with
    | "not", Ident id ->
      let var = newID sz
      __.EmitStmt <| LLVMStmt.mkBinop var "xor" sz exp (Token "-1")
      Ident var
    | _ -> Utils.futureFeature()

  member __.EmitBinOp opstr typ lhs rhs =
    let sz = __.GetLLVMType typ
    let var = newID sz
    __.EmitStmt <| LLVMStmt.mkBinop var opstr sz lhs rhs
    Ident var

  member __.EmitRelOp opstr typ lhs rhs =
    let sz = __.GetLLVMType typ
    let var = newID "i1"
    __.EmitStmt <| LLVMStmt.mkIcmp var opstr sz lhs rhs
    Ident var

  member __.EmitCast e kind etyp rt =
    let fromSz = __.GetLLVMType etyp
    let toSz = __.GetLLVMType rt
    let var = newID toSz
    __.EmitStmt <| LLVMStmt.mkCast var kind fromSz e toSz
    Ident var

  member __.EmitExtract e (etyp: RegType) (len: RegType) pos =
    let sz = __.GetLLVMType etyp
    let extSz = __.GetLLVMType len
    let tmp = newID sz
    let finalVal = newID extSz
    __.EmitStmt <| LLVMStmt.mkBinop tmp "lshr" sz e (Number (uint64 pos, sz))
    __.EmitStmt <| LLVMStmt.mkTrunc finalVal (mkTypedId tmp) extSz
    Ident finalVal

  member private __.ExprToString expr =
    match expr with
    | Ident id -> $"%%{id.Num}"
    | Opcode op -> op
    | Label lbl -> $"label %%{lbl}"
    | PhiNode (id, lbl) ->
      let id = __.ExprToString id
      let lbl = __.ExprToString lbl
      $"[ {id}, {lbl} ]"
    | Number (n, _) -> n.ToString ()
    | ExprList exprs -> exprs |> List.map __.ExprToString |> String.concat ", "
    | Token s -> s
    | TypedExpr (typ, e) -> $"{typ} {__.ExprToString e}"

  member private __.StoreStmtToString v addr align comment =
    let addr = $"{addr.IDType} %%{addr.Num}"
    let align = match align with Some a -> $", align {a}" | None -> ""
    let comment = match comment with Some c -> $"; {c}" | None -> ""
    sb <+ $"{Indent}store {v}, {addr}{align}{comment}"

  member private __.StmtsToString () =
    let mutable idCount = 1
    for stmt in stmts do
      match stmt with
      | LMark lbl -> sb <+ $"{lbl}:"
      | Branch (Some cond, lbls) ->
        let lbls = lbls |> Array.map __.ExprToString |> String.concat ", "
        sb <+ $"{Indent}br i1 {__.ExprToString cond}, {lbls}"
      | Branch (None, lbls) ->
        let lbls = lbls |> Array.map __.ExprToString |> String.concat ", "
        sb <+ $"{Indent}br {lbls}"
      | Def (lhs, rhs) ->
        let rhs = rhs |> Array.map __.ExprToString |> String.concat " "
        sb <+ $"{Indent}{renameID lhs &idCount} = {rhs}"
      | Store (Number (v, t), Ident addr, align, comment) ->
        let v = $"{t} {v}"
        __.StoreStmtToString v addr align comment
      | Store (Ident v, Ident addr, align, comment) ->
        let v = $"{v.IDType} %%{v.Num}"
        __.StoreStmtToString v addr align comment
      | Comment s -> sb <+ s
      | _ -> printfn "%A" stmt; Utils.futureFeature ()
    done

  /// Emit the LLVM IR string and destroy the builder.
  member __.Finalize () =
    sb <+ $"define void @F_{fname}(i8 {ASpace}* {attr} %%0) {{"
    __.StmtsToString ()
    sb <+ "  ret void"
    if hasJumpToFinal then sb <+ "final:"; sb <+ "  ret void" else ()
    sb <+ "}"
    let s = sb.ToString ()
    sb.Clear () |> ignore
    s

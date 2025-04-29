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

  member _.Address with get(): Addr = addr

  member _.EmitStmt (s: LLVMStmt) =
    stmts.Add s

  member this.EmitComment (s: string) =
    Comment $"{Indent}; {s}" |> this.EmitStmt

  member private _.GetRegisterInfo reg =
    let elm = Map.find reg ctxt.Context
    match elm.Size with
    | 1 -> elm, "i8"
    | 2 -> elm, "i16"
    | 4 -> elm, "i32"
    | 8 -> elm, "i64"
    | _ -> Terminator.futureFeature ()

  member private _.GetLLVMType mtyp =
    match mtyp with
    | 1<rt> -> "i1"
    | 8<rt> -> "i8"
    | 16<rt> -> "i16"
    | 32<rt> -> "i32"
    | 64<rt> -> "i64"
    | _ -> Terminator.futureFeature ()

  member private _.AddrToLabel (addr: Addr) =
    $"bbl.{addr:x}"

  member this.EmitLabel addr =
    this.AddrToLabel addr |> LMark |> this.EmitStmt

  member this.Number (num: uint64) (len: RegType) =
    Number (num, this.GetLLVMType len)

  member private this.LoadRegisterPtr reg =
    let elm, sz = this.GetRegisterInfo reg
    let ofs = elm.Offset
    let var1 = newID $"i8 {ASpace}*"
    let var2 = newID $"{sz} {ASpace}*"
    this.EmitStmt <| LLVMStmt.mkGetElementPtr var1 ctxtParam ofs
    this.EmitStmt <| LLVMStmt.mkBitcast var2 (mkTypedId var1) $"{sz} {ASpace}*"
    struct (var2, elm, sz)

  member this.EmitRegLoad reg =
    let struct (ptr, elm, sz) = this.LoadRegisterPtr reg
    let rname = hdl.RegisterFactory.GetRegString reg
    let rvar = newID sz
    this.EmitStmt <| LLVMStmt.mkLoad rvar ptr (Some $"; {rname}")
    if RegType.toBitWidth elm.RType = elm.Size * 8 then
      Ident rvar
    else
      let rtype = this.GetLLVMType elm.RType
      let rvar' = newID rtype
      this.EmitStmt <| LLVMStmt.mkTrunc rvar' (mkTypedId rvar) rtype
      Ident rvar'

  member this.EmitPCLoad () =
    let pc = hdl.RegisterFactory.ProgramCounter
    this.EmitRegLoad pc

  member this.EmitRegStore lreg rexp =
    let struct (ptr, elm, sz) = this.LoadRegisterPtr lreg
    let rname = hdl.RegisterFactory.GetRegString lreg
    if RegType.toBitWidth elm.RType = elm.Size * 8 then (* normal case *)
      this.EmitStmt <| LLVMStmt.mkStore rexp ptr None (Some rname)
    else
      let extendedReg = newID sz
      let rexp =
        match rexp with
        | Ident r -> mkTypedId r
        | Number _ -> TypedExpr (this.GetLLVMType elm.RType, rexp)
        | _ -> Terminator.futureFeature ()
      this.EmitStmt <| LLVMStmt.mkZExt extendedReg rexp sz
      this.EmitStmt
      <| LLVMStmt.mkStore (Ident extendedReg) ptr None (Some rname)

  member this.EmitBranchToFinal () =
    hasJumpToFinal <- true
    Branch (None, [| Label "final" |]) |> this.EmitStmt

  member this.EmitPCStore target =
    let pc = hdl.RegisterFactory.ProgramCounter
    this.EmitRegStore pc target
    this.EmitBranchToFinal ()

  member this.EmitBranch targets succs =
    let targets = targets |> List.filter (fun t -> List.contains t succs)
    if List.isEmpty targets then ()
    else
      let lbl = targets |> List.map (this.AddrToLabel >> Label) |> List.toArray
      Branch (None, lbl) |> this.EmitStmt

  member this.EmitInterJmp target succs =
    match target with
    | Number (addr, _) -> this.EmitBranch [ addr ] succs
    | _ -> this.EmitPCStore target

  member this.EmitCondBranch cond t f succs =
    match List.contains t succs, List.contains f succs with
    | true, true ->
      let lbls = [| Label (this.AddrToLabel t); Label (this.AddrToLabel f) |]
      Branch (Some cond, lbls) |> this.EmitStmt
    | true, false ->
      hasJumpToFinal <- true
      let lbls = [| Label (this.AddrToLabel t); Label "final" |]
      Branch (Some cond, lbls) |> this.EmitStmt
    | false, true ->
      hasJumpToFinal <- true
      let lbls = [| Label "final"; Label (this.AddrToLabel f) |]
      Branch (Some cond, lbls) |> this.EmitStmt
    | _ ->
      hasJumpToFinal <- true
      let lbls = [| Label "final"; Label "final" |]
      Branch (Some cond, lbls) |> this.EmitStmt

  member this.EmitInterCJmp typ cond t f succs =
    match t, f with
    | Number (t, _), Number (f, _) -> this.EmitCondBranch cond t f succs
    | _ ->
      let pc = newID <| this.GetLLVMType typ
      let addrType = this.GetLLVMType addrSize
      this.EmitStmt <| LLVMStmt.mkSelect pc cond addrType t f
      this.EmitPCStore (Ident pc)

  member this.EmitMemLoad mexpr mtyp =
    let intType = this.GetLLVMType addrSize
    let sz = this.GetLLVMType mtyp
    let ptr = newID $"{sz} {ASpace}*"
    let loadVal = newID sz
    this.EmitStmt <| LLVMStmt.mkIntToPtr ptr intType mexpr ptr.IDType
    this.EmitStmt <| LLVMStmt.mkLoad loadVal ptr None
    Ident loadVal

  member this.EmitMemStore addr mtyp v =
    let intType = this.GetLLVMType addrSize
    let sz = this.GetLLVMType mtyp
    let ptr = newID $"{sz} {ASpace}*"
    this.EmitStmt <| LLVMStmt.mkIntToPtr ptr intType addr ptr.IDType
    this.EmitStmt <| LLVMStmt.mkStore v ptr None None

  member this.EmitUnOp opstr exp etyp =
    let sz = this.GetLLVMType etyp
    match opstr, exp with
    | "not", Ident id ->
      let var = newID sz
      this.EmitStmt <| LLVMStmt.mkBinop var "xor" sz exp (Token "-1")
      Ident var
    | _ -> Terminator.futureFeature()

  member this.EmitBinOp opstr typ lhs rhs =
    let sz = this.GetLLVMType typ
    let var = newID sz
    this.EmitStmt <| LLVMStmt.mkBinop var opstr sz lhs rhs
    Ident var

  member this.EmitRelOp opstr typ lhs rhs =
    let sz = this.GetLLVMType typ
    let var = newID "i1"
    this.EmitStmt <| LLVMStmt.mkIcmp var opstr sz lhs rhs
    Ident var

  member this.EmitCast e kind etyp rt =
    let fromSz = this.GetLLVMType etyp
    let toSz = this.GetLLVMType rt
    let var = newID toSz
    this.EmitStmt <| LLVMStmt.mkCast var kind fromSz e toSz
    Ident var

  member this.EmitExtract e (etyp: RegType) (len: RegType) pos =
    let sz = this.GetLLVMType etyp
    let extSz = this.GetLLVMType len
    let tmp = newID sz
    let finalVal = newID extSz
    this.EmitStmt <| LLVMStmt.mkBinop tmp "lshr" sz e (Number (uint64 pos, sz))
    this.EmitStmt <| LLVMStmt.mkTrunc finalVal (mkTypedId tmp) extSz
    Ident finalVal

  member private this.ExprToString expr =
    match expr with
    | Ident id -> $"%%{id.Num}"
    | Opcode op -> op
    | Label lbl -> $"label %%{lbl}"
    | PhiNode (id, lbl) ->
      let id = this.ExprToString id
      let lbl = this.ExprToString lbl
      $"[ {id}, {lbl} ]"
    | Number (n, _) -> n.ToString ()
    | ExprList exprs ->
      exprs |> List.map this.ExprToString |> String.concat ", "
    | Token s -> s
    | TypedExpr (typ, e) -> $"{typ} {this.ExprToString e}"

  member private _.StoreStmtToString v addr align comment =
    let addr = $"{addr.IDType} %%{addr.Num}"
    let align = match align with Some a -> $", align {a}" | None -> ""
    let comment = match comment with Some c -> $"; {c}" | None -> ""
    sb <+ $"{Indent}store {v}, {addr}{align}{comment}"

  member private this.StmtsToString () =
    let mutable idCount = 1
    for stmt in stmts do
      match stmt with
      | LMark lbl -> sb <+ $"{lbl}:"
      | Branch (Some cond, lbls) ->
        let lbls = lbls |> Array.map this.ExprToString |> String.concat ", "
        sb <+ $"{Indent}br i1 {this.ExprToString cond}, {lbls}"
      | Branch (None, lbls) ->
        let lbls = lbls |> Array.map this.ExprToString |> String.concat ", "
        sb <+ $"{Indent}br {lbls}"
      | Def (lhs, rhs) ->
        let rhs = rhs |> Array.map this.ExprToString |> String.concat " "
        sb <+ $"{Indent}{renameID lhs &idCount} = {rhs}"
      | Store (Number (v, t), Ident addr, align, comment) ->
        let v = $"{t} {v}"
        this.StoreStmtToString v addr align comment
      | Store (Ident v, Ident addr, align, comment) ->
        let v = $"{v.IDType} %%{v.Num}"
        this.StoreStmtToString v addr align comment
      | Comment s -> sb <+ s
      | _ -> printfn "%A" stmt; Terminator.futureFeature ()
    done

  /// Emit the LLVM IR string and destroy the builder.
  override this.ToString () =
    sb <+ $"define void @F_{fname}(i8 {ASpace}* {attr} %%0) {{"
    this.StmtsToString ()
    sb <+ "  ret void"
    if hasJumpToFinal then sb <+ "final:"; sb <+ "  ret void" else ()
    sb <+ "}"
    let s = sb.ToString ()
    sb.Clear () |> ignore
    s

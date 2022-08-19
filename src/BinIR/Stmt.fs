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

namespace B2R2.BinIR.LowUIR

open System
open System.Text
#if HASHCONS
open LanguagePrimitives
#endif
open B2R2
open B2R2.BinIR

/// The kind of an InterJmp. Multiple kinds can present for a jump instruction.
[<Flags>]
type InterJmpKind =
  /// The base case, i.e., a simple jump instruction.
  | Base = 0
  /// A call to a function.
  | IsCall = 1
  /// A return from a function.
  | IsRet = 2
  /// An exit, which will terminate the process.
  | IsExit = 4
  /// A branch instructino that modifies the operation mode from Thumb to ARM.
  | SwitchToARM = 8
  /// A branch instructino that modifies the operation mode from ARM to Thumb.
  | SwitchToThumb = 16
  /// This is not a jump instruction. This is only useful in special cases such
  /// as when representing a delay slot of MIPS, and should never be used in
  /// other cases.
  | NotAJmp = -1

/// IL Statements.
/// NOTE: You MUST create Expr/Stmt through the AST module. *NEVER* directly
/// construct Expr nor Stmt.
#if ! HASHCONS
#else
[<CustomEquality; NoComparison>]
#endif
type S =
  /// Metadata representing the start of a machine instruction. More
  /// specifically, it contains the length of the instruction. There must be a
  /// single IMark per a machine instruction.
  | ISMark of uint32

  /// Metadata representing the end of a machine instruction. It contains the
  /// length of the current instruction.
  | IEMark of uint32

  /// Metadata representing a label (as in an assembly language). LMark is only
  /// valid within a machine instruction.
  | LMark of Symbol

  /// This statement puts a value into a register. The first argument is a
  /// destination operand, and the second argument is a source operand. The
  /// destination operand should have either a Var or a TempVar.
  ///
  /// Example: [Put(T_1:I32, Load(LE, T_2:I32))]
  /// loads a 32-bit value from the address T2, and store the value to the
  /// temporary register T1.
  | Put of Expr * Expr

  /// This statement stores a value into a memory. The first argument
  /// represents the endianness, the second argument is a destination operand,
  /// and the third argument is a value to store.
  ///
  /// Example: Store(LE, T_1:I32, T_2:I32)
  /// stores a 32-bit value T_2 into the address T_1
  | Store of Endian * Expr * Expr

  /// This statement represents a jump (unconditional) to an LMark. The first
  /// argument specifies the target address.
  | Jmp of Expr

  /// This statement represents a conditional jump to an LMark. The first
  /// argument specifies a jump condition. If the condition is true, jump to
  /// the address specified by the second argument. Otherwise, jump to the
  /// address specified by the third argument.
  | CJmp of Expr * Expr * Expr

  /// This is an unconditional jump instruction to another instruction. This is
  /// an inter-instruction jump unlike Jmp statement. The first argument is the
  /// jump target address.
  | InterJmp of Expr * InterJmpKind

  /// This is a conditional jump instruction to another instruction. The first
  /// argument specifies a jump condition. If the condition is true, change the
  /// program counter to jump to the address specified by the second argument.
  /// Otherwise, jump to the address specified by the third argument.
  | InterCJmp of Expr * Expr * Expr

  /// External function call. This statement represents a uninterpreted function
  /// call. The argument expression is in a curried form.
  | ExternalCall of Expr

  /// This represents an instruction with side effects such as a system call.
  | SideEffect of SideEffect
#if ! HASHCONS
#else
with
  override __.Equals rhs =
    match rhs with
    | :? S as rhs ->
      match __, rhs with
      | ISMark len1, ISMark len2 -> len1 = len2
      | IEMark len1, IEMark len2 -> len1 = len2
      | LMark s1, LMark s2 -> s1 = s2
      | Put (dst1, src1), Put (dst2, src2) ->
        dst1.Tag = dst2.Tag && src1.Tag = src2.Tag
      | Store (n1, addr1, e1), Store (n2, addr2, e2) ->
        n1 = n2 && addr1 = addr2 && e1.Tag = e2.Tag
      | Jmp (e1), Jmp (e2) -> e1.Tag = e2.Tag
      | CJmp (c1, t1, f1), CJmp (c2, t2, f2) ->
        c1.Tag = c2.Tag && t1.Tag = t2.Tag && f1.Tag = f2.Tag
      | InterJmp (e1, k1), InterJmp (e2, k2) -> e1.Tag = e2.Tag && k1 = k2
      | InterCJmp (c1, t1, f1), InterCJmp (c2, t2, f2) ->
        c1.Tag = c2.Tag && t1.Tag = t2.Tag && f1.Tag = f2.Tag
      | SideEffect e1, SideEffect e2 -> e1 = e2
      | _ -> false
    | _ -> false

  static member inline HashISMark (len: uint32) = len.GetHashCode () + 1

  static member inline HashIEMark (len: uint32) = 19 * len.GetHashCode () + 2

  static member inline HashLMark ((s, n): Symbol) =
    19 * (19 * s.GetHashCode () + n) + 3

  static member inline HashPut (dst: Expr) (src: Expr) =
    19 * (19 * dst.HashKey + src.HashKey) + 4

  static member inline HashStore (n: Endian) (addr: Expr) (e: Expr) =
    19 * (19 * (19 * int n + addr.HashKey) + e.HashKey) + 5

  static member inline HashJmp (e: Expr) =
    19 * (19 * e.HashKey + 1) + 6

  static member inline HashCJmp (cond: Expr) (t: Expr) (f: Expr) =
    19 * (19 * (19 * cond.HashKey + t.HashKey) + f.HashKey) + 7

  static member inline HashInterJmp (e: Expr) (k: InterJmpKind) =
    19 * (19 * e.HashKey + int k) + 8

  static member inline HashInterCJmp (cond: Expr) (t: Expr) (f: Expr) =
    19 * (19 * (19 * cond.HashKey + t.HashKey) + f.HashKey) + 9

  static member inline HashExtCall (e: Expr) =
    (19 * e.HashKey) + 10

  static member inline HashSideEffect (e: SideEffect) =
    (19 * hash e) + 11

  override __.GetHashCode () =
    match __ with
    | ISMark len -> S.HashISMark len
    | IEMark len -> S.HashIEMark len
    | LMark s -> S.HashLMark s
    | Put (dst, src) -> S.HashPut dst src
    | Store (n, addr, e) -> S.HashStore n addr e
    | Jmp (e) -> S.HashJmp e
    | CJmp (cond, t, f) -> S.HashCJmp cond t f
    | InterJmp (e, k) -> S.HashInterJmp e k
    | InterCJmp (cond, t, f) -> S.HashInterCJmp cond t f
    | ExternalCall (e) -> S.HashExtCall e
    | SideEffect (e) -> S.HashSideEffect e
#endif

#if ! HASHCONS
/// When hash-consing is not used, we simply create a wrapper for an AST node.
and [<Struct>] Stmt = {
  /// The actual AST node.
  S: S
}
#else
/// Hash-consed Stmt.
and [<CustomEquality; NoComparison>] Stmt = {
  /// The actual AST node.
  S: S
  /// Unique id.
  Tag: uint32
  /// Hash cache.
  HashKey: int
}
with
  override __.Equals rhs =
    match rhs with
    | :? Stmt as rhs -> __.Tag = rhs.Tag
    | _ -> false

  override __.GetHashCode () = __.HashKey
#endif

module Stmt =
  let appendToString stmt (sb: StringBuilder) =
    match stmt.S with
    | ISMark (len) ->
      sb.Append ("(") |> ignore
      sb.Append (len.ToString ()) |> ignore
      sb.Append (") {") |> ignore
    | IEMark (len) ->
      sb.Append ("} // ") |> ignore
      sb.Append (len.ToString ()) |> ignore
    | LMark lbl ->
      sb.Append (":") |> ignore
      sb.Append (Symbol.getName lbl) |> ignore
    | Put (exp1, exp2) ->
      Expr.appendToString exp1 sb
      sb.Append (" := ") |> ignore
      Expr.appendToString exp2 sb
    | Jmp exp ->
      sb.Append ("jmp ") |> ignore
      Expr.appendToString exp sb
    | InterJmp (exp, _) ->
      sb.Append ("ijmp ") |> ignore
      Expr.appendToString exp sb
    | Store (_endian, exp1, exp2) ->
      sb.Append ("[") |> ignore
      Expr.appendToString exp1 sb
      sb.Append ("] := ") |> ignore
      Expr.appendToString exp2 sb
    | CJmp (cond, t, f) ->
      sb.Append ("if ") |> ignore
      Expr.appendToString cond sb
      sb.Append (" then jmp ") |> ignore
      Expr.appendToString t sb
      sb.Append (" else jmp ") |> ignore
      Expr.appendToString f sb
    | InterCJmp (cond, t, f) ->
      sb.Append ("if ") |> ignore
      Expr.appendToString cond sb
      sb.Append (" then ijmp ") |> ignore
      Expr.appendToString t sb
      sb.Append (" else ijmp ") |> ignore
      Expr.appendToString f sb
    | ExternalCall (args) ->
      sb.Append ("Call") |> ignore
      Expr.appendToString args sb
    | SideEffect eff ->
      sb.Append ("!!" + SideEffect.toString eff) |> ignore

  let toString stmt =
    let sb = StringBuilder ()
    appendToString stmt sb
    sb.ToString ()

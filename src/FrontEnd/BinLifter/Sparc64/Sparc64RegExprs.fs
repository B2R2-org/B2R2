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

namespace B2R2.FrontEnd.BinLifter.Sparc64

open B2R2
open B2R2.FrontEnd.BinLifter
open B2R2.BinIR.LowUIR

type internal RegExprs (wordSize) =
  let var sz t name = AST.var sz t name (Sparc64RegisterSet.singleton t)

  (* Registers *)
  let regType = WordSize.toRegType wordSize

  member val G0 = var regType (Register.toRegID Register.G0) "G0" with get
  member val G1 = var regType (Register.toRegID Register.G1) "G1" with get
  member val G2 = var regType (Register.toRegID Register.G2) "G2" with get
  member val G3 = var regType (Register.toRegID Register.G3) "G3" with get
  member val G4 = var regType (Register.toRegID Register.G4) "G4" with get
  member val G5 = var regType (Register.toRegID Register.G1) "G5" with get
  member val G6 = var regType (Register.toRegID Register.G6) "G6" with get
  member val G7 = var regType (Register.toRegID Register.G1) "G7" with get
  member val O0 = var regType (Register.toRegID Register.O0) "O0" with get
  member val O1 = var regType (Register.toRegID Register.O1) "O1" with get
  member val O2 = var regType (Register.toRegID Register.O2) "O2" with get
  member val O3 = var regType (Register.toRegID Register.O3) "O3" with get
  member val O4 = var regType (Register.toRegID Register.O4) "O4" with get
  member val O5 = var regType (Register.toRegID Register.O5) "O5" with get
  member val O6 = var regType (Register.toRegID Register.O6) "O6" with get
  member val O7 = var regType (Register.toRegID Register.O7) "O7" with get
  member val L0 = var regType (Register.toRegID Register.L0) "L0" with get
  member val L1 = var regType (Register.toRegID Register.L1) "L1" with get
  member val L2 = var regType (Register.toRegID Register.L2) "L2" with get
  member val L3 = var regType (Register.toRegID Register.L3) "L3" with get
  member val L4 = var regType (Register.toRegID Register.L4) "L4" with get
  member val L5 = var regType (Register.toRegID Register.L5) "L5" with get
  member val L6 = var regType (Register.toRegID Register.L6) "L6" with get
  member val L7 = var regType (Register.toRegID Register.L7) "L7" with get
  member val I0 = var regType (Register.toRegID Register.I0) "I0" with get
  member val I1 = var regType (Register.toRegID Register.I1) "I1" with get
  member val I2 = var regType (Register.toRegID Register.I2) "I2" with get
  member val I3 = var regType (Register.toRegID Register.I3) "I3" with get
  member val I4 = var regType (Register.toRegID Register.I4) "I4" with get
  member val I5 = var regType (Register.toRegID Register.I5) "I5" with get
  member val I6 = var regType (Register.toRegID Register.I6) "I6" with get
  member val I7 = var regType (Register.toRegID Register.I7) "I7" with get
  member val PC = var regType (Register.toRegID Register.PC) "PC" with get
  member val NPC = var regType (Register.toRegID Register.NPC) "nPC" with get
  member val Y = var regType (Register.toRegID Register.Y) "Y" with get
  member val CCR = var regType (Register.toRegID Register.CCR) "CCR" with get

  member __.GetRegVar (name) =
    match name with
    | R.G0 -> __.G0
    | R.G1 -> __.G1
    | R.G2 -> __.G2
    | R.G3 -> __.G3
    | R.G4 -> __.G4
    | R.G5 -> __.G5
    | R.G6 -> __.G6
    | R.G7 -> __.G7
    | R.O0 -> __.O0
    | R.O1 -> __.O1
    | R.O2 -> __.O2
    | R.O3 -> __.O3
    | R.O4 -> __.O4
    | R.O5 -> __.O5
    | R.O6 -> __.O6
    | R.O7 -> __.O7
    | R.L0 -> __.L0
    | R.L1 -> __.L1
    | R.L2 -> __.L2
    | R.L3 -> __.L3
    | R.L4 -> __.L4
    | R.L5 -> __.L5
    | R.L6 -> __.L6
    | R.L7 -> __.L7
    | R.I0 -> __.I0
    | R.I1 -> __.I1
    | R.I2 -> __.I2
    | R.I3 -> __.I3
    | R.I4 -> __.I4
    | R.I5 -> __.I5
    | R.I6 -> __.I6
    | R.I7 -> __.I7
    | R.PC -> __.PC
    | R.CCR -> __.CCR
    | _ -> raise UnhandledRegExprException

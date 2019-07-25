(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Michael Tegegn <mick@kaist.ac.kr>
          Sang Kil Cha <sangkilc@kaist.ac.kr>

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

module B2R2.NameMangling.MSUtils

let getSpecialName n =
  match n with
  | '2' -> "operator new"
  | '3' -> "operator delete"
  | '4' -> "operator="
  | '5' -> "operator>>"
  | '6' -> "operator<<"
  | '7' -> "operator!"
  | '8' -> "operator=="
  | '9' -> "operator!="
  | 'A' -> "operator[]"
  | 'B' -> "operator returntype"
  | 'C' -> "operator->"
  | 'D' -> "operator*"
  | 'E' -> "operator++"
  | 'F' -> "operator--"
  | 'G' -> "operator-"
  | 'H' -> "operator+"
  | 'I' -> "operator&"
  | 'J' -> "operator->*"
  | 'K' -> "operator/"
  | 'L' -> "operator%"
  | 'M' -> "operator<"
  | 'N' -> "operator<="
  | 'O' -> "operator>"
  | 'P' -> "operator>="
  | 'Q' -> "operator,"
  | 'R' -> "operator()"
  | 'S' -> "operator~"
  | 'T' -> "operator~"
  | 'U' -> "operator|"
  | 'V' -> "operator&&"
  | 'W' -> "operator||"
  | 'X' -> "operator*="
  | 'Y' -> "operator+="
  | 'Z' -> "operator -="
  | _ -> sprintf "not a valid special name %c" n

let getUnderscoredSpecialName n =
  match n with
  | '0' -> "operator /="
  | '1' -> "operator %="
  | '2' -> "operator >>="
  | '3' -> "operator <<="
  | '4' -> "operator &="
  | '5' -> "operator |="
  | '6' -> "operator ^="
  | '7' -> "'vftable'"
  | '8' -> "'vbtable'"
  | '9' -> "'vcall'"
  | 'A' -> "'typeof'"
  | 'B' -> "'local static guard'"
  | 'C' -> "----string-----"
  | 'D' -> "'vbase destructor'"
  | 'E' -> "'vector deleting destructor'"
  | 'F' -> "'default constructor closure'"
  | 'G' -> "'scalar deleting destructor'"
  | 'H' -> "'vector constructor iterator'"
  | 'I' -> "'vector destructor iterator'"
  | 'J' -> "'vector vbase constructor iterator'"
  | 'K' -> "'virtual displacement map'"
  | 'L' -> "'eh vector constructor iterator'"
  | 'M' -> "'eh vector destructor iterator'"
  | 'N' -> "'eh vector vbase constructor iterator'"
  | 'O' -> "'copy constructor closure'"
  | 'P' -> "'udt returning' (prefix)"
  | 'Q' -> "Unknown"
  | 'R' -> "RTTI-related code (see below)"
  | 'S' -> "'local vftable'"
  | 'T' -> "'local vftable constructor closure'"
  | 'U' -> "operator new[]"
  | 'V' -> "operator delete[]"
  | 'W' -> "'omni callsig'"
  | 'X' -> "'placement delete closure'"
  | 'Y' -> "'placement delete[] closure'"
  | 'Z' -> ""
  | _ -> sprintf "not a valid special name  _%c" n

let getdUnderscoredSpecialName n =
  match n with
  | 'A' -> "'managed vector constructor iterator'"
  | 'B' -> "'managed vector destructor iterator'"
  | 'C' -> "'eh vector copy constructor iterator'"
  | 'D' -> "'eh vector vbase copy constructor iterator'"
  | 'E' -> "'dynamic initializer'"
  | 'F' -> "'dynamic atexit destructor`"
  | 'G' -> "'vector copy constructor iterator'"
  | 'H' -> "'vector vbase copy constructor iterator'"
  | 'I' -> "'managed vector copy constructor iterator'"
  | 'J' -> "'local static thread guard'"
  | 'K' -> "user defined literal operator"
  | _ -> sprintf "not a valid special name _%c" n

let getHexChar c =
  match c with
  | 'A' -> '0'
  | 'B' -> '1'
  | 'C' -> '2'
  | 'D' -> '3'
  | 'E' -> '4'
  | 'F' -> '5'
  | 'G' -> '6'
  | 'H' -> '7'
  | 'I' -> '8'
  | 'J' -> '9'
  | 'K' -> 'A'
  | 'L' -> 'B'
  | 'M' -> 'C'
  | 'N' -> 'D'
  | 'O' -> 'E'
  | 'P' -> 'F'
  | _ -> '?'

let getRTTI c =
  match c with
  | '2' -> "'RTTI Base Class Array'"
  | '3' -> "'RTTI Class Hierarchy Descriptor'"
  | '4' -> "'RTTI Complete Object Locator'"
  |  _  -> sprintf "not valid RTTI descriptor %c" c

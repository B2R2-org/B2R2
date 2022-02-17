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

module B2R2.FrontEnd.BinLifter.SH4.GeneralLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingOperators
open B2R2.FrontEnd.BinLifter.SH4

let add = function
  | _ -> Utils.futureFeature()

let addc = function
  | _ -> Utils.futureFeature()

let addv = function
  | _ -> Utils.futureFeature()

let ``and`` = function
  | _ -> Utils.futureFeature()

let andb= function
  | _ -> Utils.futureFeature()

let bf = function
  | _ -> Utils.futureFeature()

let bfs = function
  | _ -> Utils.futureFeature()

let bra = function
  | _ -> Utils.futureFeature()

let braf = function
  | _ -> Utils.futureFeature()

let bsr = function
  | _ -> Utils.futureFeature()

let bsrf = function
  | _ -> Utils.futureFeature()

let bt = function
  | _ -> Utils.futureFeature()

let bts = function
  | _ -> Utils.futureFeature()

let clrmac = function
  | _ -> Utils.futureFeature()

let clrs = function
  | _ -> Utils.futureFeature()

let clrt = function
  | _ -> Utils.futureFeature()

let cmpeq = function
  | _ -> Utils.futureFeature()

let cmpge = function
  | _ -> Utils.futureFeature()

let cmpgt = function
  | _ -> Utils.futureFeature()

let cmphi = function
  | _ -> Utils.futureFeature()

let cmphs = function
  | _ -> Utils.futureFeature()

let cmppl = function
  | _ -> Utils.futureFeature()

let cmppz = function
  | _ -> Utils.futureFeature()

let cmpstr = function
  | _ -> Utils.futureFeature()

let div0s = function
  | _ -> Utils.futureFeature()

let div0u = function
  | _ -> Utils.futureFeature()

let div1 = function
  | _ -> Utils.futureFeature()

let dmulsl = function
  | _ -> Utils.futureFeature()

let dmulul = function
  | _ -> Utils.futureFeature()

let dt = function
  | _ -> Utils.futureFeature()

let exts = function
  | _ -> Utils.futureFeature()

let extsb = function
  | _ -> Utils.futureFeature()

let extsw = function
  | _ -> Utils.futureFeature()

let extu = function
  | _ -> Utils.futureFeature()

let extub = function
  | _ -> Utils.futureFeature()

let extuw = function
  | _ -> Utils.futureFeature()

let fabs = function
  | _ -> Utils.futureFeature()

let fadd = function
  | _ -> Utils.futureFeature()

let fcmp = function
  | _ -> Utils.futureFeature()

let fcmpeq = function
  | _ -> Utils.futureFeature()

let fcmpgt = function
  | _ -> Utils.futureFeature()

let fcnvds = function
  | _ -> Utils.futureFeature()

let fcnvsd = function
  | _ -> Utils.futureFeature()

let fdiv = function
  | _ -> Utils.futureFeature()

let fipr = function
  | _ -> Utils.futureFeature()

let fldi0 = function
  | _ -> Utils.futureFeature()

let fldi1 = function
  | _ -> Utils.futureFeature()

let flds = function
  | _ -> Utils.futureFeature()

let ``float`` = function
  | _ -> Utils.futureFeature()

let fmac = function
  | _ -> Utils.futureFeature()

let fmov = function
  | _ -> Utils.futureFeature()

let fmovs = function
  | _ -> Utils.futureFeature()

let fmul = function
  | _ -> Utils.futureFeature()

let fneg = function
  | _ -> Utils.futureFeature()

let frchg = function
  | _ -> Utils.futureFeature()

let fschg = function
  | _ -> Utils.futureFeature()

let fsqrt = function
  | _ -> Utils.futureFeature()

let fsts = function
  | _ -> Utils.futureFeature()

let fsub = function
  | _ -> Utils.futureFeature()

let ftrc = function
  | _ -> Utils.futureFeature()

let ftrv = function
  | _ -> Utils.futureFeature()

let jmp = function
  | _ -> Utils.futureFeature()

let jsr = function
  | _ -> Utils.futureFeature()

let ldc = function
  | _ -> Utils.futureFeature()

let ldcl = function
  | _ -> Utils.futureFeature()

let lds = function
  | _ -> Utils.futureFeature()

let ldsl = function
  | _ -> Utils.futureFeature()

let ldtlb = function
  | _ -> Utils.futureFeature()

let macl = function
  | _ -> Utils.futureFeature()

let macw = function
  | _ -> Utils.futureFeature()

let mov = function
  | _ -> Utils.futureFeature()

let mova = function
  | _ -> Utils.futureFeature()

let movb = function
  | _ -> Utils.futureFeature()

let movw = function
  | _ -> Utils.futureFeature()

let movl = function
  | _ -> Utils.futureFeature()

let movcal = function
  | _ -> Utils.futureFeature()

let movt = function
  | _ -> Utils.futureFeature()

let mull = function
  | _ -> Utils.futureFeature()

let mulsw = function
  | _ -> Utils.futureFeature()

let muluw = function
  | _ -> Utils.futureFeature()

let neg = function
  | _ -> Utils.futureFeature()

let negc = function
  | _ -> Utils.futureFeature()

let nop = function
  | _ -> Utils.futureFeature()

let ``not`` = function
  | _ -> Utils.futureFeature()

let ocbi = function
  | _ -> Utils.futureFeature()

let ocbp = function
  | _ -> Utils.futureFeature()

let ocbwb = function
  | _ -> Utils.futureFeature()

let ``or`` = function
  | _ -> Utils.futureFeature()

let orb = function
  | _ -> Utils.futureFeature()

let pref = function
  | _ -> Utils.futureFeature()

let rotcl = function
  | _ -> Utils.futureFeature()

let rotcr = function
  | _ -> Utils.futureFeature()

let rotl = function
  | _ -> Utils.futureFeature()

let rotr = function
  | _ -> Utils.futureFeature()

let rte = function
  | _ -> Utils.futureFeature()

let rts = function
  | _ -> Utils.futureFeature()

let sets = function
  | _ -> Utils.futureFeature()

let sett = function
  | _ -> Utils.futureFeature()

let shad = function
  | _ -> Utils.futureFeature()

let shal = function
  | _ -> Utils.futureFeature()

let shar = function
  | _ -> Utils.futureFeature()

let shld = function
  | _ -> Utils.futureFeature()

let shll = function
  | _ -> Utils.futureFeature()

let shll2 = function
  | _ -> Utils.futureFeature()

let shll8 = function
  | _ -> Utils.futureFeature()

let shll16 = function
  | _ -> Utils.futureFeature()

let shlr = function
  | _ -> Utils.futureFeature()

let shlr2 = function
  | _ -> Utils.futureFeature()

let shlr8 = function
  | _ -> Utils.futureFeature()

let shlr16 = function
  | _ -> Utils.futureFeature()

let sleep = function
  | _ -> Utils.futureFeature()

let stc = function
  | _ -> Utils.futureFeature()

let stcl = function
  | _ -> Utils.futureFeature()

let sts = function
  | _ -> Utils.futureFeature()

let stsl = function
  | _ -> Utils.futureFeature()

let sub = function
  | _ -> Utils.futureFeature()

let subc = function
  | _ -> Utils.futureFeature()

let subv = function
  | _ -> Utils.futureFeature()

let swap = function
  | _ -> Utils.futureFeature()

let swapb = function
  | _ -> Utils.futureFeature()

let swapw = function
  | _ -> Utils.futureFeature()

let tas = function
  | _ -> Utils.futureFeature()

let tasb = function
  | _ -> Utils.futureFeature()

let trapa = function
  | _ -> Utils.futureFeature()

let tst = function
  | _ -> Utils.futureFeature()

let tstb = function
  | _ -> Utils.futureFeature()

let xor = function
  | _ -> Utils.futureFeature()

let xorb = function
  | _ -> Utils.futureFeature()

let xtrct = function
  | _ -> Utils.futureFeature()
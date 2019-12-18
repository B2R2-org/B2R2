(*
  B2R2 - the Next-Generation Reversing Platform

  Author: Mehdi Aghakishiyev <agakisiyev.mehdi@gmail.com>
          Michael Tegegn <mick@kaist.ac.kr>

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

module B2R2.Assembler.Intel.FixInsInfo

open B2R2
open B2R2.FrontEnd.Intel

// FixMe
let vexInfoFromOpcode opcode :VEXInfo option = None

// FixMe: Should complete the fields of InsInfo. Should call vexInfoFromOpcode
// for every insInfo and complete the InsInfo size. It should also look for and
// substitue label operands.
let updateInsInfos (ins: InsInfo list) (lbls: Map<string, Addr>): InsInfo list =
  ins

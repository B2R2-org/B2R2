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

/// The vector facility. A vector register is 128 bits wide, which is wider than
/// a register a LowUIR expression can name, so each is reached as the two
/// 64-bit halves the register factory hands out -- and for the first sixteen
/// the left half *is* the matching floating-point register, as the
/// architecture says. An element size the instruction's mask names decides how
/// the 128 bits divide into lanes; because the mask is settled at lifting time,
/// every lane becomes its own statement and no loop is needed.
module internal B2R2.FrontEnd.S390.VectorLifter

open B2R2
open B2R2.BinIR
open B2R2.BinIR.LowUIR
open B2R2.BinIR.LowUIR.AST.InfixOp
open B2R2.FrontEnd.BinLifter
open B2R2.FrontEnd.BinLifter.LiftingUtils
open B2R2.FrontEnd.S390.LiftingUtils

/// A vector register as its two halves: the left one holds the elements the
/// architecture numbers first, since it stores everything most significant end
/// first.
type private Vec =
  { Hi: Expr
    Lo: Expr }

let private vecOf bld r =
  let struct (hi, lo) = pseudoRegVar128 bld (r: Register)
  { Hi = hi; Lo = lo }

/// The vector register an operand names.
let private vec bld o = vecOf bld (oprReg o)

/// The value of an operand that carries a small number, which the vector
/// formats spell sometimes as an immediate and sometimes as a mask.
let private numOf o =
  match o with
  | OpMask m -> int64 m
  | _ -> oprImm o

/// The whole 128 bits of a vector, for the operations whose element is the
/// register itself.
let private whole v = AST.concat v.Hi v.Lo

/// Writes 128 bits back into a vector's two halves.
let private setWhole bld v (e: Expr) =
  append bld {
    v.Hi := AST.xthi 64<rt> e
    v.Lo := AST.xtlo 64<rt> e
  }

let private bitsOf (w: RegType) = RegType.toBitWidth w

/// How many elements of the given width a vector holds.
let private lanes w = 128 / bitsOf w

/// The element of a vector at the given index, counted from the left as the
/// architecture counts them. Being an extraction of a register it serves as a
/// destination as well as a source.
let private lane v w i =
  let bits = bitsOf w
  let per = 64 / bits
  let half = if i < per then v.Hi else v.Lo
  AST.extract half w (64 - (i % per + 1) * bits)

/// The element of a vector at the given index, read as a value. A quadword
/// element is the register itself, which is not an extraction of either half.
let private getLane v w i = if bitsOf w = 128 then whole v else lane v w i

/// Writes an element back, taking a quadword one through the pair of halves.
let private setLane bld d w i e =
  if bitsOf w = 128 then setWhole bld d e else append bld { lane d w i := e }

/// The element size a mask names: the sizes run from byte through quadword in
/// the order the architecture numbers them.
let private esize (m: Mask) =
  match m &&& 7us with
  | 0us -> 8<rt>
  | 1us -> 16<rt>
  | 2us -> 32<rt>
  | 3us -> 64<rt>
  | _ -> 128<rt>

/// Applies an operation to every pair of matching elements. The results are
/// computed into temporaries before any is written back, so an instruction
/// whose destination is also one of its sources still reads the old elements.
let private mapPair bld w d x y f =
  append bld {
    if bitsOf w = 128 then
      let t = tmpVar bld 128<rt>
      t := f (whole x) (whole y)
      setWhole bld d t
    else
      let n = lanes w
      let ts = Array.init n (fun _ -> tmpVar bld w)
      for i in 0 .. n - 1 do
        ts[i] := f (lane x w i) (lane y w i)
      for i in 0 .. n - 1 do
        lane d w i := ts[i]
  }

/// Applies an operation to every element of one vector.
let private mapOne bld w d x f =
  append bld {
    if bitsOf w = 128 then
      let t = tmpVar bld 128<rt>
      t := f (whole x)
      setWhole bld d t
    else
      let n = lanes w
      let ts = Array.init n (fun _ -> tmpVar bld w)
      for i in 0 .. n - 1 do
        ts[i] := f (lane x w i)
      for i in 0 .. n - 1 do
        lane d w i := ts[i]
  }

/// Applies an operation to every triple of matching elements.
let private mapTriple bld w d x y z f =
  append bld {
    let n = lanes w
    let ts = Array.init n (fun _ -> tmpVar bld w)
    for i in 0 .. n - 1 do
      ts[i] := f (lane x w i) (lane y w i) (lane z w i)
    for i in 0 .. n - 1 do
      lane d w i := ts[i]
  }

/// An element all of whose bits are one, which is what a comparison that holds
/// writes and a test of a lane looks for.
let private allOnes w = numI64 -1L w

/// An operation whose operands are two vectors and whose element size a mask
/// gives: the very shape most of the facility's arithmetic takes.
let private binary ins insLen bld f =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[3])
    mapPair bld w (vec bld o[0]) (vec bld o[1]) (vec bld o[2]) f
  }

/// The same shape, but at a fixed element size the opcode itself names.
let private binaryAt ins insLen bld w f =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    mapPair bld w (vec bld o[0]) (vec bld o[1]) (vec bld o[2]) f
  }

/// A one-operand operation whose element size a mask gives.
let private unary ins insLen bld f =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[2])
    mapOne bld w (vec bld o[0]) (vec bld o[1]) f
  }

/// A three-vector operation whose element size a mask gives.
let private ternary ins insLen bld f =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[4])
    mapTriple
      bld w (vec bld o[0]) (vec bld o[1]) (vec bld o[2]) (vec bld o[3]) f
  }

/// VECTOR LOAD and VECTOR STORE, the plain sixteen-byte accesses.
let load ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let addr = tmpVar bld GRSize
    addr := transMem bld o[1]
    d.Hi := loadMem GRSize addr
    d.Lo := loadMem GRSize (addr .+ numG 8L)
  }

let store ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let s = vec bld o[0]
    let addr = tmpVar bld GRSize
    addr := transMem bld o[1]
    storeMem addr s.Hi
    storeMem (addr .+ numG 8L) s.Lo
  }

/// The registers a load- or store-multiple walks, wrapping around VR31 to VR0.
let private vecRange (v1: Register) (v3: Register) =
  let first = int v1 - int Register.VR0
  let count = ((int v3 - int v1) &&& 0x1f) + 1
  [| for i in 0 .. count - 1 ->
       enum<Register> (int Register.VR0 + ((first + i) &&& 0x1f)) |]

/// VECTOR LOAD MULTIPLE and VECTOR STORE MULTIPLE.
let multiple ins insLen bld isLoad =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let regs = vecRange (oprReg o[0]) (oprReg o[2])
    let addr = tmpVar bld GRSize
    addr := transMem bld o[1]
    for i in 0 .. regs.Length - 1 do
      let v = vecOf bld regs[i]
      let at = addr .+ numG (int64 i * 16L)
      if isLoad then
        v.Hi := loadMem GRSize at
        v.Lo := loadMem GRSize (at .+ numG 8L)
      else
        storeMem at v.Hi
        storeMem (at .+ numG 8L) v.Lo
  }

/// VECTOR LOAD WITH LENGTH and VECTOR STORE WITH LENGTH: the third operand's
/// register says how many bytes past the address take part, and the rest of the
/// vector is zeroed (loading) or left alone in storage (storing).
let withLength ins insLen bld isLoad =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let v = vec bld o[0]
    let addr = tmpVar bld GRSize
    let len = tmpVar bld GRSize
    addr := transMem bld o[1]
    len := zextTo GRSize (low (oprRegVar bld o[2])) .+ AST.num1 GRSize
    if isLoad then
      v.Hi := AST.num0 GRSize
      v.Lo := AST.num0 GRSize
    else
      ()
    for i in 0 .. 15 do
      let skip = label bld $"VlenSkip{i}"
      let act = label bld $"VlenAct{i}"
      AST.cjmp (numG (int64 i) .< len)
               (AST.jmpDest act)
               (AST.jmpDest skip)
      AST.lmark act
      let at = addr .+ numG (int64 i)
      if isLoad then append bld { lane v 8<rt> i := loadMem 8<rt> at }
      else append bld { storeMem at (lane v 8<rt> i) }
      AST.lmark skip
  }

/// VECTOR LOAD TO BLOCK BOUNDARY, which loads as much as it can without
/// crossing the boundary the mask names and leaves the rest of the vector
/// undefined -- zero here, which is a value the architecture allows.
let loadToBoundary ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let v = vec bld o[0]
    let bound =
      match oprMask o[2] &&& 0xfus with
      | 0us -> 64L
      | 1us -> 128L
      | 2us -> 256L
      | 3us -> 512L
      | 4us -> 1024L
      | 5us -> 2048L
      | 6us -> 4096L
      | _ -> 64L
    let addr = tmpVar bld GRSize
    let room = tmpVar bld GRSize
    addr := transMem bld o[1]
    room := numG bound .- (addr .& numG (bound - 1L))
    v.Hi := AST.num0 GRSize
    v.Lo := AST.num0 GRSize
    for i in 0 .. 15 do
      let skip = label bld $"VlbbSkip{i}"
      let act = label bld $"VlbbAct{i}"
      AST.cjmp (numG (int64 i) .< room)
               (AST.jmpDest act)
               (AST.jmpDest skip)
      AST.lmark act
      lane v 8<rt> i := loadMem 8<rt> (addr .+ numG (int64 i))
      AST.lmark skip
  }

/// VECTOR LOAD AND REPLICATE: one element of storage fills every lane.
let loadReplicate ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let w = esize (oprMask o[2])
    let t = tmpVar bld w
    t := loadMem w (transMem bld o[1])
    for i in 0 .. lanes w - 1 do
      lane d w i := t
  }

/// VECTOR LOAD ELEMENT and VECTOR STORE ELEMENT: one lane, the index a mask
/// names, takes or fills one unit of storage.
let element ins insLen bld w isLoad =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let v = vec bld o[0]
    let i = int (oprMask o[2]) % lanes w
    if isLoad then append bld { lane v w i := loadMem w (transMem bld o[1]) }
    else append bld { storeMem (transMem bld o[1]) (lane v w i) }
  }

/// VECTOR LOAD ELEMENT IMMEDIATE, which writes a signed halfword into one lane.
let elementImm ins insLen bld w =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let v = vec bld o[0]
    let i = int (oprMask o[2]) % lanes w
    lane v w i := numI64 (numOf o[1]) w
  }

/// VECTOR LOAD LOGICAL ELEMENT AND ZERO: one unit of storage goes to the lane
/// the architecture picks for it and every other bit becomes zero.
let loadLogicalZero ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let v = vec bld o[0]
    let m = oprMask o[2] &&& 0xfus
    let w = if m = 6us then 32<rt> else esize m
    let idx = if m = 6us then 1 elif bitsOf w = 64 then 0 else lanes w / 2 - 1
    v.Hi := AST.num0 GRSize
    v.Lo := AST.num0 GRSize
    lane v w idx := loadMem w (transMem bld o[1])
  }

/// VECTOR LOAD GR FROM VR ELEMENT: one lane, the index an address computation
/// gives, goes to a general register.
let loadFromElement ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let s = vec bld o[2]
    let w = esize (oprMask o[3])
    let d = oprRegVar bld o[0]
    let n = lanes w
    let idx = tmpVar bld GRSize
    let t = tmpVar bld w
    idx := transMem bld o[1] .& numG (int64 n - 1L)
    t := lane s w 0
    for i in 1 .. n - 1 do
      t := AST.ite (idx == numG (int64 i)) (lane s w i) t
    d := zextTo GRSize t
  }

/// VECTOR LOAD VR ELEMENT FROM GR, the reverse.
let loadToElement ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let w = esize (oprMask o[3])
    let src = oprRegVar bld o[2]
    let n = lanes w
    let idx = tmpVar bld GRSize
    idx := transMem bld o[1] .& numG (int64 n - 1L)
    for i in 0 .. n - 1 do
      let cur = lane d w i
      cur := AST.ite (idx == numG (int64 i)) (narrowTo w src) cur
  }

/// VECTOR LOAD VR FROM GRS DISJOINT, which builds a vector from two general
/// registers.
let loadFromPair ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    d.Hi := oprRegVar bld o[1]
    d.Lo := oprRegVar bld o[2]
  }

/// VECTOR LOAD, a move between two vector registers.
let move ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let s = vec bld o[1]
    d.Hi := s.Hi
    d.Lo := s.Lo
  }

/// VECTOR GENERATE BYTE MASK: each bit of a halfword immediate becomes a byte
/// of all ones or all zeros. It is how the assembler spells a vector of zeros
/// and one of ones.
let generateByteMask ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let m = uint64 (numOf o[1]) &&& 0xffffUL
    let mutable hi = 0UL
    let mutable lo = 0UL
    for i in 0 .. 15 do
      if m &&& (0x8000UL >>> i) <> 0UL then
        if i < 8 then hi <- hi ||| (0xffUL <<< (8 * (7 - i)))
        else lo <- lo ||| (0xffUL <<< (8 * (15 - i)))
      else
        ()
    d.Hi := numG (int64 hi)
    d.Lo := numG (int64 lo)
  }

/// VECTOR GENERATE MASK: every lane takes the run of ones from one bit position
/// through another, wrapping around the lane when the first lies after the
/// second.
let generateMask ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let w = esize (oprMask o[3])
    let bits = bitsOf w
    let start = int (numOf o[1]) % bits
    let fin = int (numOf o[2]) % bits
    let bitAt i = 1UL <<< (bits - 1 - i)
    let mutable m = 0UL
    if start <= fin then
      for i in start .. fin do m <- m ||| bitAt i
    else
      for i in start .. bits - 1 do m <- m ||| bitAt i
      for i in 0 .. fin do m <- m ||| bitAt i
    for i in 0 .. lanes w - 1 do
      lane d w i := numI64 (int64 m) w
  }

/// VECTOR REPLICATE: one lane of the source fills every lane.
let replicate ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let s = vec bld o[2]
    let w = esize (oprMask o[3])
    let i = int (numOf o[1]) % lanes w
    let t = tmpVar bld w
    t := lane s w i
    for k in 0 .. lanes w - 1 do
      lane d w k := t
  }

/// VECTOR REPLICATE IMMEDIATE, which fills every lane with a signed halfword.
let replicateImm ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let w = esize (oprMask o[2])
    for i in 0 .. lanes w - 1 do
      lane d w i := numI64 (numOf o[1]) w
  }

/// VECTOR LOAD RIGHTMOST WITH LENGTH and its store, which put the bytes at the
/// right-hand end of the vector rather than the left.
let rightmostWithLength ins insLen bld fromReg isLoad =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let v = vec bld o[0]
    let addr = tmpVar bld GRSize
    let len = tmpVar bld GRSize
    addr := transMem bld o[1]
    if fromReg then
      len := zextTo GRSize (low (oprRegVar bld o[2])) .+ AST.num1 GRSize
    else
      len := numG (numOf o[2] &&& 0xffL) .+ AST.num1 GRSize
    if isLoad then
      v.Hi := AST.num0 GRSize
      v.Lo := AST.num0 GRSize
    else
      ()
    for k in 0 .. 15 do
      let skip = label bld $"VrlSkip{k}"
      let act = label bld $"VrlAct{k}"
      AST.cjmp (numG (int64 k) .< len)
               (AST.jmpDest act)
               (AST.jmpDest skip)
      AST.lmark act
      let at = addr .+ numG (int64 k)
      let idx = 15 - k
      if isLoad then append bld { lane v 8<rt> idx := loadMem 8<rt> at }
      else append bld { storeMem at (lane v 8<rt> idx) }
      AST.lmark skip
  }

/// The byte-reversing loads and stores, which turn each element end for end so
/// that a little-endian buffer can be read as it stands.
let private reverse (w: RegType) e =
  let n = bitsOf w / 8
  if n = 1 then
    e
  else
    let bytes = [| for i in 0 .. n - 1 -> AST.extract e 8<rt> (i * 8) |]
    Array.reduce (fun acc b -> AST.concat acc b) bytes

let loadReversed ins insLen bld byElement =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let w = if byElement then esize (oprMask o[2]) else 128<rt>
    let addr = tmpVar bld GRSize
    addr := transMem bld o[1]
    if bitsOf w = 128 then
      let t = tmpVar bld 128<rt>
      t := loadMem 128<rt> addr
      setWhole bld d (reverse 128<rt> t)
    else
      let n = lanes w
      let bytes = bitsOf w / 8
      for i in 0 .. n - 1 do
        let at = addr .+ numG (int64 (i * bytes))
        lane d w i := reverse w (loadMem w at)
  }

let storeReversed ins insLen bld byElement =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let s = vec bld o[0]
    let w = if byElement then esize (oprMask o[2]) else 128<rt>
    let addr = tmpVar bld GRSize
    addr := transMem bld o[1]
    if bitsOf w = 128 then
      storeMem addr (reverse 128<rt> (whole s))
    else
      let n = lanes w
      let bytes = bitsOf w / 8
      for i in 0 .. n - 1 do
        let at = addr .+ numG (int64 (i * bytes))
        storeMem at (reverse w (lane s w i))
  }

/// VECTOR LOAD BYTE REVERSED ELEMENT AND ZERO, and the element loads and stores
/// that reverse just the one element they touch.
let elementReversed ins insLen bld w isLoad =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let v = vec bld o[0]
    let i = int (oprMask o[2]) % lanes w
    if isLoad then
      lane v w i := reverse w (loadMem w (transMem bld o[1]))
    else
      storeMem (transMem bld o[1]) (reverse w (lane v w i))
  }

let loadReversedReplicate ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let w = esize (oprMask o[2])
    let t = tmpVar bld w
    t := reverse w (loadMem w (transMem bld o[1]))
    for i in 0 .. lanes w - 1 do
      lane d w i := t
  }

let loadReversedLogicalZero ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let v = vec bld o[0]
    let w = esize (oprMask o[2])
    let idx = if bitsOf w = 64 then 0 else lanes w / 2 - 1
    v.Hi := AST.num0 GRSize
    v.Lo := AST.num0 GRSize
    lane v w idx := reverse w (loadMem w (transMem bld o[1]))
  }

/// VECTOR GATHER ELEMENT and VECTOR SCATTER ELEMENT, which reach one lane
/// through an address the vector itself supplies as an index.
let gatherScatter ins insLen bld w isGather =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let v = vec bld o[0]
    let i = int (oprMask o[2]) % lanes w
    let addr = transMem bld o[1]
    if isGather then append bld { lane v w i := loadMem w addr }
    else append bld { storeMem addr (lane v w i) }
  }

/// The carry out of an unsigned addition of one element, as an element of ones
/// or zeros -- which is the form the facility's carry vectors take.
let private carryOf (w: RegType) a b =
  let sum = a .+ b
  AST.ite (sum .< a) (AST.num1 w) (AST.num0 w)

/// The borrow of an unsigned subtraction, which the facility reports the other
/// way round: one means no borrow was needed.
let private borrowOf (w: RegType) a b =
  AST.ite (a .>= b) (AST.num1 w) (AST.num0 w)

/// VECTOR ADD WITH CARRY and its subtracting counterpart, which take the carry
/// vector a previous ADD WITH CARRY COMPUTE CARRY produced.
let addWithCarry ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[4])
    mapTriple bld
      w
      (vec bld o[0])
      (vec bld o[1])
      (vec bld o[2])
      (vec bld o[3])
      (fun a b c -> a .+ b .+ (c .& AST.num1 w))
  }

let addCarryCompute ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[4])
    mapTriple bld w (vec bld o[0]) (vec bld o[1]) (vec bld o[2]) (vec bld o[3])
      (fun a b c ->
        let cin = c .& AST.num1 w
        let s = a .+ b
        let carry1 = AST.ite (s .< a) (AST.num1 w) (AST.num0 w)
        let s2 = s .+ cin
        let carry2 = AST.ite (s2 .< s) (AST.num1 w) (AST.num0 w)
        carry1 .| carry2)
  }

let subWithBorrow ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[4])
    mapTriple bld
      w
      (vec bld o[0])
      (vec bld o[1])
      (vec bld o[2])
      (vec bld o[3])
      (fun a b c -> a .- b .- (AST.num1 w .- (c .& AST.num1 w)))
  }

let subBorrowCompute ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[4])
    mapTriple bld w (vec bld o[0]) (vec bld o[1]) (vec bld o[2]) (vec bld o[3])
      (fun a b c ->
        let bin = AST.num1 w .- (c .& AST.num1 w)
        AST.ite (a .>= (b .+ bin)) (AST.num1 w) (AST.num0 w))
  }

/// The averaging adds, which round the halved sum away from zero.
let private avgSigned (w: RegType) a b =
  let wide = w * 2
  let s = AST.sext wide a .+ AST.sext wide b .+ AST.num1 wide
  AST.xtlo w (s ?>> AST.num1 wide)

let private avgLogical (w: RegType) a b =
  let wide = w * 2
  let s = AST.zext wide a .+ AST.zext wide b .+ AST.num1 wide
  AST.xtlo w (s >> AST.num1 wide)

/// The multiplies whose product is as wide as the operands, and the ones that
/// keep its high half instead.
let private mulHigh signed (w: RegType) a b =
  let wide = w * 2
  let ext = if signed then AST.sext else AST.zext
  AST.xthi w (ext wide a .* ext wide b)

/// The multiplies that widen: the even or the odd lanes of the sources make
/// products twice as wide, so half as many of them.
let private widenMul ins insLen bld signed odd =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[3])
    let wide = w * 2
    let ext = if signed then AST.sext else AST.zext
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let n = lanes wide
    let ts = Array.init n (fun _ -> tmpVar bld wide)
    for i in 0 .. n - 1 do
      let src = 2 * i + (if odd then 1 else 0)
      ts[i] := ext wide (getLane x w src) .* ext wide (getLane y w src)
    for i in 0 .. n - 1 do
      setLane bld d wide i ts[i]
  }

/// The widening multiply-and-adds, which add a third vector's wide lanes to the
/// products.
let private widenMulAdd ins insLen bld signed odd =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[4])
    let wide = w * 2
    let ext = if signed then AST.sext else AST.zext
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let z = vec bld o[3]
    let n = lanes wide
    let ts = Array.init n (fun _ -> tmpVar bld wide)
    for i in 0 .. n - 1 do
      let src = 2 * i + (if odd then 1 else 0)
      ts[i] := ext wide (getLane x w src) .* ext wide (getLane y w src)
               .+ getLane z wide i
    for i in 0 .. n - 1 do
      setLane bld d wide i ts[i]
  }

/// VECTOR MULTIPLY AND ADD LOW and its high-half relatives, whose product stays
/// the width of the operands.
let private mulAdd ins insLen bld f =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[4])
    mapTriple bld
      w
      (vec bld o[0])
      (vec bld o[1])
      (vec bld o[2])
      (vec bld o[3])
      (f w)
  }

/// VECTOR SUM ACROSS the group of lanes the opcode names: the sums go into
/// lanes twice or four times as wide, which is how a dot product or a checksum
/// is accumulated without overflowing.
let private sumAcross ins insLen bld (wide: RegType) =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[3])
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let n = lanes wide
    let per = lanes w / n
    let ts = Array.init n (fun _ -> tmpVar bld wide)
    for i in 0 .. n - 1 do
      let mutable acc = AST.zext wide (getLane y w (per * (i + 1) - 1))
      for k in 0 .. per - 1 do
        acc <- acc .+ AST.zext wide (getLane x w (per * i + k))
      ts[i] := acc
    for i in 0 .. n - 1 do
      setLane bld d wide i ts[i]
  }

/// VECTOR GALOIS FIELD MULTIPLY SUM, the carry-less multiply a cyclic
/// redundancy check is built from: the products of the even and the odd lanes
/// are added without carries into a lane twice as wide.
let private galoisMul ins insLen bld accumulate =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[if accumulate then 4 else 3])
    let wide = w * 2
    let bits = bitsOf w
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let n = lanes wide
    let ts = Array.init n (fun _ -> tmpVar bld wide)
    for i in 0 .. n - 1 do
      let clmul a b =
        let a = AST.zext wide a
        let b = AST.zext wide b
        let mutable acc = AST.num0 wide
        for k in 0 .. bits - 1 do
          let bit = (b >> numI32 k wide) .& AST.num1 wide
          let term = AST.ite (bit == AST.num1 wide)
                             (a << numI32 k wide)
                             (AST.num0 wide)
          acc <- acc <+> term
        acc
      let even = clmul (getLane x w (2 * i)) (getLane y w (2 * i))
      let odd = clmul (getLane x w (2 * i + 1)) (getLane y w (2 * i + 1))
      let sum = even <+> odd
      if accumulate then
        append bld { ts[i] := sum <+> getLane (vec bld o[3]) wide i }
      else
        append bld { ts[i] := sum }
    for i in 0 .. n - 1 do
      setLane bld d wide i ts[i]
  }

/// VECTOR CHECKSUM, which adds the word lanes with the carries folded back in.
let checksum ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let acc = tmpVar bld GRSize
    acc := zextTo GRSize (lane y 32<rt> 1)
    for i in 0 .. 3 do
      acc := acc .+ zextTo GRSize (lane x 32<rt> i)
    acc := (acc .& numG 0xffffffffL) .+ (acc >> numG 32L)
    acc := (acc .& numG 0xffffffffL) .+ (acc >> numG 32L)
    d.Hi := AST.num0 GRSize
    d.Lo := AST.num0 GRSize
    lane d 32<rt> 1 := AST.xtlo 32<rt> acc
  }

/// VECTOR BIT PERMUTE, which gathers the bits a vector of indices names into
/// the rightmost halfword of the result.
let bitPermute ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let acc = tmpVar bld 16<rt>
    acc := AST.num0 16<rt>
    for k in 0 .. 15 do
      let idx = tmpVar bld GRSize
      idx := zextTo GRSize (lane y 8<rt> k)
      let bit = tmpVar bld 16<rt>
      bit := AST.num0 16<rt>
      for b in 0 .. 127 do
        let src = if b < 64 then x.Hi else x.Lo
        let pos = 63 - (b % 64)
        let one = AST.extract src 1<rt> pos
        bit := AST.ite (idx == numG (int64 b)) (zextTo 16<rt> one) bit
      acc := (acc << AST.num1 16<rt>) .| bit
    d.Hi := AST.num0 GRSize
    d.Lo := AST.num0 GRSize
    lane d 16<rt> 7 := acc
  }

/// The bit-counting operations, each written as the fixed sequence of masked
/// adds that counts without a loop.
let private popcount (w: RegType) e =
  let bits = bitsOf w
  let mask (pat: uint64) =
    let mutable v = 0UL
    for i in 0 .. bits / 8 - 1 do v <- v ||| (pat <<< (8 * i))
    numI64 (int64 v) w
  let mutable acc = e .- ((e >> AST.num1 w) .& mask 0x55UL)
  acc <- (acc .& mask 0x33UL) .+ ((acc >> numI32 2 w) .& mask 0x33UL)
  acc <- (acc .+ (acc >> numI32 4 w)) .& mask 0x0fUL
  if bits = 8 then
    acc
  else
    let mutable sum = acc
    let mutable sh = 8
    while sh < bits do
      sum <- sum .+ (sum >> numI32 sh w)
      sh <- sh * 2
    sum .& numI64 0xffL w

/// VECTOR COUNT LEADING ZEROS and TRAILING ZEROS, each written as a chain of
/// selects over the bit positions -- the element widths are small enough that
/// this stays shorter than a loop would be.
let private countZeros leading (w: RegType) e =
  let bits = bitsOf w
  let mutable acc = numI32 bits w
  for i in 0 .. bits - 1 do
    let pos = if leading then bits - 1 - i else i
    let bit = (e >> numI32 pos w) .& AST.num1 w
    acc <- AST.ite (bit == AST.num1 w) (numI32 i w) acc
  acc

/// The element-wise shifts, whose count is either an immediate or the matching
/// lane of a third vector.
let private shiftByCount (w: RegType) f e count =
  let bits = numI32 (bitsOf w) w
  let n = count .& (bits .- AST.num1 w)
  f e n

/// The element-wise shifts whose count is one value for every lane, taken from
/// the address the second operand forms rather than from a vector.
let private shiftByAddress ins insLen bld f =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[3])
    let bits = bitsOf w
    let d = vec bld o[0]
    let x = vec bld o[2]
    let n = tmpVar bld w
    n := narrowTo w (transMem bld o[1]) .& numI32 (bits - 1) w
    mapOne bld w d x (fun a -> f a n)
  }

/// VECTOR SHIFT LEFT and its relatives, which shift the whole 128 bits by a
/// count the rightmost byte of a third vector's last lane gives.
let private shiftWhole ins insLen bld byBytes f =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let t = tmpVar bld 128<rt>
    let n = tmpVar bld 128<rt>
    n := AST.zext 128<rt> (lane y 8<rt> 15)
    let count = if byBytes then (n .& numI64 15L 128<rt>) .* numI64 8L 128<rt>
                else n .& numI64 127L 128<rt>
    t := f (whole x) count
    setWhole bld d t
  }

/// VECTOR SHIFT LEFT DOUBLE BY BYTE, which takes a window of the two sources
/// laid end to end.
/// The window of the two sources laid end to end that begins the given number
/// of bits from the left. It is written as a pair of 128-bit shifts rather than
/// one shift of a 256-bit value, which is wider than the arithmetic the
/// evaluator carries.
let private windowFromLeft bld x y shift =
  if shift = 0 then
    whole x
  else
    let hi = tmpVar bld 128<rt>
    let lo = tmpVar bld 128<rt>
    append bld {
      hi := whole x << numI32 shift 128<rt>
      lo := whole y >> numI32 (128 - shift) 128<rt>
    }
    hi .| lo

/// VECTOR SHIFT LEFT DOUBLE BY BYTE, and the bit-precise form of the same.
let shiftDoubleLeft ins insLen bld byBytes =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let raw = int (numOf o[3])
    let shift = if byBytes then (raw &&& 0xf) * 8 else raw &&& 7
    setWhole bld d (windowFromLeft bld x y shift)
  }

/// VECTOR SHIFT RIGHT DOUBLE BY BIT, which takes the window at the right-hand
/// end instead.
let shiftDoubleRight ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let shift = int (numOf o[3]) &&& 7
    setWhole bld d (windowFromLeft bld x y (128 - shift))
  }

/// VECTOR ELEMENT ROTATE AND INSERT UNDER MASK, which rotates one vector's
/// lanes and takes the bits a third vector's lanes select.
let rotateInsert ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[4])
    let bits = bitsOf w
    let count = int (numOf o[3]) % bits
    mapTriple bld w (vec bld o[0]) (vec bld o[1]) (vec bld o[2]) (vec bld o[0])
      (fun a b d ->
        let rot =
          if count = 0 then a
          else (a << numI32 count w) .| (a >> numI32 (bits - count) w)
        (rot .& b) .| (d .& AST.not b))
  }

/// Whether the mask's rightmost bit asks for a condition code.
let private wantsCC (m: Mask) = m &&& 1us <> 0us

/// The condition code an element-wise comparison reports: 0 when every lane
/// held, 1 when some did, 3 when none did.
let private setCCCompare bld w d =
  append bld {
    let n = lanes w
    let all = tmpVar bld w
    let any = tmpVar bld w
    all := lane d w 0
    any := lane d w 0
    for i in 1 .. n - 1 do
      all := all .& lane d w i
      any := any .| lane d w i
    let zero = AST.num0 w
    ccVar bld
            := AST.ite (all != zero)
                       (numCC 0)
                       (AST.ite (any != zero) (numCC 1) (numCC 3))
  }

/// The element-wise comparisons, which write all ones into a lane the
/// comparison held for and all zeros into the others.
let compare ins insLen bld f =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[3])
    let cc = Array.length o > 4 && wantsCC (oprMask o[4])
    let d = vec bld o[0]
    mapPair bld
      w
      d
      (vec bld o[1])
      (vec bld o[2])
      (fun a b -> AST.ite (f a b) (allOnes w) (AST.num0 w))
    if cc then setCCCompare bld w d else ()
  }

/// VECTOR ELEMENT COMPARE, which reports how one lane of each vector stands
/// rather than writing a result.
let elementCompare ins insLen bld signed =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[2])
    let i = lanes w / 2 - 1
    let a = tmpVar bld w
    let b = tmpVar bld w
    a := lane (vec bld o[0]) w i
    b := lane (vec bld o[1]) w i
    if signed then setCCCmp bld a b else setCCCmpLogical bld a b
  }

/// VECTOR TEST UNDER MASK, whose condition code says whether the bits the mask
/// selects were all zeros, a mixture, or all ones.
let testUnderMask ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let x = whole (vec bld o[0])
    let m = whole (vec bld o[1])
    let sel = tmpVar bld 128<rt>
    let mask = tmpVar bld 128<rt>
    mask := m
    sel := x .& mask
    let zero = AST.num0 128<rt>
    let mixed = AST.ite (sel == mask) (numCC 3) (numCC 1)
    ccVar bld := AST.ite (mask == zero)
                         (numCC 0)
                         (AST.ite (sel == zero) (numCC 0) mixed)
  }

/// The index of the leftmost lane a search found something in, as a byte count,
/// which is the answer every one of the string instructions gives.
let private setIndex bld w d found idx =
  append bld {
    d.Hi := AST.num0 GRSize
    d.Lo := AST.num0 GRSize
    lane d 64<rt> 0 := AST.ite found idx (numG 16L)
  }

/// VECTOR FIND ANY ELEMENT EQUAL and VECTOR FIND ELEMENT EQUAL: the first lane
/// of the second operand that matches one of the third's -- or, for the "not
/// equal" form, the first that differs -- decides. A zero lane counts as the
/// end of a string when the mask says so, which is what makes these the whole
/// of a vector strlen or strchr.
let findElement ins insLen bld wantEqual =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[3])
    let m5 = if Array.length o > 4 then oprMask o[4] else 0us
    let zeroSearch = m5 &&& 2us <> 0us
    let cc = wantsCC m5
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let n = lanes w
    let bytes = bitsOf w / 8
    let idx = tmpVar bld GRSize
    let hit = tmpVar bld 1<rt>
    idx := numG 16L
    hit := AST.b0
    for i in n - 1 .. -1 .. 0 do
      let a = lane x w i
      let b = lane y w i
      let same = if wantEqual then a == b else a != b
      let cond = if zeroSearch then same .| (a == AST.num0 w) else same
      idx := AST.ite cond (numG (int64 (i * bytes))) idx
      hit := AST.ite cond AST.b1 hit
    setIndex bld w d (hit == AST.b1) idx
    if cc then
      append bld { ccVar bld := AST.ite (hit == AST.b1) (numCC 1) (numCC 3) }
    else
      ()
  }

/// VECTOR ISOLATE STRING, which keeps every lane up to the first zero one and
/// clears the rest -- the vector form of taking a null-terminated prefix.
let isolateString ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[2])
    let m5 = if Array.length o > 3 then oprMask o[3] else 0us
    let d = vec bld o[0]
    let x = vec bld o[1]
    let n = lanes w
    let live = tmpVar bld 1<rt>
    let ts = Array.init n (fun _ -> tmpVar bld w)
    live := AST.b1
    for i in 0 .. n - 1 do
      let a = lane x w i
      ts[i] := AST.ite (live == AST.b1) a (AST.num0 w)
      live := AST.ite (a == AST.num0 w) AST.b0 live
    for i in 0 .. n - 1 do
      lane d w i := ts[i]
    if wantsCC m5 then
      ccVar bld := AST.ite (live == AST.b1) (numCC 3) (numCC 0)
    else
      ()
  }

/// VECTOR STRING RANGE COMPARE and VECTOR STRING SEARCH, the two remaining
/// string primitives. Both walk the lanes looking for the first that satisfies
/// a condition the extra operands describe.
let stringRangeCompare ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[4])
    let m6 = if Array.length o > 5 then oprMask o[5] else 0us
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let z = vec bld o[3]
    let n = lanes w
    let bytes = bitsOf w / 8
    let idx = tmpVar bld GRSize
    let hit = tmpVar bld 1<rt>
    idx := numG 16L
    hit := AST.b0
    for i in n - 1 .. -1 .. 0 do
      (* Each pair of lanes of the second and third operands gives a range and
         the controls that say which ends of it count; a lane of the first
         operand in range is a match. *)
      let a = lane x w i
      let lo = lane y w i
      let ctl = lane z w i
      let ge = (ctl .& numI64 0x80L w) == AST.num0 w
      let cond = AST.ite ge (a .>= lo) (a .<= lo)
      idx := AST.ite cond (numG (int64 (i * bytes))) idx
      hit := AST.ite cond AST.b1 hit
    setIndex bld w d (hit == AST.b1) idx
    if wantsCC m6 then
      ccVar bld := AST.ite (hit == AST.b1) (numCC 1) (numCC 3)
    else
      ()
  }

let stringSearch ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[4])
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let z = vec bld o[3]
    let n = lanes w
    let bytes = bitsOf w / 8
    let len = tmpVar bld GRSize
    let idx = tmpVar bld GRSize
    let hit = tmpVar bld 1<rt>
    len := zextTo GRSize (lane z 8<rt> 7)
    idx := numG 16L
    hit := AST.b0
    for start in n - 1 .. -1 .. 0 do
      (* A match at this lane means every lane of the substring, as far as its
         length reaches within the vector, agrees. *)
      let mutable cond = AST.b1
      for k in 0 .. n - 1 - start do
        let inRange = numG (int64 k) .< len
        let same = lane x w (start + k) == lane y w k
        cond <- cond .& (AST.ite inRange same AST.b1)
      idx := AST.ite cond (numG (int64 (start * bytes))) idx
      hit := AST.ite cond AST.b1 hit
    setIndex bld w d (hit == AST.b1) idx
    ccVar bld := AST.ite (hit == AST.b1) (numCC 2) (numCC 3)
  }

/// VECTOR PACK, which halves the width of every lane by dropping its left half,
/// and the saturating forms, which clamp instead of dropping.
let pack ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[3])
    let narrow = w / 2
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let n = lanes narrow
    let ts = Array.init n (fun _ -> tmpVar bld narrow)
    for i in 0 .. n / 2 - 1 do
      ts[i] := AST.xtlo narrow (lane x w i)
    for i in 0 .. n / 2 - 1 do
      ts[n / 2 + i] := AST.xtlo narrow (lane y w i)
    for i in 0 .. n - 1 do
      lane d narrow i := ts[i]
  }

/// VECTOR UNPACK, which doubles the width of the lanes at one end of the
/// source, sign- or zero-extending each.
let unpack ins insLen bld signed fromHigh =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[2])
    let wide = w * 2
    let ext = if signed then AST.sext else AST.zext
    let d = vec bld o[0]
    let x = vec bld o[1]
    let n = lanes wide
    let ts = Array.init n (fun _ -> tmpVar bld wide)
    for i in 0 .. n - 1 do
      let src = if fromHigh then i else n + i
      ts[i] := ext wide (getLane x w src)
    for i in 0 .. n - 1 do
      setLane bld d wide i ts[i]
  }

/// VECTOR MERGE, which interleaves the lanes at one end of the two sources.
let merge ins insLen bld fromHigh =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let w = esize (oprMask o[3])
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let n = lanes w
    let ts = Array.init n (fun _ -> tmpVar bld w)
    for i in 0 .. n / 2 - 1 do
      let src = if fromHigh then i else n / 2 + i
      ts[2 * i] := lane x w src
      ts[2 * i + 1] := lane y w src
    for i in 0 .. n - 1 do
      lane d w i := ts[i]
  }

/// VECTOR PERMUTE, which builds each byte of the result from whichever byte of
/// the two sources laid end to end a third vector's byte names.
let permute ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let z = vec bld o[3]
    let ts = Array.init 16 (fun _ -> tmpVar bld 8<rt>)
    for i in 0 .. 15 do
      let idx = tmpVar bld GRSize
      idx := zextTo GRSize (lane z 8<rt> i) .& numG 31L
      let mutable pick = lane x 8<rt> 0
      for k in 1 .. 31 do
        let src = if k < 16 then lane x 8<rt> k else lane y 8<rt> (k - 16)
        pick <- AST.ite (idx == numG (int64 k)) src pick
      ts[i] := pick
    for i in 0 .. 15 do
      lane d 8<rt> i := ts[i]
  }

/// VECTOR PERMUTE DOUBLEWORD IMMEDIATE, the same idea over two doublewords.
let permuteDoubleword ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let m = int (numOf o[3])
    let a = tmpVar bld GRSize
    let b = tmpVar bld GRSize
    a := if m &&& 4 = 0 then x.Hi else x.Lo
    b := if m &&& 1 = 0 then y.Hi else y.Lo
    d.Hi := a
    d.Lo := b
  }

/// VECTOR SELECT, whose third operand chooses bit by bit between the other two.
let select ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let x = vec bld o[1]
    let y = vec bld o[2]
    let z = vec bld o[3]
    let m = tmpVar bld GRSize
    m := z.Hi
    let hi = tmpVar bld GRSize
    let lo = tmpVar bld GRSize
    hi := (x.Hi .& m) .| (y.Hi .& AST.not m)
    m := z.Lo
    lo := (x.Lo .& m) .| (y.Lo .& AST.not m)
    d.Hi := hi
    d.Lo := lo
  }

/// VECTOR SIGN EXTEND TO DOUBLEWORD, which takes the rightmost element of each
/// half and spreads its sign over the whole of that half.
let signExtendDoubleword ins insLen bld =
  lift bld (ins: Instruction) insLen {
    let o = oprArray ins
    let d = vec bld o[0]
    let x = vec bld o[1]
    d.Hi := AST.sext GRSize (AST.xtlo 8<rt> x.Hi)
    d.Lo := AST.sext GRSize (AST.xtlo 8<rt> x.Lo)
  }

/// An instruction of the facility this lifter does not model: the vector
/// floating-point operations, which would need a 128-bit float the IR has no
/// type for, and the vector decimal ones, whose packed-decimal arithmetic is
/// not modelled either.
let unsupported ins insLen bld =
  lift bld (ins: Instruction) insLen {
    AST.sideEffect UnsupportedInstruction
  }

/// Translates one vector instruction.
let translate (ins: Instruction) insLen bld =
  match ins.Opcode with
  | Opcode.VL ->
    load ins insLen bld
  | Opcode.VST ->
    store ins insLen bld
  | Opcode.VLM ->
    multiple ins insLen bld true
  | Opcode.VSTM ->
    multiple ins insLen bld false
  | Opcode.VLL ->
    withLength ins insLen bld true
  | Opcode.VSTL ->
    withLength ins insLen bld false
  | Opcode.VLBB ->
    loadToBoundary ins insLen bld
  | Opcode.VLREP ->
    loadReplicate ins insLen bld
  | Opcode.VLR ->
    move ins insLen bld
  | Opcode.VLEB ->
    element ins insLen bld 8<rt> true
  | Opcode.VLEH ->
    element ins insLen bld 16<rt> true
  | Opcode.VLEF ->
    element ins insLen bld 32<rt> true
  | Opcode.VLEG ->
    element ins insLen bld 64<rt> true
  | Opcode.VSTEB ->
    element ins insLen bld 8<rt> false
  | Opcode.VSTEH ->
    element ins insLen bld 16<rt> false
  | Opcode.VSTEF ->
    element ins insLen bld 32<rt> false
  | Opcode.VSTEG ->
    element ins insLen bld 64<rt> false
  | Opcode.VLEIB ->
    elementImm ins insLen bld 8<rt>
  | Opcode.VLEIH ->
    elementImm ins insLen bld 16<rt>
  | Opcode.VLEIF ->
    elementImm ins insLen bld 32<rt>
  | Opcode.VLEIG ->
    elementImm ins insLen bld 64<rt>
  | Opcode.VLLEZ ->
    loadLogicalZero ins insLen bld
  | Opcode.VLGV ->
    loadFromElement ins insLen bld
  | Opcode.VLVG ->
    loadToElement ins insLen bld
  | Opcode.VLVGP ->
    loadFromPair ins insLen bld
  | Opcode.VGBM ->
    generateByteMask ins insLen bld
  | Opcode.VGM ->
    generateMask ins insLen bld
  | Opcode.VREP ->
    replicate ins insLen bld
  | Opcode.VREPI ->
    replicateImm ins insLen bld
  | Opcode.VLRL ->
    rightmostWithLength ins insLen bld false true
  | Opcode.VLRLR ->
    rightmostWithLength ins insLen bld true true
  | Opcode.VSTRL ->
    rightmostWithLength ins insLen bld false false
  | Opcode.VSTRLR ->
    rightmostWithLength ins insLen bld true false
  | Opcode.VLBR ->
    loadReversed ins insLen bld true
  | Opcode.VLER ->
    loadReversed ins insLen bld true
  | Opcode.VSTBR ->
    storeReversed ins insLen bld true
  | Opcode.VSTER ->
    storeReversed ins insLen bld true
  | Opcode.VLBRREP ->
    loadReversedReplicate ins insLen bld
  | Opcode.VLLEBRZ ->
    loadReversedLogicalZero ins insLen bld
  | Opcode.VLEBRH ->
    elementReversed ins insLen bld 16<rt> true
  | Opcode.VLEBRF ->
    elementReversed ins insLen bld 32<rt> true
  | Opcode.VLEBRG ->
    elementReversed ins insLen bld 64<rt> true
  | Opcode.VSTEBRH ->
    elementReversed ins insLen bld 16<rt> false
  | Opcode.VSTEBRF ->
    elementReversed ins insLen bld 32<rt> false
  | Opcode.VSTEBRG ->
    elementReversed ins insLen bld 64<rt> false
  | Opcode.VN ->
    binaryAt ins insLen bld 128<rt> (.&)
  | Opcode.VO ->
    binaryAt ins insLen bld 128<rt> (.|)
  | Opcode.VX ->
    binaryAt ins insLen bld 128<rt> (<+>)
  | Opcode.VNC ->
    binaryAt ins insLen bld 128<rt> (fun a b -> a .& AST.not b)
  | Opcode.VOC ->
    binaryAt ins insLen bld 128<rt> (fun a b -> a .| AST.not b)
  | Opcode.VNO ->
    binaryAt ins insLen bld 128<rt> (fun a b -> AST.not (a .| b))
  | Opcode.VNN ->
    binaryAt ins insLen bld 128<rt> (fun a b -> AST.not (a .& b))
  | Opcode.VNX ->
    binaryAt ins insLen bld 128<rt> (fun a b -> AST.not (a <+> b))
  | Opcode.VSEL ->
    select ins insLen bld
  | Opcode.VA ->
    binary ins insLen bld (.+)
  | Opcode.VS ->
    binary ins insLen bld (.-)
  | Opcode.VACC ->
    let o = oprArray ins
    let w = esize (oprMask o[3])
    binary ins insLen bld (carryOf w)
  | Opcode.VSCBI ->
    let o = oprArray ins
    let w = esize (oprMask o[3])
    binary ins insLen bld (borrowOf w)
  | Opcode.VAC ->
    addWithCarry ins insLen bld
  | Opcode.VACCC ->
    addCarryCompute ins insLen bld
  | Opcode.VSBI ->
    subWithBorrow ins insLen bld
  | Opcode.VSBCBI ->
    subBorrowCompute ins insLen bld
  | Opcode.VAVG ->
    let o = oprArray ins
    let w = esize (oprMask o[3])
    binary ins insLen bld (avgSigned w)
  | Opcode.VAVGL ->
    let o = oprArray ins
    let w = esize (oprMask o[3])
    binary ins insLen bld (avgLogical w)
  | Opcode.VMX ->
    binary ins insLen bld (fun a b -> AST.ite (a ?> b) a b)
  | Opcode.VMXL ->
    binary ins insLen bld (fun a b -> AST.ite (a .> b) a b)
  | Opcode.VMN ->
    binary ins insLen bld (fun a b -> AST.ite (a ?< b) a b)
  | Opcode.VMNL ->
    binary ins insLen bld (fun a b -> AST.ite (a .< b) a b)
  | Opcode.VLC ->
    unary ins insLen bld AST.neg
  | Opcode.VLP ->
    let o = oprArray ins
    let w = esize (oprMask o[2])
    unary ins insLen bld (fun a ->
      AST.ite (a ?< AST.num0 w) (AST.neg a) a)
  | Opcode.VML ->
    binary ins insLen bld (.*)
  | Opcode.VMH ->
    let o = oprArray ins
    let w = esize (oprMask o[3])
    binary ins insLen bld (mulHigh true w)
  | Opcode.VMLH ->
    let o = oprArray ins
    let w = esize (oprMask o[3])
    binary ins insLen bld (mulHigh false w)
  | Opcode.VME ->
    widenMul ins insLen bld true false
  | Opcode.VMO ->
    widenMul ins insLen bld true true
  | Opcode.VMLE ->
    widenMul ins insLen bld false false
  | Opcode.VMLO ->
    widenMul ins insLen bld false true
  | Opcode.VMAE ->
    widenMulAdd ins insLen bld true false
  | Opcode.VMAO ->
    widenMulAdd ins insLen bld true true
  | Opcode.VMALE ->
    widenMulAdd ins insLen bld false false
  | Opcode.VMALO ->
    widenMulAdd ins insLen bld false true
  | Opcode.VMAL ->
    mulAdd ins insLen bld (fun _ a b c -> (a .* b) .+ c)
  | Opcode.VMAH ->
    mulAdd ins insLen bld (fun w a b c -> mulHigh true w a b .+ c)
  | Opcode.VMALH ->
    mulAdd ins insLen bld (fun w a b c -> mulHigh false w a b .+ c)
  | Opcode.VSUM ->
    sumAcross ins insLen bld 32<rt>
  | Opcode.VSUMG ->
    sumAcross ins insLen bld 64<rt>
  | Opcode.VSUMQ ->
    sumAcross ins insLen bld 128<rt>
  | Opcode.VGFM ->
    galoisMul ins insLen bld false
  | Opcode.VGFMA ->
    galoisMul ins insLen bld true
  | Opcode.VCKSM ->
    checksum ins insLen bld
  | Opcode.VBPERM ->
    bitPermute ins insLen bld
  | Opcode.VPOPCT ->
    let o = oprArray ins
    let w = esize (oprMask o[2])
    unary ins insLen bld (popcount w)
  | Opcode.VCLZ ->
    let o = oprArray ins
    let w = esize (oprMask o[2])
    unary ins insLen bld (countZeros true w)
  | Opcode.VCTZ ->
    let o = oprArray ins
    let w = esize (oprMask o[2])
    unary ins insLen bld (countZeros false w)
  | Opcode.VESL ->
    shiftByAddress ins insLen bld (<<)
  | Opcode.VESRL ->
    shiftByAddress ins insLen bld (>>)
  | Opcode.VESRA ->
    shiftByAddress ins insLen bld (?>>)
  | Opcode.VESLV ->
    let o = oprArray ins
    let w = esize (oprMask o[3])
    binary ins insLen bld (shiftByCount w (<<))
  | Opcode.VESRLV ->
    let o = oprArray ins
    let w = esize (oprMask o[3])
    binary ins insLen bld (shiftByCount w (>>))
  | Opcode.VESRAV ->
    let o = oprArray ins
    let w = esize (oprMask o[3])
    binary ins insLen bld (shiftByCount w (?>>))
  | Opcode.VERLL ->
    let o = oprArray ins
    let w = esize (oprMask o[3])
    shiftByAddress ins insLen bld (fun a n ->
      (a << n) .| (a >> (numI32 (bitsOf w) w .- n)))
  | Opcode.VERLLV ->
    let o = oprArray ins
    let w = esize (oprMask o[3])
    let bits = bitsOf w
    binary ins insLen bld (fun a c ->
      let n = c .& numI32 (bits - 1) w
      (a << n) .| (a >> (numI32 bits w .- n)))
  | Opcode.VERIM ->
    rotateInsert ins insLen bld
  | Opcode.VSL ->
    shiftWhole ins insLen bld false (<<)
  | Opcode.VSRL ->
    shiftWhole ins insLen bld false (>>)
  | Opcode.VSRA ->
    shiftWhole ins insLen bld false (?>>)
  | Opcode.VSLB ->
    shiftWhole ins insLen bld true (<<)
  | Opcode.VSRLB ->
    shiftWhole ins insLen bld true (>>)
  | Opcode.VSRAB ->
    shiftWhole ins insLen bld true (?>>)
  | Opcode.VSLDB ->
    shiftDoubleLeft ins insLen bld true
  | Opcode.VSLD ->
    shiftDoubleLeft ins insLen bld false
  | Opcode.VSRD ->
    shiftDoubleRight ins insLen bld
  | Opcode.VCEQ ->
    compare ins insLen bld (==)
  | Opcode.VCH ->
    compare ins insLen bld (?>)
  | Opcode.VCHL ->
    compare ins insLen bld (.>)
  | Opcode.VEC ->
    elementCompare ins insLen bld true
  | Opcode.VECL ->
    elementCompare ins insLen bld false
  | Opcode.VTM ->
    testUnderMask ins insLen bld
  | Opcode.VFEE | Opcode.VFAE ->
    findElement ins insLen bld true
  | Opcode.VFENE ->
    findElement ins insLen bld false
  | Opcode.VISTR ->
    isolateString ins insLen bld
  | Opcode.VSTRC ->
    stringRangeCompare ins insLen bld
  | Opcode.VSTRS ->
    stringSearch ins insLen bld
  | Opcode.VPK | Opcode.VPKS | Opcode.VPKLS ->
    pack ins insLen bld
  | Opcode.VMRH ->
    merge ins insLen bld true
  | Opcode.VMRL ->
    merge ins insLen bld false
  | Opcode.VPERM ->
    permute ins insLen bld
  | Opcode.VPDI ->
    permuteDoubleword ins insLen bld
  | Opcode.VSEG ->
    signExtendDoubleword ins insLen bld
  | _ ->
    unsupported ins insLen bld

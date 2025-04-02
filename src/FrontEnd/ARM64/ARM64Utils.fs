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

module internal B2R2.FrontEnd.ARM64.Utils

open B2R2
open B2R2.FrontEnd.ARM64

let extract binary n1 n2 =
  let m, n = if max n1 n2 = n1 then n1, n2 else n2, n1
  let range = m - n + 1u
  if range > 31u then failwith "invaild range" else ()
  let mask = pown 2 (int range) - 1 |> uint32
  binary >>> int n &&& mask

let pickBit binary (pos: uint32) = binary >>> int pos &&& 0b1u

let concat (n1: uint32) (n2: uint32) shift = (n1 <<< shift) + n2

let halve bin = bin &&& 0x0000ffffu, bin >>> 16

/// n : uint32
let intToBits n cipher =
  let rec loop acc idx =
    if idx < 0 then acc
    else loop (byte ((n &&& pown 2u idx) >>> idx) :: acc) (idx - 1)
  loop [] (cipher - 1) |> List.rev

/// Manual util functions
// SignExtend()
let signExtend bitSize extSize (imm: uint64) =
  assert (bitSize <= extSize)
  if imm >>> (bitSize - 1) = 0b0UL then imm
  else BigInteger.getMask extSize - BigInteger.getMask bitSize ||| (bigint imm)
       |> uint64

// ZeroExtend()
// ============
let zeroExtend bitSize extSize (imm: uint32) =
  assert (bitSize <= extSize)
  concat (0u <<< (extSize - bitSize - 1)) imm bitSize

// BFXPreferred()
// ==============
//
// Return TRUE if UBFX or SBFX is the preferred disassembly of a
// UBFM or SBFM bitfield instruction. Must exclude more specific
// aliases UBFIZ, SBFIZ, UXT[BH], SXT[BHW], LSL, LSR and ASR.
let BFXPreferred sf uns imms immr =
  if imms < immr then false
  else if imms = (concat sf 0b11111u 5) then false
  else if immr = 0b000000u then
    if sf = 0b0u && (imms = 0b000111u || imms = 0b001111u) then false
    else
      not (concat sf uns 1 = 0b10u
        && (imms = 0b000111u || imms = 0b001111u || imms = 0b011111u))
  else true

// HighestSetBit()
// ===============
let highestSetBit nBit imm =
  let rec loop idx =
    if idx < 0 then failwith "There is no SeBit"
    else if imm &&& (1u <<< idx) <> 0u then idx else loop (idx - 1)
  loop (nBit - 1)

// Ones()
// ======
let ones n = (pown 2 (n - 1)) - 1
let zeroExtendOnes m _ = (1L <<< m) - 1L

// ROR()
// =====
let RORZeroExtendOnes m n r =
  let value = zeroExtendOnes m n
  if r = 0 then value
  else ((value >>> r) &&& ((1L <<< (n - r)) - 1L)) |||
       ((value &&& ((1L <<< r) - 1L)) <<< (n - r))

// Replicate()
// ===========
let replicate value bits oprSize =
  let rec loop acc shift =
    if shift >= RegType.toBitWidth oprSize then acc
    else loop (acc ||| (value <<< shift)) (shift + bits)
  loop value bits

// DecodeBitMasks()
// ================
// Decode AArch64 bitfield and logical immediate masks which use a similar
// encoding structure
let decodeBitMasks immN imms immr isImm oprSize =
  let len = highestSetBit 7 ((immN <<< 6) ||| (~~~imms &&& 0x3fu))
  if len < 1 then failwith "reserve value" else ()
  let levels = zeroExtendOnes len 6 |> uint32
  if isImm && (imms &&& levels) = levels then failwith "reserved value" else ()

  let eSize = 1 <<< len
  let s = imms &&& levels
  let r = immr &&& levels

  replicate (RORZeroExtendOnes (int s + 1) eSize (int r)) eSize oprSize

// aarch64/instrs/system/sysops/sysop/SysOp
// SysOp()
// =======
let SysOp bin =
  match extract bin 18u 5u with
  | 0b00001111000000u -> SysAT // S1E1R
  | 0b10001111000000u -> SysAT // S1E2R
  | 0b11001111000000u -> SysAT // S1E3R
  | 0b00001111000001u -> SysAT // S1E1W
  | 0b10001111000001u -> SysAT // S1E2W
  | 0b11001111000001u -> SysAT // S1E3W
  | 0b00001111000010u -> SysAT // S1E0R
  | 0b00001111000011u -> SysAT // S1E0W
  | 0b10001111000100u -> SysAT // S12E1R
  | 0b10001111000101u -> SysAT // S12E1W
  | 0b10001111000110u -> SysAT // S12E0R
  | 0b10001111000111u -> SysAT // S12E0W
  | 0b01101110100001u -> SysDC // ZVA
  | 0b00001110110001u -> SysDC // IVAC
  | 0b00001110110010u -> SysDC // ISW
  | 0b01101111010001u -> SysDC // CVAC
  | 0b00001111010010u -> SysDC // CSW
  | 0b01101111011001u -> SysDC // CVAU
  | 0b01101111110001u -> SysDC // CIVAC
  | 0b00001111110010u -> SysDC // CISW
  | 0b00001110001000u -> SysIC // IALLUIS
  | 0b00001110101000u -> SysIC // IALLU
  | 0b01101110101001u -> SysIC // IVAU
  | 0b10010000000001u -> SysTLBI // IPAS2E1IS
  | 0b10010000000101u -> SysTLBI // IPAS2LE1IS
  | 0b00010000011000u -> SysTLBI // VMALLE1IS
  | 0b10010000011000u -> SysTLBI // ALLE2IS
  | 0b11010000011000u -> SysTLBI // ALLE3IS
  | 0b00010000011001u -> SysTLBI // VAE1IS
  | 0b10010000011001u -> SysTLBI // VAE2IS
  | 0b11010000011001u -> SysTLBI // VAE3IS
  | 0b00010000011010u -> SysTLBI // ASIDE1IS
  | 0b00010000011011u -> SysTLBI // VAAE1IS
  | 0b10010000011100u -> SysTLBI // ALLE1IS
  | 0b00010000011101u -> SysTLBI // VALE1IS
  | 0b10010000011101u -> SysTLBI // VALE2IS
  | 0b11010000011101u -> SysTLBI // VALE3IS
  | 0b10010000011110u -> SysTLBI // VMALLS12E1IS
  | 0b00010000011111u -> SysTLBI // VAALE1IS
  | 0b10010000100001u -> SysTLBI // IPAS2E1
  | 0b10010000100101u -> SysTLBI // IPAS2LE1
  | 0b00010000111000u -> SysTLBI // VMALLE1
  | 0b10010000111000u -> SysTLBI // ALLE2
  | 0b11010000111000u -> SysTLBI // ALLE3
  | 0b00010000111001u -> SysTLBI // VAE1
  | 0b10010000111001u -> SysTLBI // VAE2
  | 0b11010000111001u -> SysTLBI // VAE3
  | 0b00010000111010u -> SysTLBI // ASIDE1
  | 0b00010000111011u -> SysTLBI // VAAE1
  | 0b10010000111100u -> SysTLBI // ALLE1
  | 0b00010000111101u -> SysTLBI // VALE1
  | 0b10010000111101u -> SysTLBI // VALE2
  | 0b11010000111101u -> SysTLBI // VALE3
  | 0b10010000111110u -> SysTLBI // VMALLS12E1
  | 0b00010000111111u -> SysTLBI // VAALE1
  | _ -> SysSYS

// DecodeImmShift()
let decodeImmShift typ imm5 =
  match typ with
  | 0b00u -> SRTypeLSL, imm5
  | 0b01u -> SRTypeLSR, if imm5 = 0ul then 32ul else imm5
  | 0b10u -> SRTypeASR, if imm5 = 0ul then 32ul else imm5
  | 0b11u when imm5 = 0ul -> SRTypeRRX, 1ul
  | 0b11u -> SRTypeROR, imm5
  | _ -> raise InvalidTypeException

// DecodeRegShift()
let decodeRegShift = function
  | 0b00u -> SRTypeLSL
  | 0b01u -> SRTypeLSR
  | 0b10u -> SRTypeASR
  | 0b11u -> SRTypeROR
  | _ -> raise InvalidTypeException

// aarch64/instrs/integer/logical/movwpreferred/MoveWidePreferred
// MoveWidePreferred()
// ===================
//
// Return TRUE if a bitmask immediate encoding would generate an immediate
// value that could also be represented by a single MOVZ or MOVN instruction.
// Used as a condition for the preferred MOV<-ORR alias.
let moveWidePreferred bin = // sf immN imms immr
  let isSfOne = (pickBit bin 31u) = 0b1u
  let immN = pickBit bin 22u
  let imms = extract bin 15u 10u
  let immr = extract bin 21u 16u
  let immNimms = concat immN imms 6
  let width = if isSfOne then 64 else 32
  // element size must equal total immediate size
  if isSfOne && (immNimms &&& 0b1000000u <> 0b1000000u) then false
  else if isSfOne && (immNimms &&& 0b1100000u <> 0b0000000u) then false
  // for MOVZ must contain no more than 16 ones
  // ones must not span halfword boundary when rotated
  else if imms < 16u then 0xf &&& (- (int immr) % 16) <= (15 - (int imms))
  // for MOVN must contain no more than 16 zeros
  // zeros must not span halfword boundary when rotated
  else if (int imms) >= width - 15
  then (int immr % 16) <= (int imms - (width - 15)) else false

// shared/functions/integer/AddWithCarry
// AddWithCarry()
// ==============
// Integer addition with carry input, returning result and NZCV flags
let addWithCarry x y carryin size =
  let unsignedSum = uint32 x + uint32 y + uint32 carryin
  let signedSum = int x + int y + int carryin
  let result = extract unsignedSum (size - 1u) 0u
  let n = pickBit result (size - 1u)
  let z = if result = 0u then 1u else 0u
  let c = if uint32 result = unsignedSum then 0u else 1u
  let v = if int result = signedSum then 0u else 1u
  result, concat (concat (concat n z 1) c 1) v 1

// vim: set tw=80 sts=2 sw=2:

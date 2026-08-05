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

/// <summary>
/// Encodes everything reaching memory: the loads and the stores of every
/// width, at a distance held in a register and at one written out, into the
/// general registers, into the floating-point ones, and into the registers of
/// a unit outside the processor.
/// </summary>
module internal B2R2.Assembly.PARISC.AsmMemory

open B2R2.FrontEnd.PARISC
open B2R2.Assembly.PARISC.ParserHelper
open B2R2.Assembly.PARISC.AsmField

(* The six bits the instructions reaching memory at a short distance begin
   with, already in the place they sit. *)
let [<Literal>] private OpShort = 0x0C000000u

(* The bit saying that how far an instruction reaches is written out rather
   than held in a register. *)
let [<Literal>] private Written = 0x1000u

(* The two bits telling the load of a word from the load of a floating-point
   number where the two share the six a word begins with. They lie just above
   the sign of the distance, which is why such a load reaches only every
   fourth byte. *)
let [<Literal>] private WordSelect = 0x4u

/// <summary>
/// The two bits saying what becomes of the register an address is counted
/// from, where the address is reached at a distance held in a second register.
///
/// One of the two says whether that second register was already scaled to the
/// width of what is read, and the other whether the first is left holding the
/// address it reached.
/// </summary>
let private indexedModify = function
  | [] -> 0u, 0u
  | [ "m" ] -> 0u, 1u
  | [ "s" ] -> 1u, 0u
  | [ "sm" ] -> 1u, 1u
  | _ -> fail "no address is counted this way"

/// The same, where the distance is written out, in which case the two bits say
/// which side of the reading the register is left holding the address on, and
/// leaving it holding an address it already held is written differently from
/// the rest.
let private shortModify zero = function
  | [] -> 0u, 0u
  | [ "o" ] when zero -> 0u, 1u
  | [ "ma" ] when not zero -> 0u, 1u
  | [ "mb" ] -> 1u, 1u
  | _ -> fail "no address is counted this way"

/// The same, for the stores laying down only part of a doubleword, which say
/// which part they lay down where the others say how they were scaled.
let private bytesModify _ = function
  | [] -> 0u, 0u
  | [ "b"; "m" ] -> 0u, 1u
  | [ "e" ] -> 1u, 0u
  | [ "e"; "m" ] -> 1u, 1u
  | _ -> fail "no partial store is written this way"

/// The two bits a load carries saying what is to become of what it touches.
let private loadHint = function
  | [] -> 0u
  | [ "sl" ] -> 2u
  | _ -> fail "a load carries no such hint"

/// The same, for the loads taking hold of what they read so that nothing else
/// may have it.
let private lockHint = function
  | [] -> 0u
  | [ "co" ] -> 1u
  | _ -> fail "a locking load carries no such hint"

/// The same, for a store.
let private storeHint = function
  | [] -> 0u
  | [ "bc" ] -> 1u
  | [ "sl" ] -> 2u
  | _ -> fail "a store carries no such hint"

/// No space at all, which is what the instructions reaching memory as the
/// processor itself sees it name.
let private noSpace = function
  | None ->
    0u
  | Some(reg: Register) ->
    fail $"nothing is reached in {Register.toString reg} here"

/// How far an instruction reaches, where it reaches only every so many bytes.
let private every width (offset: uint64) =
  if int64 offset % width = 0L then offset
  else fail $"this reaches only every {width} bytes"

/// A load reaching memory at a distance held in a second register.
let private indexedLoad ext4 space hint ins =
  let flags, rest = split [ "m"; "s"; "sm" ] ins.Suffixes
  let a, m = indexedModify flags
  let cc = hint rest
  match ins.Operands with
  | [ Mem(Some(Rg index), sp, baseReg); Rg d ] ->
    OpShort ||| (gpr baseReg <<< 21) ||| (gpr index <<< 16) ||| space sp
    ||| (a <<< 13) ||| (cc <<< 10) ||| (ext4 <<< 6) ||| (m <<< 5) ||| gpr d
  | _ ->
    wrongOperands ins

/// A load reaching memory at a written distance of five bits.
let private shortLoad ext4 space hint ins =
  let flags, rest = split [ "o"; "ma"; "mb" ] ins.Suffixes
  let cc = hint rest
  match ins.Operands with
  | [ Mem(Some(Im offset), sp, baseReg); Rg d ] ->
    let a, m = shortModify (offset = 0UL) flags
    OpShort ||| (gpr baseReg <<< 21) ||| (lowSignExt 5 offset <<< 16)
    ||| space sp ||| (a <<< 13) ||| Written ||| (cc <<< 10) ||| (ext4 <<< 6)
    ||| (m <<< 5) ||| gpr d
  | _ ->
    wrongOperands ins

/// A store reaching memory at a written distance of five bits, which keeps
/// that distance where a load keeps the register it lands in.
let private shortStore ext4 space modify hint ins =
  let flags, rest = split [ "o"; "ma"; "mb"; "b"; "e"; "m" ] ins.Suffixes
  let cc = hint rest
  match ins.Operands with
  | [ Rg s; Mem(Some(Im offset), sp, baseReg) ] ->
    let a, m = modify (offset = 0UL) (List.sort flags)
    OpShort ||| (gpr baseReg <<< 21) ||| (gpr s <<< 16) ||| space sp
    ||| (a <<< 13) ||| Written ||| (cc <<< 10) ||| (ext4 <<< 6) ||| (m <<< 5)
    ||| lowSignExt 5 offset
  | _ ->
    wrongOperands ins

/// A load reaching memory at a written distance of fourteen bits.
let private longLoad opcode ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Mem(Some(Im offset), sp, baseReg); Rg d ] ->
    (opcode <<< 26) ||| (gpr baseReg <<< 21) ||| (gpr d <<< 16) ||| space2 sp
    ||| assemble16 offset
  | _ ->
    wrongOperands ins

/// A store reaching memory at a written distance of fourteen bits.
let private longStore opcode ins =
  nothingLeft ins ins.Suffixes
  match ins.Operands with
  | [ Rg s; Mem(Some(Im offset), sp, baseReg) ] ->
    (opcode <<< 26) ||| (gpr baseReg <<< 21) ||| (gpr s <<< 16) ||| space2 sp
    ||| assemble16 offset
  | _ ->
    wrongOperands ins

/// <summary>
/// Whether the word written after the name of a load or a store agrees with
/// how far it reaches.
///
/// Some of these instructions leave the register an address is counted from
/// holding that address, and which side of the reading they do it on is not
/// written in the encoding at all: it is read off the sign of the distance.
/// </summary>
let private agrees before (offset: uint64) flags =
  let negative = int64 offset < 0L
  let ok =
    match flags with
    | [ "mb" ] -> negative = before
    | [ "ma" ] -> negative <> before
    | _ -> false
  if ok then () else fail "this is not how far such an instruction reaches"

/// A load of fourteen bits' distance that leaves the register it counted from
/// holding the address it reached.
let private modifiedLoad opcode before extra step ins =
  let flags, rest = split [ "ma"; "mb" ] ins.Suffixes
  nothingLeft ins rest
  match ins.Operands with
  | [ Mem(Some(Im offset), sp, baseReg); Rg d ] ->
    let offset = every step offset
    agrees before offset flags
    (opcode <<< 26) ||| (gpr baseReg <<< 21) ||| (gpr d <<< 16) ||| space2 sp
    ||| assemble16 offset ||| extra
  | _ ->
    wrongOperands ins

/// The same, for a store.
let private modifiedStore opcode before extra step ins =
  let flags, rest = split [ "ma"; "mb" ] ins.Suffixes
  nothingLeft ins rest
  match ins.Operands with
  | [ Rg s; Mem(Some(Im offset), sp, baseReg) ] ->
    let offset = every step offset
    agrees before offset flags
    (opcode <<< 26) ||| (gpr baseReg <<< 21) ||| (gpr s <<< 16) ||| space2 sp
    ||| assemble16 offset ||| extra
  | _ ->
    wrongOperands ins

/// <summary>
/// A load of a doubleword reaching a whole doubleword's distance away.
///
/// The three lowest bits of such a distance are always clear, so the encoding
/// spends them on saying what becomes of the register the address was counted
/// from, and on telling a doubleword of a floating-point number from one of
/// anything else.
/// </summary>
let private doubleLoad opcode kind target ins =
  let flags, rest = split [ "o"; "ma"; "mb" ] ins.Suffixes
  nothingLeft ins rest
  match ins.Operands with
  | [ Mem(Some(Im offset), sp, baseReg); Rg d ] ->
    let offset = every 8L offset
    let a, m = shortModify (offset = 0UL) flags
    (opcode <<< 26) ||| (gpr baseReg <<< 21) ||| (target d <<< 16)
    ||| space2 sp ||| assemble16 offset ||| (m <<< 3) ||| (a <<< 2) ||| kind
  | _ ->
    wrongOperands ins

/// The same, for a store.
let private doubleStore opcode kind source ins =
  let flags, rest = split [ "o"; "ma"; "mb" ] ins.Suffixes
  nothingLeft ins rest
  match ins.Operands with
  | [ Rg s; Mem(Some(Im offset), sp, baseReg) ] ->
    let offset = every 8L offset
    let a, m = shortModify (offset = 0UL) flags
    (opcode <<< 26) ||| (gpr baseReg <<< 21) ||| (source s <<< 16)
    ||| space2 sp ||| assemble16 offset ||| (m <<< 3) ||| (a <<< 2) ||| kind
  | _ ->
    wrongOperands ins

/// <summary>
/// A load of a floating-point word reaching a whole word's distance away.
///
/// What it loads is half of a register, and the bit saying which half is the
/// one just above the sign of the distance, which the distance has no use for
/// because it counts in whole words.
/// </summary>
let private wordFloatLoad opcode side ins =
  match ins.Operands with
  | [ Mem(Some(Im offset), sp, baseReg); Rg d ] ->
    let n, right = fprHalf d
    (opcode <<< 26) ||| (gpr baseReg <<< 21) ||| (n <<< 16) ||| space2 sp
    ||| assemble16 (every 4L offset) ||| side ||| (right <<< 1)
  | _ ->
    wrongOperands ins

/// The same, for a store.
let private wordFloatStore opcode side ins =
  match ins.Operands with
  | [ Rg s; Mem(Some(Im offset), sp, baseReg) ] ->
    let n, right = fprHalf s
    (opcode <<< 26) ||| (gpr baseReg <<< 21) ||| (n <<< 16) ||| space2 sp
    ||| assemble16 (every 4L offset) ||| side ||| (right <<< 1)
  | _ ->
    wrongOperands ins

/// <summary>
/// One word of the kind a unit outside the processor loads and stores with.
///
/// Which unit is meant lies in three bits just below the one saying whether
/// the instruction stores, and the floating-point unit is the one those three
/// bits name where they are clear.
/// </summary>
let private coprocessor opcode uid store rest =
  (opcode <<< 26) ||| (store <<< 9) ||| (uid <<< 6) ||| rest

/// A load into a unit outside the processor at a distance held in a register.
let private unitIndexedLoad opcode uid target ins =
  let flags, rest = split [ "m"; "s"; "sm" ] ins.Suffixes
  let a, m = indexedModify flags
  let cc = loadHint rest
  match ins.Operands with
  | [ Mem(Some(Rg index), sp, baseReg); Rg d ] ->
    coprocessor opcode uid 0u
      ((gpr baseReg <<< 21) ||| (gpr index <<< 16) ||| space2 sp
       ||| (a <<< 13) ||| (cc <<< 10) ||| (m <<< 5) ||| target d)
  | _ ->
    wrongOperands ins

/// The same, at a written distance of five bits.
let private unitShortLoad opcode uid target ins =
  let flags, rest = split [ "o"; "ma"; "mb" ] ins.Suffixes
  let cc = loadHint rest
  match ins.Operands with
  | [ Mem(Some(Im offset), sp, baseReg); Rg d ] ->
    let a, m = shortModify (offset = 0UL) flags
    coprocessor opcode uid 0u
      ((gpr baseReg <<< 21) ||| (lowSignExt 5 offset <<< 16) ||| space2 sp
       ||| (a <<< 13) ||| Written ||| (cc <<< 10) ||| (m <<< 5) ||| target d)
  | _ ->
    wrongOperands ins

/// A store out of a unit outside the processor at a distance held in a
/// register.
let private unitIndexedStore opcode uid source ins =
  let flags, rest = split [ "m"; "s"; "sm" ] ins.Suffixes
  let a, m = indexedModify flags
  let cc = storeHint rest
  match ins.Operands with
  | [ Rg s; Mem(Some(Rg index), sp, baseReg) ] ->
    coprocessor opcode uid 1u
      ((gpr baseReg <<< 21) ||| (gpr index <<< 16) ||| space2 sp
       ||| (a <<< 13) ||| (cc <<< 10) ||| (m <<< 5) ||| source s)
  | _ ->
    wrongOperands ins

/// The same, at a written distance of five bits.
let private unitShortStore opcode uid source ins =
  let flags, rest = split [ "o"; "ma"; "mb" ] ins.Suffixes
  let cc = storeHint rest
  match ins.Operands with
  | [ Rg s; Mem(Some(Im offset), sp, baseReg) ] ->
    let a, m = shortModify (offset = 0UL) flags
    coprocessor opcode uid 1u
      ((gpr baseReg <<< 21) ||| (lowSignExt 5 offset <<< 16) ||| space2 sp
       ||| (a <<< 13) ||| Written ||| (cc <<< 10) ||| (m <<< 5) ||| source s)
  | _ ->
    wrongOperands ins

/// An instruction naming which unit outside the processor it is meant for,
/// where that unit is not the floating-point one and so is written out.
let private named least build ins =
  let numbers, rest = takeNumbers 1 ins.Suffixes
  let uid = uint32 (List.head numbers)
  if uid < least || uid > 7u then fail $"{uid} names no unit"
  else build uid { ins with Suffixes = rest }

/// A load into a unit outside the processor, at either kind of distance.
let private unitLoad opcode least ins =
  let build uid =
    orTry (unitIndexedLoad opcode uid gpr) (unitShortLoad opcode uid gpr)
  named least build ins

/// A store out of a unit outside the processor, at either kind of distance.
let private unitStore opcode least ins =
  let build uid =
    orTry (unitIndexedStore opcode uid gpr) (unitShortStore opcode uid gpr)
  named least build ins

/// <summary>
/// The bits naming half a floating-point register where the floating-point
/// unit is reached as one coprocessor among several.
///
/// Which half is meant is said by the lowest of the three bits that would
/// otherwise name which coprocessor, which is why the floating-point unit is
/// the one those three bits name where the upper two are clear.
/// </summary>
let private halfRegister reg =
  let n, right = fprHalf reg
  n ||| (right <<< 6)

/// A load of a floating-point number named the way a unit outside the
/// processor names one, which is how the floating-point unit is reached where
/// how far it reaches is held in a register.
let private floatUnitLoad opcode ins =
  orTry (unitIndexedLoad opcode 0u halfRegister)
    (unitShortLoad opcode 0u halfRegister) ins

/// The same, for a store.
let private floatUnitStore opcode ins =
  orTry (unitIndexedStore opcode 0u halfRegister)
    (unitShortStore opcode 0u halfRegister) ins

/// Tries every way an instruction of this name reaches memory, in turn.
let private anyOf forms ins = (List.reduce orTry forms) ins

/// The load of a word, which is written five ways and reaches memory in all of
/// them.
let private ldw =
  anyOf
    [ indexedLoad 0b0010u space2 loadHint
      shortLoad 0b0010u space2 loadHint
      longLoad 0b010010u
      modifiedLoad 0b010011u true 0u 1L
      modifiedLoad 0b010111u false WordSelect 4L ]

/// The store of a word, which is written the same ways but one.
let private stw =
  anyOf
    [ shortStore 0b1010u space2 shortModify storeHint
      longStore 0b011010u
      modifiedStore 0b011011u true 0u 1L
      modifiedStore 0b011111u false WordSelect 4L ]

/// The load of a byte or a halfword, which reaches memory three ways.
let private plainLoad ext4 opcode =
  anyOf
    [ indexedLoad ext4 space2 loadHint
      shortLoad ext4 space2 loadHint
      longLoad opcode ]

/// The store of a byte or a halfword.
let private plainStore ext4 opcode =
  anyOf [ shortStore ext4 space2 shortModify storeHint; longStore opcode ]

/// The load of a doubleword, whose widest form counts in whole doublewords.
let private ldd =
  anyOf
    [ indexedLoad 0b0011u space2 loadHint
      shortLoad 0b0011u space2 loadHint
      doubleLoad 0b010100u 0u gpr ]

/// The store of a doubleword.
let private std =
  anyOf
    [ shortStore 0b1011u space2 shortModify storeHint
      doubleStore 0b011100u 0u gpr ]

/// A load reaching memory as the processor itself sees it, which names no
/// space of its own.
let private absoluteLoad ext4 =
  anyOf [ indexedLoad ext4 noSpace loadHint; shortLoad ext4 noSpace loadHint ]

/// A load taking hold of what it reads so that nothing else may have it.
let private lockingLoad ext4 =
  anyOf [ indexedLoad ext4 space2 lockHint; shortLoad ext4 space2 lockHint ]

/// The load of a floating-point word at a written distance of fourteen bits,
/// where a word after the name says which side of the reading the register the
/// address was counted from is left holding it on.
let private longFloatLoad plain modified ins =
  match ins.Suffixes with
  | [] -> wordFloatLoad plain 0u ins
  | [ "ma" ] -> wordFloatLoad modified 0u ins
  | [ "mb" ] -> wordFloatLoad modified WordSelect ins
  | _ -> wrongSuffixes ins

/// The same, for a store.
let private longFloatStore plain modified ins =
  match ins.Suffixes with
  | [] -> wordFloatStore plain 0u ins
  | [ "ma" ] -> wordFloatStore modified 0u ins
  | [ "mb" ] -> wordFloatStore modified WordSelect ins
  | _ -> wrongSuffixes ins

/// The load of a floating-point word, which is reached four ways.
let private fldw =
  anyOf [ floatUnitLoad 0b001001u; longFloatLoad 0b010111u 0b010110u ]

/// The store of a floating-point word.
let private fstw =
  anyOf [ floatUnitStore 0b001001u; longFloatStore 0b011111u 0b011110u ]

/// The load of a floating-point doubleword.
let private fldd =
  anyOf [ floatUnitLoad 0b001011u; doubleLoad 0b010100u 2u fpr ]

/// The store of a floating-point doubleword.
let private fstd =
  anyOf [ floatUnitStore 0b001011u; doubleStore 0b011100u 2u fpr ]

/// The instructions reaching memory.
let memoryEncoders () =
  [ "ldb", plainLoad 0b0000u 0b010000u
    "ldh", plainLoad 0b0001u 0b010001u
    "ldw", ldw
    "ldd", ldd
    "ldda", absoluteLoad 0b0100u
    "ldcd", lockingLoad 0b0101u
    "ldwa", absoluteLoad 0b0110u
    "ldcw", lockingLoad 0b0111u
    "stb", plainStore 0b1000u 0b011000u
    "sth", plainStore 0b1001u 0b011001u
    "stw", stw
    "std", std
    "stby", shortStore 0b1100u space2 bytesModify storeHint
    "stdby", shortStore 0b1101u space2 bytesModify storeHint
    "stwa", shortStore 0b1110u noSpace shortModify storeHint
    "stda", shortStore 0b1111u noSpace shortModify storeHint
    "fldw", fldw
    "fstw", fstw
    "fldd", fldd
    "fstd", fstd
    "cldw", unitLoad 0b001001u 2u
    "cldd", unitLoad 0b001011u 1u
    "cstw", unitStore 0b001001u 2u
    "cstd", unitStore 0b001011u 1u ]

// vim: set tw=80 sts=2 sw=2:

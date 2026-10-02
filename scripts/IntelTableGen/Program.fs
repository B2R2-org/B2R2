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

/// Generates the Intel decode table and opcode enum from Intel.json:
/// InstructionArrays.fs, the rows of every opcode map packed into primitive
/// arrays, and Opcode.fs, the enum those rows name their instructions with.
/// Intel.json is the source the two are read from; neither is written by
/// hand.
///
/// The tool stands alone rather than referencing the Intel project, so that
/// it builds however broken the files it is about to replace are. The bit
/// layouts and enum numberings it writes are the ones InstructionCore.fs
/// and InstructionArrays.fs's own decode functions read, and are stated once
/// each below.
module IntelTableGen

open System
open System.IO
open System.Text
open System.Text.Json
open System.Globalization
open System.Collections.Generic

/// One operand descriptor, as Intel.json spells it. Structural equality is
/// what lets identical operand lists share one packed copy.
type Opr =
  | RM of int
  | RMdiff of int * int
  | RMEr of int * int
  | RMSae of int * int
  | RMBcst of int * int * int
  | RMBcstEr of int * int * int
  | RMBcstSae of int * int * int
  | RegSae of int
  | Reg of int * string
  | RegAddr
  | OpMaskReg of string
  | KM of int
  | Sreg
  | CtrlReg
  | DebugReg
  | FixedReg of string
  | STReg of string option
  | BM of int
  | BndReg
  | MM of int
  | MMXReg of string
  | Mem of int
  | MemVSIB of int
  | Moffs of int
  | Far of int
  | Imm of int
  | FixedImm of int
  | Rel of int
  | NoOpr

type ModRM =
  | NoModRM
  | ModRMr of string
  | ModRMOp of int * string
  | FixedModRM of int
  | STiModRM of int

/// The APX bits an EVEX-promoted row allows, as Intel.json spells them: "0",
/// "1" or "0/1" for ND and NF, and the source condition code of a CCMPscc
/// or CTESTscc row, -1 where it carries none.
type ApxNeed =
  { ND: string
    NF: string
    SCC: int }

type Row =
  { OpcodeByte: int
    Opcode: string
    Class: string
    Map: string
    Prefix: string
    REX: string
    VL: string
    ModRM: ModRM
    Operands: Opr list
    OpEn: string
    Mode64: string
    Compat: string
    Tuple: string
    SzCond: string
    APX: ApxNeed option }

type OpcodeEntry =
  { Name: string
    Descriptions: string list
    Aliases: string list }

/// Checks an object against the fields it may carry, so that a misspelt
/// field stops the build rather than being ignored. A "note" is allowed
/// anywhere, for the reason a row or an opcode is the way it is.
let private allowKeys (e: JsonElement) (allowed: string list) (what: string) =
  for p in e.EnumerateObject() do
    if p.Name <> "note" && not (List.contains p.Name allowed) then
      failwithf "%s: unknown field '%s'" what p.Name
    else
      ()

let private str (e: JsonElement) (name: string) =
  match e.TryGetProperty name with
  | true, v -> v.GetString()
  | _ -> failwithf "missing field '%s'" name

let private num (e: JsonElement) (name: string) =
  match e.TryGetProperty name with
  | true, v when v.ValueKind = JsonValueKind.Number -> v.GetInt32()
  | true, v -> Int32.Parse(v.GetString(), CultureInfo.InvariantCulture)
  | _ -> failwithf "missing field '%s'" name

let private parseOpr (e: JsonElement) =
  let kind = str e "kind"
  let chk keys = allowKeys e ("kind" :: keys) ("operand " + kind)
  let sz name = num e name
  match kind with
  | "RM" ->
    chk [ "size" ]
    RM(sz "size")
  | "RMdiff" ->
    chk [ "size1"; "size2" ]
    RMdiff(sz "size1", sz "size2")
  | "RMEr" ->
    chk [ "size1"; "size2" ]
    RMEr(sz "size1", sz "size2")
  | "RMSae" ->
    chk [ "size1"; "size2" ]
    RMSae(sz "size1", sz "size2")
  | "RMBcst" ->
    chk [ "size1"; "size2"; "size3" ]
    RMBcst(sz "size1", sz "size2", sz "size3")
  | "RMBcstEr" ->
    chk [ "size1"; "size2"; "size3" ]
    RMBcstEr(sz "size1", sz "size2", sz "size3")
  | "RMBcstSae" ->
    chk [ "size1"; "size2"; "size3" ]
    RMBcstSae(sz "size1", sz "size2", sz "size3")
  | "RegSae" ->
    chk [ "size" ]
    RegSae(sz "size")
  | "Reg" ->
    chk [ "size"; "regType" ]
    Reg(sz "size", str e "regType")
  | "RegAddr" ->
    chk []
    RegAddr
  | "OpMaskReg" ->
    chk [ "regType" ]
    OpMaskReg(str e "regType")
  | "KM" ->
    chk [ "size" ]
    KM(sz "size")
  | "Sreg" ->
    chk []
    Sreg
  | "CtrlReg" ->
    chk []
    CtrlReg
  | "DebugReg" ->
    chk []
    DebugReg
  | "FixedReg" ->
    chk [ "reg" ]
    FixedReg(str e "reg")
  | "STReg" ->
    chk [ "reg" ]
    match str e "reg" with
    | "ST" -> STReg None
    | r -> STReg(Some r)
  | "BM" ->
    chk [ "size" ]
    BM(sz "size")
  | "BndReg" ->
    chk []
    BndReg
  | "MM" ->
    chk [ "size" ]
    MM(sz "size")
  | "MMXReg" ->
    chk [ "regType" ]
    MMXReg(str e "regType")
  | "Mem" ->
    chk [ "size" ]
    Mem(sz "size")
  | "MemVSIB" ->
    chk [ "size" ]
    MemVSIB(sz "size")
  | "Moffs" ->
    chk [ "size" ]
    Moffs(sz "size")
  | "Far" ->
    chk [ "size" ]
    Far(sz "size")
  | "Imm" ->
    chk [ "size" ]
    Imm(sz "size")
  | "FixedImm" ->
    chk [ "value" ]
    FixedImm(sz "value")
  | "Rel" ->
    chk [ "size" ]
    Rel(sz "size")
  | "NoOpr" ->
    chk []
    NoOpr
  | k ->
    failwithf "unknown operand kind '%s'" k

let private parseModRM (e: JsonElement) =
  let kind = str e "kind"
  let chk keys = allowKeys e ("kind" :: keys) ("ModRM " + kind)
  match kind with
  | "NoModRM" ->
    chk []
    NoModRM
  | "ModRM" ->
    chk [ "oprType" ]
    ModRMr(str e "oprType")
  | "FixedModRM" ->
    chk [ "digit" ]
    FixedModRM(num e "digit")
  | "STiModRM" ->
    chk [ "base" ]
    STiModRM(num e "base")
  | k when k.StartsWith "ModRMOp" && k.Length = 8 ->
    chk [ "oprType" ]
    ModRMOp(int k[7] - int '0', str e "oprType")
  | k ->
    failwithf "unknown ModRM kind '%s'" k

let private rowFields =
  [ "OpcodeByte"
    "Opcode"
    "OpcodeClass"
    "PrefixType"
    "REXPrefixType"
    "VectorLength"
    "ModRM"
    "Operands"
    "OpEn"
    "Mode64"
    "Compat"
    "TupleType"
    "SzCond"
    "APX" ]

let private parseAPX (e: JsonElement) =
  match e.TryGetProperty "APX" with
  | true, a ->
    allowKeys a [ "ND"; "NF"; "SCC" ] "APX"
    let scc =
      match a.TryGetProperty "SCC" with
      | true, _ -> num a "SCC"
      | _ -> -1
    Some { ND = str a "ND"; NF = str a "NF"; SCC = scc }
  | _ ->
    None

let private parseRow (e: JsonElement) =
  allowKeys e rowFields "row"
  let cls = e.GetProperty "OpcodeClass"
  allowKeys cls [ "type"; "map" ] "OpcodeClass"
  let pref = e.GetProperty "PrefixType"
  allowKeys pref [ "type"; "kind" ] "PrefixType"
  let operands = e.GetProperty "Operands"
  { OpcodeByte = num e "OpcodeByte"
    Opcode = str e "Opcode"
    Class = str cls "type"
    Map = str cls "map"
    Prefix = str pref "type" + " " + str pref "kind"
    REX = str e "REXPrefixType"
    VL = str e "VectorLength"
    ModRM = parseModRM (e.GetProperty "ModRM")
    Operands = [ for o in operands.EnumerateArray() -> parseOpr o ]
    OpEn = str e "OpEn"
    Mode64 = str e "Mode64"
    Compat = str e "Compat"
    Tuple = str e "TupleType"
    SzCond = str e "SzCond"
    APX = parseAPX e }

let private parseOpcode (e: JsonElement) =
  allowKeys e [ "name"; "description"; "aliases" ] "opcode"
  let desc = e.GetProperty "description"
  { Name = str e "name"
    Descriptions =
      if desc.ValueKind = JsonValueKind.Array then
        [ for d in desc.EnumerateArray() -> d.GetString() ]
      else
        [ desc.GetString() ]
    Aliases =
      match e.TryGetProperty "aliases" with
      | true, a -> [ for x in a.EnumerateArray() -> x.GetString() ]
      | _ -> [] }

let private readJson (path: string) =
  use doc = JsonDocument.Parse(File.ReadAllText path)
  let root = doc.RootElement
  allowKeys root [ "opcodes"; "rows" ] "Intel.json"
  let opcodes = root.GetProperty "opcodes"
  let rows = root.GetProperty "rows"
  let opcodes = [ for o in opcodes.EnumerateArray() -> parseOpcode o ]
  let rows = [ for r in rows.EnumerateArray() -> parseRow r ]
  opcodes, rows

/// Numbers the opcodes. Names are sorted, and a name shares the number of the
/// alias group it belongs to, so that which row the decoder reaches first
/// cannot change the opcode. The group takes its number where its first name
/// sorts, and is written out with its representative first.
let private numberOpcodes (entries: OpcodeEntry list) =
  let canonical = Dictionary<string, string>()
  let aliasOrder = Dictionary<string, int>()
  for e in entries do
    canonical[e.Name] <- e.Name
    aliasOrder[e.Name] <- 0
    e.Aliases |> List.iteri (fun i a ->
      canonical[a] <- e.Name
      aliasOrder[a] <- i + 1)
  let names =
    canonical.Keys
    |> Seq.toArray
    |> Array.sortWith (fun a b -> String.CompareOrdinal(a, b))
  let ids = Dictionary<string, int>()
  let mutable next = 0
  let alphabetical =
    names
    |> Array.map (fun n ->
      let c = canonical[n]
      if not (ids.ContainsKey c) then
        ids[c] <- next
        next <- next + 1
      else
        ()
      n, ids[c])
  let emitted =
    alphabetical
    |> Array.sortBy (fun (n, idx) -> idx, aliasOrder[n], n)
  let isAlias n = canonical[n] <> n
  alphabetical, emitted, next, ids, isAlias

let private licence = """(*
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
*)"""

let private generatedNote =
  "(* Generated by IntelTableGen from scripts/IntelTableGen/Intel.json; "
  + "do not\n   edit it, edit Intel.json and rerun the generator. *)"

let private opcodeModule = """  let isBranch = function
    | Opcode.CALL | Opcode.JMP | Opcode.JMPABS | Opcode.RET
    | Opcode.JA | Opcode.JB | Opcode.JBE | Opcode.JCXZ | Opcode.JECXZ
    | Opcode.JG | Opcode.JL | Opcode.JLE | Opcode.JNB | Opcode.JNL
    | Opcode.JNO | Opcode.JNP | Opcode.JNS | Opcode.JNZ | Opcode.JO
    | Opcode.JP | Opcode.JRCXZ | Opcode.JS | Opcode.JZ | Opcode.LOOP
    | Opcode.LOOPE | Opcode.LOOPNE -> true
    | _ -> false

  let isCETInstr = function
    | Opcode.INCSSPD | Opcode.INCSSPQ | Opcode.RDSSPD | Opcode.RDSSPQ
    | Opcode.SAVEPREVSSP | Opcode.RSTORSSP | Opcode.WRSSD | Opcode.WRSSQ
    | Opcode.WRUSSD | Opcode.WRUSSQ | Opcode.SETSSBSY | Opcode.CLRSSBSY -> true
    | _ -> false

  /// The conditional compares and tests of Intel APX, whose EVEX prefix
  /// carries a default flags value beside the operands.
  let isCondCmpOrTest = function
    | Opcode.CCMPO | Opcode.CCMPNO | Opcode.CCMPB | Opcode.CCMPNB
    | Opcode.CCMPZ | Opcode.CCMPNZ | Opcode.CCMPBE | Opcode.CCMPA
    | Opcode.CCMPS | Opcode.CCMPNS | Opcode.CCMPT | Opcode.CCMPF
    | Opcode.CCMPL | Opcode.CCMPNL | Opcode.CCMPLE | Opcode.CCMPG
    | Opcode.CTESTO | Opcode.CTESTNO | Opcode.CTESTB | Opcode.CTESTNB
    | Opcode.CTESTZ | Opcode.CTESTNZ | Opcode.CTESTBE | Opcode.CTESTA
    | Opcode.CTESTS | Opcode.CTESTNS | Opcode.CTESTT | Opcode.CTESTF
    | Opcode.CTESTL | Opcode.CTESTNL | Opcode.CTESTLE | Opcode.CTESTG -> true
    | _ -> false
"""

let private toStringTail = """    | Opcode.InvalOP -> "(InvalOp)"
    (* Every declared opcode has a name above, so only a value cast into the
       enum from outside reaches here. The lifter names an instruction it
       cannot express by calling this, so a failure here would report that as
       something other than the missing IR it is. *)
    | _ -> B2R2.Terminator.impossible ()
"""

/// Writes one description as /// lines, wrapped at the column limit.
let private writeComment (w: StreamWriter) (desc: string) =
  let prefix = "  /// "
  let available = 80 - prefix.Length
  let width (s: string) = StringInfo(s).LengthInTextElements
  let words = desc.Split([| ' ' |], StringSplitOptions.RemoveEmptyEntries)
  let mutable line = ""
  for word in words do
    if line.Length = 0 then
      line <- word
    elif width line + 1 + width word <= available then
      line <- line + " " + word
    else
      w.WriteLine(prefix + line)
      line <- word
  if line.Length > 0 then w.WriteLine(prefix + line) else ()

/// Writes the enum: every name with its number, a group's descriptions ahead
/// of its first name, and InvalOP after the last.
let private writeOpcodeEnum (w: StreamWriter) (entries: OpcodeEntry list) =
  let _, emitted, count, _, _ = numberOpcodes entries
  let byName = entries |> List.map (fun e -> e.Name, e) |> dict
  let mutable previous = -1
  w.WriteLine "type Opcode ="
  for name, idx in emitted do
    if idx <> previous then
      for d in byName[name].Descriptions do writeComment w d
    else
      ()
    previous <- idx
    w.WriteLine $"  | {name} = {idx}"
  writeComment w "Invalid Opcode."
  w.WriteLine $"  | InvalOP = {count}"

/// Writes the Opcode module: the fixed predicates and toString, which names
/// every representative and no alias.
let private writeOpcodeModule (w: StreamWriter) (entries: OpcodeEntry list) =
  let alphabetical, _, _, _, isAlias = numberOpcodes entries
  w.WriteLine "\n/// Provides functions to check properties of opcodes."
  w.WriteLine "[<RequireQualifiedAccess>]"
  w.WriteLine "module internal Opcode ="
  w.Write opcodeModule
  w.WriteLine "\n  let toString = function"
  for name, _ in alphabetical do
    if isAlias name then
      ()
    else
      let lower = name.ToLowerInvariant()
      w.WriteLine $"    | Opcode.{name} -> \"{lower}\""
  w.Write toStringTail

let private writeOpcodeFile (path: string) (entries: OpcodeEntry list) =
  use w = new StreamWriter(path, false, UTF8Encoding false)
  w.NewLine <- "\n"
  w.WriteLine licence
  w.WriteLine ""
  w.WriteLine generatedNote
  w.WriteLine ""
  w.WriteLine "namespace B2R2.FrontEnd.Intel\n"
  w.WriteLine "/// <summary>\n/// Represents an Intel opcode.\n/// </summary>"
  writeOpcodeEnum w entries
  writeOpcodeModule w entries

/// O and OI rows name their register in the opcode byte's low three bits,
/// and the table carries one row apiece; the seven bytes after it are the
/// same row with the next register.
let private expandRegEncodings (rows: Row list) =
  let extra =
    rows
    |> List.filter (fun r -> r.OpEn = "O" || r.OpEn = "OI")
    |> List.collect (fun r ->
      [ for n in 1 .. 7 -> { r with OpcodeByte = r.OpcodeByte + n } ])
  rows @ extra

/// The opcode maps, in the order InstructionArrays.fs declares them.
let private maps =
  [ "Normal", "OneByte", "norOne"
    "Normal", "TwoBytes", "norTwo"
    "Normal", "ThreeBytes38", "norThree38"
    "Normal", "ThreeBytes3A", "norThree3A"
    "VEX", "TwoBytes", "vexTwo"
    "VEX", "ThreeBytes38", "vexThree38"
    "VEX", "ThreeBytes3A", "vexThree3A"
    "EVEX", "TwoBytes", "evexTwo"
    "EVEX", "ThreeBytes38", "evexThree38"
    "EVEX", "ThreeBytes3A", "evexThree3A"
    "EVEX", "MAP5", "evexMap5"
    "EVEX", "MAP6", "evexMap6"
    "EVEX", "MAP4", "evexMap4"
    "EVEX", "MAP7", "evexMap7" ]

/// Reports entries that no emitted table claims. An opcode map we do not
/// handle yet must not go missing without a word.
let private reportUnemitted (rows: Row list) =
  for (cls, map), n in rows |> List.countBy (fun r -> r.Class, r.Map) do
    if maps |> List.exists (fun (c, m, _) -> c = cls && m = map) then
      ()
    else
      let what = sprintf "%s %s" cls map
      printfn "[Error] %d %s entries have no table and are dropped." n what

let private hasSz16 = function
  | RM 16 | Reg(16, _) | Rel 16 | RegSae 16 ->
    true
  | RMdiff(a, b) | RMEr(a, b) | RMSae(a, b) ->
    a = 16 || b = 16
  | RMBcst(a, b, c) | RMBcstEr(a, b, c) | RMBcstSae(a, b, c) ->
    a = 16 || b = 16 || c = 16
  | _ ->
    false

/// Rows of one slot that differ only in their operands cannot be told apart
/// by the decoder, unless an operand-size prefix separates a 16-bit form.
let private sanitizeSlot (slot: Row[]) =
  let sameButOperands (a: Row) (b: Row) =
    { a with Operands = [] } = { b with Operands = [] }
  let anySz16 () =
    slot |> Array.exists (fun r -> r.Operands |> List.exists hasSz16)
  if slot.Length > 1 && slot |> Array.forall (sameButOperands slot[0]) then
    if anySz16 () then
      ()
    else
      printfn
        "[Error] All %d entries are same except Operands: %s(0x%X)"
        slot.Length
        slot[0].Opcode
        slot[0].OpcodeByte
  else
    ()

/// The x87 forms the manual writes with a 9Bh in front, which the decoder
/// reads as WAIT and then the instruction itself.
let private isWaitPrefixedX87 (r: Row) =
  r.OpcodeByte = 0x9B && r.OpEn = "None"

/// The 256 slots of one map. GETSEC's leaves collapse into one row, and the
/// one-byte map's 9Bh slot keeps only WAIT itself.
let private buildMap (cls, map, funName) (rows: Row list) =
  let rows = rows |> List.filter (fun r -> r.Class = cls && r.Map = map)
  Array.init 256 (fun b ->
    let slot = rows |> List.filter (fun r -> r.OpcodeByte = b) |> List.toArray
    let allGetsec = slot |> Array.forall (fun r -> r.Opcode = "GETSEC")
    let slot =
      if slot.Length > 0 && allGetsec then
        Array.distinct slot
      else
        slot
    sanitizeSlot slot
    if funName = "norOne" then
      slot |> Array.filter (isWaitPrefixedX87 >> not)
    else
      slot)

/// Collects the distinct values a field takes, in first-seen order, together
/// with the index each is written as.
let private intern (values: 'T seq) =
  let order = ResizeArray<'T>()
  let index = Dictionary<'T, int>(HashIdentity.Structural)
  for v in values do
    if index.ContainsKey v then
      ()
    else
      index[v] <- order.Count
      order.Add v
  order.ToArray(), index

/// Every width leaves room for the table to grow.
let private fit name width value =
  if value >= (1 <<< width) then
    failwithf "%s no longer fits in %d bits: %d" name width value
  else
    int64 value

/// The fields a register descriptor can be read from, by the index the
/// descriptor carries. InstructionArrays.fs's decodeOpr reads them by this
/// index.
let private regFields = [| "RegBit"; "RMBit"; "VVVV"; "IS4"; "OpRd"; "Unused" |]

let private regField f =
  match Array.tryFindIndex ((=) f) regFields with
  | Some i -> i
  | None -> failwithf "unknown register field '%s'" f

/// One operand descriptor as its integer: the tag in bits 55:48 and up to
/// three values in the three 16-bit fields below it, as decodeOpr reads it.
let private packOpr (fixedIdx: string -> int) opr =
  let pack tag a b c =
    (int64 (tag: int) <<< 48)
    ||| (fit "operand value" 16 a <<< 32)
    ||| (fit "operand value" 16 b <<< 16)
    ||| fit "operand value" 16 c
  match opr with
  | RM s -> pack 0 s 0 0
  | RMdiff(a, b) -> pack 1 a b 0
  | RMEr(a, b) -> pack 2 a b 0
  | RMSae(a, b) -> pack 3 a b 0
  | RMBcst(a, b, c) -> pack 4 a b c
  | RMBcstEr(a, b, c) -> pack 5 a b c
  | RMBcstSae(a, b, c) -> pack 6 a b c
  | RegSae s -> pack 7 s 0 0
  | Reg(s, f) -> pack 8 s (regField f) 0
  | RegAddr -> pack 9 0 0 0
  | OpMaskReg f -> pack 10 (regField f) 0 0
  | KM s -> pack 11 s 0 0
  | Sreg -> pack 12 0 0 0
  | CtrlReg -> pack 13 0 0 0
  | DebugReg -> pack 14 0 0 0
  | FixedReg r -> pack 15 (fixedIdx r) 0 0
  | STReg None -> pack 16 0 0 0
  | STReg(Some r) -> pack 17 (fixedIdx r) 0 0
  | BM s -> pack 18 s 0 0
  | BndReg -> pack 19 0 0 0
  | MM s -> pack 20 s 0 0
  | MMXReg f -> pack 21 (regField f) 0 0
  | Mem s -> pack 22 s 0 0
  | MemVSIB s -> pack 23 s 0 0
  | Moffs s -> pack 24 s 0 0
  | Far s -> pack 25 s 0 0
  | Imm s -> pack 26 s 0 0
  | FixedImm v -> pack 27 v 0 0
  | Rel s -> pack 28 s 0 0
  | NoOpr -> pack 29 0 0 0

/// The ND and NF requirements of a row as decodeRow reads them: 0 clear, 1
/// set, 2 either, mirroring BitNeed in InstructionCore.fs.
let private bitNeed (name: string) (v: string) =
  match v with
  | "0" -> 0
  | "1" -> 1
  | "0/1" -> 2
  | v -> failwithf "unknown %s '%s'" name v

/// The APX bits of a row, packed above its operand list index: a presence
/// bit, ND and NF in two bits apiece, and the source condition code plus one
/// in five, so that zero stands for none.
let private packAPX (apx: ApxNeed option) =
  match apx with
  | None ->
    0L
  | Some a ->
    (1L <<< 52)
    ||| (fit "ND" 2 (bitNeed "ND" a.ND) <<< 53)
    ||| (fit "NF" 2 (bitNeed "NF" a.NF) <<< 55)
    ||| (fit "SCC" 5 (a.SCC + 1) <<< 57)

let private packMain opcodeByte opcode modRM oprList apx =
  fit "opcode byte" 8 opcodeByte
  ||| (fit "opcode" 16 opcode <<< 8)
  ||| (fit "ModRM index" 12 modRM <<< 24)
  ||| (fit "operand list index" 16 oprList <<< 36)
  ||| packAPX apx

let private packAttrs pref rex vl opEn mode64 compat tuple szCond =
  int (fit "prefix index" 3 pref
       ||| (fit "REX prefix" 4 rex <<< 3)
       ||| (fit "vector length" 2 vl <<< 7)
       ||| (fit "Op/En" 7 opEn <<< 9)
       ||| (fit "64-bit mode" 3 mode64 <<< 16)
       ||| (fit "compatibility mode" 3 compat <<< 19)
       ||| (fit "tuple type" 5 tuple <<< 22)
       ||| (fit "size condition" 3 szCond <<< 27))

/// The enum values InstructionCore.fs gives the attributes rowAttrs packs, by
/// name. They mirror that file and have to move with it.
let private enumIndex (name: string) (values: string[]) (v: string) =
  match Array.tryFindIndex ((=) v) values with
  | Some i -> i
  | None -> failwithf "unknown %s '%s'" name v

let private rexTypes =
  [| "NOREX"; "WIG"; "W0"; "W1"; "REX"; "REXW"; "REX2"; "REX2W" |]

let private vectorLengths = [| "None"; "V128"; "V256"; "V512" |]

let private opEns =
  [| "None"
     "A"
     "B"
     "C"
     "D"
     "E"
     "F"
     "FD"
     "G"
     "I"
     "II"
     "M"
     "M1"
     "MC"
     "MI"
     "MR"
     "MRC"
     "MRI"
     "MVR"
     "O"
     "OI"
     "R"
     "RM"
     "RM0"
     "RMI"
     "RMV"
     "RR"
     "RRI"
     "RVM"
     "RVMI"
     "RVMR"
     "RVR"
     "S"
     "TD"
     "VM"
     "VMI"
     "ZO"
     "RI"
     "IR"
     "VR"
     "VMR"
     "VRM"
     "VM1"
     "VMC"
     "VMRI"
     "VMRC" |]

let private mode64s =
  [| "None"
     "NE"
     "NA"
     "NS"
     "Valid"
     "Invalid"
     "VNE"
     "Inv" |]

let private compats = [| "None"; "NE"; "NA"; "Valid"; "Invalid" |]

let private tupleTypes =
  [| "Full"
     "Half"
     "FullMem"
     "Tuple1Scalar"
     "Tuple1Fixed"
     "Tuple2"
     "Tuple4"
     "Tuple8"
     "HalfMem"
     "QuarterMem"
     "EighthMem"
     "Mem128"
     "MOVDDUP"
     "Quarter"
     "Scalar"
     "Tuple1_4X"
     "NA" |]

let private szConds = [| "D64"; "F64"; "Normal" |]

let private modRMText = function
  | NoModRM -> "ModRMType.NoModRM"
  | ModRMr t -> $"ModRMType.ModRM {t}"
  | ModRMOp(d, t) -> $"ModRMType.ModRMOp{d} {t}"
  | FixedModRM b -> $"ModRMType.FixedModRM 0x{b:X2}uy"
  | STiModRM b -> $"ModRMType.STiModRM 0x{b:X2}uy"

let private header = """module B2R2.FrontEnd.Intel.InstructionArrays

open B2R2

(* Generated by IntelTableGen from scripts/IntelTableGen/Intel.json; do not
   edit it, edit Intel.json and rerun the generator. The rows are packed into
   the primitive arrays below and unpacked at first use: written out one
   record apiece, the same table cost 468 KB of IL and a quarter of a second
   to JIT before the first instruction could be read. *)

(* The operand descriptors of every row, as data: each descriptor is one
   integer holding its tag in bits 55:48 and up to three values in the three
   16-bit fields below it, and oprListStart says where each row's list begins.
   Written out as one array literal apiece, the lists were a static
   initializer of 28 KB that took the JIT twenty milliseconds before the first
   instruction could be read. *)
"""

let private rtLine =
  "let inline private rt (n: int) = LanguagePrimitives.Int32WithMeasure<rt> n"

/// The function InstructionArrays.fs reads an operand descriptor back with.
/// It is what
/// undoes packOpr, so it is written here beside it.
let private decodeOprBody = """let private decodeOpr (code: int64) =
  let a = int ((code >>> 32) &&& 0xFFFFL)
  let b = int ((code >>> 16) &&& 0xFFFFL)
  let c = int (code &&& 0xFFFFL)
  match int (code >>> 48) with
  | 0 -> RM(rt a)
  | 1 -> RMdiff(rt a, rt b)
  | 2 -> RMEr(rt a, rt b)
  | 3 -> RMSae(rt a, rt b)
  | 4 -> RMBcst(rt a, rt b, rt c)
  | 5 -> RMBcstEr(rt a, rt b, rt c)
  | 6 -> RMBcstSae(rt a, rt b, rt c)
  | 7 -> RegSae(rt a)
  | 8 -> Reg(rt a, regFields[b])
  | 9 -> RegAddr
  | 10 -> OpMaskReg regFields[a]
  | 11 -> KM(rt a)
  | 12 -> Sreg
  | 13 -> CtrlReg
  | 14 -> DebugReg
  | 15 -> FixedReg fixedRegs[a]
  | 16 -> STReg None
  | 17 -> STReg(Some fixedRegs[a])
  | 18 -> BM(rt a)
  | 19 -> BndReg
  | 20 -> MM(rt a)
  | 21 -> MMXReg regFields[a]
  | 22 -> Mem(rt a)
  | 23 -> MemVSIB(rt a)
  | 24 -> Moffs(rt a)
  | 25 -> Far(rt a)
  | 26 -> Imm(rt a)
  | 27 -> FixedImm a
  | 28 -> Rel(rt a)
  | 29 -> NoOpr
  | _ -> Unknown "bad operand code"

let private oprLists: OperandType[][] =
  let lists = Array.zeroCreate (oprListStart.Length - 1)
  for i in 0 .. lists.Length - 1 do
    let operands = Array.zeroCreate (oprListStart[i + 1] - oprListStart[i])
    for j in 0 .. operands.Length - 1 do
      operands[j] <- decodeOpr oprCodes[oprListStart[i] + j]
    lists[i] <- operands
  lists
"""

/// The functions InstructionArrays.fs reads a row and a map back with; they
/// undo
/// packMain and packAttrs.
let private decodeRow = """/// Reads one row back out of the two arrays above.
let private decodeRow i =
  let m = rowMain[i]
  let a = rowAttrs[i]
  { OpcodeByte = uint32 (m &&& 0xFFL)
    Opcode = enum<Opcode> (int ((m >>> 8) &&& 0xFFFFL))
    PrefixType = prefixTypes[a &&& 0x7]
    REXPrefixType = enum<REXPrefixType> ((a >>> 3) &&& 0xF)
    VectorLength = enum<VectorLength> ((a >>> 7) &&& 0x3)
    ModRM = modRMs[int ((m >>> 24) &&& 0xFFFL)]
    (* Copied so that no two rows share one array: nothing
       writes to these today, and this keeps it that way. *)
    Operands = Array.copy oprLists[int ((m >>> 36) &&& 0xFFFFL)]
    OpEn = enum<OpEn> ((a >>> 9) &&& 0x7F)
    Mode64 = enum<Mode64> ((a >>> 16) &&& 0x7)
    Compat = enum<CompatLegMode> ((a >>> 19) &&& 0x7)
    TupleType = enum<TupleType> ((a >>> 22) &&& 0x1F)
    SzCond = enum<SzCond> ((a >>> 27) &&& 0x7)
    APX =
      if (m >>> 52) &&& 0x1L = 0L then
        None
      else
        Some { ND = enum<BitNeed> (int ((m >>> 53) &&& 0x3L))
               NF = enum<BitNeed> (int ((m >>> 55) &&& 0x3L))
               SCC = int ((m >>> 57) &&& 0x1FL) - 1 } }

/// The 256 slots of one opcode map.
let private buildMap (mapIdx: int) =
  let map = Array.zeroCreate 256
  for slot in 0 .. 255 do
    let k = mapIdx * 256 + slot
    let first = slotStart[k]
    let rows = Array.zeroCreate (slotStart[k + 1] - first)
    for j in 0 .. rows.Length - 1 do
      rows[j] <- decodeRow (first + j)
    map[slot] <- rows
  map

"""

/// Everything the packed table is written from: the rows in the order the
/// decoder reads them, the values they share, and where each list and slot
/// begins.
type private Packed =
  { Rows: Row list
    OprIndex: Dictionary<Opr list, int>
    ModRMs: ModRM[]
    ModRMIndex: Dictionary<ModRM, int>
    Prefixes: string[]
    PrefixIndex: Dictionary<string, int>
    FixedRegs: string[]
    OprCodes: int64[]
    OprListStart: int[]
    SlotStart: int[] }

/// Packs the operand lists: each descriptor as an integer, the fixed
/// registers interned as the packing meets them.
let private packOperandLists (oprLists: Opr list[]) =
  let fixedRegs = ResizeArray<string>()
  let fixedIdx (r: string) =
    match fixedRegs.IndexOf r with
    | -1 ->
      fixedRegs.Add r
      fixedRegs.Count - 1
    | i ->
      i
  let codes = ResizeArray<int64>()
  let starts = ResizeArray<int>()
  for operands in oprLists do
    starts.Add codes.Count
    for o in operands do codes.Add(packOpr fixedIdx o)
  starts.Add codes.Count
  fixedRegs.ToArray(), codes.ToArray(), starts.ToArray()

/// Where each of the 256 slots of each map begins in the row arrays.
let private slotStarts (tables: Row[][] list) =
  let starts = ResizeArray<int>()
  let mutable next = 0
  for slots in tables do
    for slot in slots do
      starts.Add next
      next <- next + slot.Length
  starts.Add next
  starts.ToArray()

let private pack (rows: Row list) =
  let rows = expandRegEncodings rows
  reportUnemitted rows
  let tables = maps |> List.map (fun m -> buildMap m rows)
  let rows = tables |> List.collect (Array.toList >> List.collect Array.toList)
  let oprLists, oprIndex = intern (rows |> Seq.map (fun r -> r.Operands))
  let modRMs, modRMIndex = intern (rows |> Seq.map (fun r -> r.ModRM))
  let prefixes, prefixIndex = intern (rows |> Seq.map (fun r -> r.Prefix))
  printfn
    "[intern] %d rows -> %d operand lists, %d ModRM forms, %d prefixes"
    rows.Length
    oprLists.Length
    modRMs.Length
    prefixes.Length
  let fixedRegs, oprCodes, oprListStart = packOperandLists oprLists
  { Rows = rows
    OprIndex = oprIndex
    ModRMs = modRMs
    ModRMIndex = modRMIndex
    Prefixes = prefixes
    PrefixIndex = prefixIndex
    FixedRegs = fixedRegs
    OprCodes = oprCodes
    OprListStart = oprListStart
    SlotStart = slotStarts tables }

let private opcodeIdOf (ids: Dictionary<string, int>) (name: string) =
  match ids.TryGetValue name with
  | true, i -> i
  | _ -> failwithf "row names an opcode Intel.json does not list: %s" name

let private rowMainLit (p: Packed) opcodeId (r: Row) =
  let opcode = opcodeId r.Opcode
  let modRM = p.ModRMIndex[r.ModRM]
  let oprList = p.OprIndex[r.Operands]
  let bits = packMain r.OpcodeByte opcode modRM oprList r.APX
  $"0x{bits:X}L"

let private rowAttrsLit (p: Packed) (r: Row) =
  packAttrs
    p.PrefixIndex[r.Prefix]
    (enumIndex "REXPrefixType" rexTypes r.REX)
    (enumIndex "VectorLength" vectorLengths r.VL)
    (enumIndex "OpEn" opEns r.OpEn)
    (enumIndex "Mode64" mode64s r.Mode64)
    (enumIndex "Compat" compats r.Compat)
    (enumIndex "TupleType" tupleTypes r.Tuple)
    (enumIndex "SzCond" szConds r.SzCond)
  |> string

/// Writes a doc comment, one line apiece.
let private writeDoc (w: StreamWriter) (lines: string list) =
  for line in lines do w.WriteLine("/// " + line)

/// Writes a literal whose elements each take a line of their own.
let private writeLines (w: StreamWriter) name typ (elems: string[]) =
  w.WriteLine $"let private {name}: {typ} ="
  w.WriteLine "  [|"
  elems |> Array.iter (fun e -> w.WriteLine $"    {e}")
  w.WriteLine "  |]"
  w.WriteLine ""

/// Writes the operand descriptors and what reads them back.
let private writeOperands (w: StreamWriter) (p: Packed) =
  let codes = p.OprCodes |> Array.map (fun c -> $"0x{c:X}L")
  let fixedRegs = p.FixedRegs |> Array.map (fun r -> $"Register.{r}")
  w.Write header
  writeLines w "oprCodes" "int64[]" codes
  writeLines w "oprListStart" "int32[]" (p.OprListStart |> Array.map string)
  writeDoc w
    [ "The registers a fixed-register descriptor can name, by the index the"
      "descriptor carries." ]
  writeLines w "fixedRegs" "Register[]" fixedRegs
  writeDoc w
    [ "The fields a register descriptor can be read from, by the index the"
      "descriptor carries." ]
  writeLines w "regFields" "OprRegType[]" regFields
  w.WriteLine rtLine
  w.WriteLine ""
  w.WriteLine "/// Reads one operand descriptor back out of its integer."
  w.Write decodeOprBody
  w.WriteLine ""

/// Writes the rows and what reads them back.
let private writeRows (w: StreamWriter) (p: Packed) opcodeId =
  let rowMain = p.Rows |> List.map (rowMainLit p opcodeId) |> List.toArray
  let rowAttrs = p.Rows |> List.map (rowAttrsLit p) |> List.toArray
  writeLines w "modRMs" "ModRMType[]" (p.ModRMs |> Array.map modRMText)
  writeLines w "prefixTypes" "PrefixType[]" p.Prefixes
  writeLines w "rowMain" "int64[]" rowMain
  writeLines w "rowAttrs" "int32[]" rowAttrs
  writeLines w "slotStart" "int32[]" (p.SlotStart |> Array.map string)
  w.Write decodeRow
  maps |> List.iteri (fun i (_, _, funName) ->
    w.WriteLine $"let ({funName}: InstructionCore[][]) = buildMap {i}")

let private writeTableFile path (opcodeIds: Dictionary<string, int>) rows =
  let packed = pack rows
  use w = new StreamWriter(path, false, UTF8Encoding false)
  w.NewLine <- "\n"
  writeOperands w packed
  writeRows w packed (opcodeIdOf opcodeIds)

[<EntryPoint>]
let main argv =
  if argv.Length <> 2 then
    eprintfn "usage: IntelTableGen <Intel.json> <output directory>"
    1
  else
    let opcodes, rows = readJson argv[0]
    let _, _, _, ids, _ = numberOpcodes opcodes
    let opcodePath = Path.Combine(argv[1], "Opcode.fs")
    writeOpcodeFile opcodePath opcodes
    printfn "wrote %s: %d opcodes" opcodePath ids.Count
    let tablePath = Path.Combine(argv[1], "InstructionArrays.fs")
    writeTableFile tablePath ids rows
    printfn "wrote %s: %d rows" tablePath rows.Length
    0

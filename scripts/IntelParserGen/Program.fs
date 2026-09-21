/// Generates the Intel parser's straight-line opcode code from the rows and
/// chains of B2R2.FrontEnd.Intel.InstructionTable: DLegacy.fs for the four
/// legacy maps and DVex.fs for the eight VEX and EVEX maps. One function per
/// (map, opcode byte) slot; inside it a switch on the ModRM.reg digit where
/// the slot needs one, a switch on the REX and mandatory-prefix state, and
/// the row's operands read with every width folded to a constant.
module IntelParserGen

open System
open System.IO
open System.Text
open System.Collections.Generic
open B2R2
open B2R2.FrontEnd.Intel

/// Splits a line at the spaces that sit outside parentheses, keeping each
/// piece within the width; a piece that still does not fit is left as it is.
let private splitOutsideParens (width: int) (indent: string) (s: string) =
  let mutable depth = 0
  let breaks = ResizeArray<int>()
  for i in 0 .. s.Length - 1 do
    match s[i] with
    | '(' | '[' -> depth <- depth + 1
    | ')' | ']' -> depth <- depth - 1
    | ' ' when depth = 0 -> breaks.Add i
    | _ -> ()
  breaks.Add s.Length
  let pieces = ResizeArray<string>()
  let mutable start = 0
  let mutable lineStart = 0
  let mutable limit = width
  for b in breaks do
    if b - lineStart > limit && start > lineStart then
      pieces.Add(s.Substring(lineStart, start - lineStart))
      lineStart <- start
      limit <- width - indent.Length - 2
    start <- b + 1
  pieces.Add(s.Substring lineStart)
  if pieces.Count <= 1 then
    [ s.TrimEnd() ]
  else
    (* Every argument on a line of its own, so that the line breaks are
       consistent: the first token is the function, the rest its arguments. *)
    let tokens = ResizeArray<string>()
    let mutable last = 0
    for b in breaks do
      if b > last then tokens.Add(s.Substring(last, b - last).Trim())
      last <- b + 1
    tokens
    |> Seq.filter (fun t -> t <> "")
    |> Seq.mapi (fun i t -> if i = 0 then indent + t else indent + "  " + t)
    |> List.ofSeq

/// Folds a generated line to the 80-column width the repository keeps: a
/// context case splits its alternatives, a condition breaks before each &&,
/// and a call or binding continues on lines indented two more.
let private fold (line: string) =
  if line.Length <= 80 then [ line ]
  else
    let indent = line.Substring(0, line.Length - line.TrimStart().Length)
    let body = line.TrimStart()
    if body.StartsWith "| " && body.EndsWith " ->" then
      let alts = body.Substring(2, body.Length - 5).Split(" | ")
      let lines = ResizeArray<string>()
      let cur = StringBuilder(indent + "| " + alts[0])
      for a in alts |> Array.skip 1 do
        if cur.Length + 3 + a.Length > 77 then
          lines.Add(cur.ToString())
          cur.Clear().Append(indent + "| " + a) |> ignore
        else cur.Append(" | " + a) |> ignore
      lines.Add(cur.ToString() + " ->")
      List.ofSeq lines
    elif (body.StartsWith "if " || body.StartsWith "elif ")
         && body.EndsWith " then" && body.Contains " && " then
      let kw = if body.StartsWith "if " then "if " else "elif "
      let cond = body.Substring(kw.Length, body.Length - kw.Length - 5)
      let parts = ResizeArray<string>()
      let mutable depth = 0
      let mutable start = 0
      for i in 0 .. cond.Length - 1 do
        match cond[i] with
        | '(' -> depth <- depth + 1
        | ')' -> depth <- depth - 1
        | '&' when depth = 0 && i + 1 < cond.Length && cond[i + 1] = '&'
                   && i > 0 && cond[i - 1] = ' ' ->
          parts.Add(cond.Substring(start, i - 1 - start))
          start <- i + 3
        | _ -> ()
      parts.Add(cond.Substring start)
      let parts = parts.ToArray()
      let pad = String(' ', indent.Length + kw.Length)
      [ for i in 0 .. parts.Length - 1 do
          let prefix = if i = 0 then indent + kw else pad
          let suffix = if i = parts.Length - 1 then " then" else " &&"
          yield prefix + parts[i] + suffix ]
      |> List.collect (fun l ->
        if l.Length <= 80 then [ l ] else splitOutsideParens 80 pad l)
    elif body.StartsWith "let " && body.Contains " = " then
      let eq = line.IndexOf " = "
      let head = line.Substring(0, eq + 2)
      let rest = line.Substring(eq + 3)
      let pad = indent + "  "
      if rest.StartsWith "(if " && rest.EndsWith ")" then
        let inner = rest.Substring(1, rest.Length - 2)
        let thenAt = inner.IndexOf " then "
        let elseAt = inner.LastIndexOf " else "
        let c = inner.Substring(3, thenAt - 3)
        let a = inner.Substring(thenAt + 6, elseAt - thenAt - 6)
        let b = inner.Substring(elseAt + 6)
        [ head; pad + "if " + c + " then"; pad + "  " + a; pad + "else"
          pad + "  " + b ]
        |> List.collect (fun l ->
          if l.Length <= 80 then [ l ] else splitOutsideParens 80 pad l)
      else
        let restLine = pad + rest
        head :: (if restLine.Length <= 80 then [ restLine ]
                 else splitOutsideParens 80 pad restLine)
    else
      splitOutsideParens 80 indent line

type private Emitter(vex: bool) =
  let sb = StringBuilder()

  member _.Vex = vex

  member _.Line(s: string) =
    for l in fold s do sb.Append(l).Append('\n') |> ignore

  member _.Text = sb.ToString()

let private rows (head: Row) =
  let acc = ResizeArray<Row>()
  let mutable r = head
  while not (isNull (box r)) do
    acc.Add r
    r <- r.Next
  acc

/// A row's identity across its chain copies: the copies share one OprSpecs
/// array, which no other row does.
let private ident (r: Row) =
  System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode r.OprSpecs

let private rt (sz: RegType) = sprintf "%d<rt>" (int sz)

let private opc (o: Opcode) = sprintf "Opcode.%s" (o.ToString())

let private pfx (p: Prefix) =
  if p = Prefix.None then "Prefix.None"
  else
    let names =
      [ Prefix.OPSIZE; Prefix.REPZ; Prefix.REPNZ; Prefix.LOCK; Prefix.ADDRSIZE ]
      |> List.filter (fun f -> p &&& f = f)
      |> List.map (fun f -> "Prefix." + f.ToString())
    if names.Length = 1 then names.Head
    else "(" + String.Join(" ||| ", names) + ")"

let private szc (c: SzCond) = sprintf "SzCond.%s" (c.ToString())

let private tt (t: TupleType) = sprintf "TupleType.%s" (t.ToString())

let private regv (v: int) = sprintf "(regv %d)" v

let private rcDecor (r: Row) =
  match r.RCDecor with
  | NoRounding -> "NoRounding"
  | StaticRounding -> "StaticRounding"
  | SuppressAllExceptions -> "SuppressAllExceptions"

let private vlOf (r: Row) =
  match r.VectorLength with
  | VectorLength.V128 -> Some 128
  | VectorLength.V256 -> Some 256
  | VectorLength.V512 -> Some 512
  | _ -> None

/// The condition the ModRM byte has to satisfy beyond the digit switch.
let private modRMCond (r: Row) hasDigitSwitch =
  let wd = r.MatchWord
  if wd &&& MatchWord.Any <> 0UL then []
  else
    let mask = int (wd &&& 0xFFUL)
    let value = int ((wd >>> 8) &&& 0xFFUL)
    let mask = if hasDigitSwitch then mask &&& 0xC7 else mask
    let notReg = wd &&& MatchWord.NotReg <> 0UL
    [ if mask <> 0 then
        if mask = 0xC0 && value &&& 0xC0 = 0xC0 then yield "isReg m"
        else yield sprintf "(m &&& 0x%02Xuy) = 0x%02Xuy" mask (value &&& mask)
      if notReg then yield "isMem m" ]

let private e3Cond (r: Row) =
  match r.Opcode.ToString() with
  | "JCXZ" -> [ "st.AddrSz = 16<rt>" ]
  | "JECXZ" -> [ "st.AddrSz = 32<rt>" ]
  | "JRCXZ" -> [ "st.AddrSz = 64<rt>" ]
  | o -> failwithf "unexpected E3 opcode %s" o

/// The vector-length constraint, as Parser.matchVectorLength reads it: with
/// EVEX.b on a register form in a slot that offers a rounding decoration,
/// L'L is spent on the rounding mode and only a row offering one answers.
let private vlCond (r: Row) =
  let plain =
    match vlOf r with
    | Some vl -> Some (sprintf "st.VL = %d<rt>" vl)
    | None -> None
  if r.SlotDeclaresRC then
    let rc = if r.RCDecor <> NoRounding then "true" else "false"
    let vl = defaultArg (vlOf r) 0
    if vl = 0 && rc = "true" then []
    else [ sprintf "vlOk &st m %s %d<rt>" rc vl ]
  else
    Option.toList plain

/// The opmask constraints, as Parser.matchGatherMask, matchZeroing and
/// matchMaskableDest read them, with the row's facts folded in.
let private maskConds (r: Row) =
  [ if r.UsesVSIB then yield "not (st.IsEVEX && st.AAA = 0)"
    if r.UsesVSIB || r.DestIsMaskReg then
      yield "not (st.IsEVEX && st.Zeroing)"
    elif r.HasMemoryDest then
      yield "not (st.IsEVEX && st.Zeroing && isMem m)"
    if not r.DestRegCanBeMasked then
      if r.HasMemoryDest then
        yield "(not (st.IsEVEX && st.AAA <> 0) || isMem m)"
      else
        yield "not (st.IsEVEX && st.AAA <> 0)" ]

/// The whole condition of a row, given the digit was switched on already.
let private rowCond (em: Emitter) (r: Row) hasDigitSwitch =
  let conds =
    modRMCond r hasDigitSwitch
    @ (if r.IsE3 then e3Cond r else [])
    @ (if r.IsPlainNop then [ "not (REXPrefix.hasB st.REX)" ] else [])
    @ (if em.Vex then
         (if r.Requires66h then
            [ "(Prefix.hasOprSz st.Pref && not (REXPrefix.hasW st.REX))" ]
          else [])
         @ vlCond r
         @ maskConds r
       else [])
    @ (if r.LockableDest then [ "(st.NoLock || isMem m)" ] else [ "st.NoLock" ])
  String.Join(" && ", conds)

type private Opr =
  { Expr: string
    IsRegStatic: bool
    NotReg: bool
    /// For a register-or-memory operand: its register width and memory width.
    RM: (RegType * RegType) option
    /// The broadcast element width the memory form declares, or 0<rt>.
    Bcst: RegType }

/// The expression reading one operand, as Parser.parseOperand reads it, with
/// the row's constants folded in.
let private operand (em: Emitter) (r: Row) (o: OprSpec) =
  let mk e = { Expr = e; IsRegStatic = false; NotReg = false; RM = None; Bcst = 0<rt> }
  let reg e = { mk e with IsRegStatic = true }
  let nonReg e = { mk e with NotReg = true }
  let rmk e rsz msz bcst = { mk e with RM = Some (rsz, msz); Bcst = bcst }
  let t = tt r.TupleType
  let memOf sz bcst =
    if em.Vex then sprintf "memV span &st m %s %s %s" (rt sz) t (rt bcst)
    else sprintf "mem span &st m %s" (rt sz)
  let rmOf rsz msz bcst =
    if em.Vex then
      sprintf "rmOprV span &st m %s %s %s %s" (rt rsz) (rt msz) t (rt bcst)
    elif rsz = msz then sprintf "rmOpr span &st m %s" (rt rsz)
    else
      sprintf "(if isReg m then Operands.oprReg (rmReg &st m %s) else mem span &st m %s)"
        (rt rsz) (rt msz)
  let regReg sz = if em.Vex then sprintf "regRegV &st m %s" (rt sz) else sprintf "regReg &st m %s" (rt sz)
  let rmReg sz = if em.Vex then sprintf "rmRegV &st m %s" (rt sz) else sprintf "rmReg &st m %s" (rt sz)
  match o.Kind with
  | OprKind.RM -> rmk (rmOf o.Size o.Size 0<rt>) o.Size o.Size 0<rt>
  | OprKind.RMTwoWidths -> rmk (rmOf o.Size o.MemSize 0<rt>) o.Size o.MemSize 0<rt>
  | OprKind.RMBroadcast ->
    rmk (rmOf o.Size o.MemSize o.BcstSize) o.Size o.MemSize o.BcstSize
  | OprKind.MemVSIB -> nonReg (sprintf "memVSIB span &st m %s %s" (rt o.Size) t)
  | OprKind.Reg ->
    match o.Field with
    | OprRegType.RegBit -> reg (regReg o.Size)
    | OprRegType.RMBit -> reg (rmReg o.Size)
    | OprRegType.OpRd -> reg (sprintf "opReg &st %d %s" (int r.OpcodeByte &&& 7) (rt o.Size))
    | OprRegType.VVVV -> reg (sprintf "vvvvReg &st %s" (rt o.Size))
    | OprRegType.IS4 -> reg (sprintf "is4Reg span &st %s" (rt o.Size))
    | f -> failwithf "unsupported reg field %A in row %A" f r.Opcode
  | OprKind.Mem -> nonReg (memOf o.Size 0<rt>)
  | OprKind.MemFromPrefixes ->
    if em.Vex then
      nonReg (sprintf "memV span &st m (effOprSz &st %s) %s 0<rt>" (szc r.SzCond) t)
    else nonReg (sprintf "mem span &st m (effOprSz &st %s)" (szc r.SzCond))
  | OprKind.Imm ->
    if r.SignExtendsImm then nonReg (sprintf "simm span &st %s" (rt o.Size))
    else nonReg (sprintf "uimm span &st %s" (rt o.Size))
  | OprKind.Rel -> nonReg (sprintf "rel span &st %s" (rt o.Size))
  | OprKind.FixedReg | OprKind.FixedRegModeWidth -> reg (regv o.Value)
  | OprKind.STRegRM -> reg "RegisterHelper.streg (rm m)"
  | OprKind.STRegFixed -> reg (regv o.Value)
  | OprKind.BM ->
    mk (sprintf "(if isReg m then OperandParsers.parseBoundRegister (rm m) else %s)"
          (memOf o.Size 0<rt>))
  | OprKind.BndReg -> mk "OperandParsers.parseBoundRegister (reg m)"
  | OprKind.OpMaskReg ->
    let idx, isRegField =
      match o.Field with
      | OprRegType.RegBit -> "reg m", "true"
      | OprRegType.RMBit -> "rm m", "false"
      | OprRegType.VVVV -> "st.VVVV", "false"
      | f -> failwithf "unsupported opmask field %A" f
    mk (sprintf "opmaskReg &st (%s) %s" idx isRegField)
  | OprKind.KM ->
    mk (sprintf "(if isReg m then OperandParsers.parseOpMaskReg (rm m) else %s)"
          (memOf o.Size 0<rt>))
  | OprKind.MMXReg ->
    match o.Field with
    | OprRegType.RegBit -> mk "OperandParsers.parseMMXReg (reg m)"
    | OprRegType.RMBit -> mk "OperandParsers.parseMMXReg (rm m)"
    | OprRegType.VVVV -> mk "OperandParsers.parseMMXReg st.VVVV"
    | f -> failwithf "unsupported mmx field %A" f
  | OprKind.MM ->
    mk (sprintf "(if isReg m then OperandParsers.parseMMXReg (rm m) else %s)"
          (memOf o.Size 0<rt>))
  | OprKind.FixedImm ->
    nonReg (sprintf "Operands.oprImm %dL %s" o.Value (rt r.FixedImmSize))
  | OprKind.Moffs -> nonReg (sprintf "moffs span &st %s" (rt o.Size))
  | OprKind.CtrlReg ->
    mk "OperandParsers.parseControlReg (OperandParsers.sysRegIndex m st.REX)"
  | OprKind.DebugReg ->
    mk "OperandParsers.parseDebugReg (OperandParsers.sysRegIndex m st.REX)"
  | OprKind.RegAddr ->
    if r.IsGroupExtension then reg (rmReg 0<rt> |> fun _ -> "rmReg &st m st.AddrSz")
    else reg "regReg &st m st.AddrSz"
  | OprKind.Sreg -> mk "OperandParsers.parseSegReg (reg m)"
  | OprKind.Far ->
    (* m16:16, m16:32 or m16:64: the memory operand is the whole pointer, the
       selector included, as Parser.parseFarOperand sizes it. *)
    if r.HasModRM then nonReg (memOf (o.Size + 16<rt>) 0<rt>)
    else nonReg (sprintf "farPtr span &st %s" (rt o.Size))
  | k -> failwithf "unsupported operand kind %A in row %A" k r.Opcode

let private opSize (r: Row) =
  match r.OpWidthKind with
  | OpWidthKind.Fixed -> rt r.OpWidth
  | OpWidthKind.ByModRMForm ->
    sprintf "(if isReg m then %s else %s)" (rt r.OpWidth) (rt r.OpWidthMem)
  | OpWidthKind.FixedRegister ->
    sprintf "regTypeOf &st %s" (regv (int r.OpWidthReg))
  | OpWidthKind.EffectiveAddress -> "st.AddrSz"
  | _ -> sprintf "effOprSz &st %s" (szc r.EffSzCond)

/// The call that makes the instruction, for the given operands expression.
/// Under VEX the broadcast width goes with it: only a memory form of an
/// RMBroadcast operand declares one.
let private finishCall (em: Emitter) (r: Row) (oprs: string) (bcstExpr: string) =
  ignore em
  if em.Vex then
    let regForm = if r.HasModRM then "isReg m" else "false"
    sprintf "finishV &st %s (%s) (%s) %s %s (%s)"
      (opc r.Opcode) oprs (opSize r) bcstExpr (rcDecor r) regForm
  else
    let isFar =
      if r.IsFarRet
         || (r.OprSpecs |> Array.exists (fun o -> o.Kind = OprKind.Far)) then
        "true"
      else "false"
    let selector =
      if r.IsNopOrPause then
        sprintf "(if Prefix.hasREPZ st.Pref then Prefix.REPZ else %s)"
          (pfx r.SelectorPrefixes)
      else pfx r.SelectorPrefixes
    sprintf "finish &st %s (%s) (%s) %s %s" (opc r.Opcode) oprs (opSize r) isFar selector

/// Adds the finishing call; where it would not fit the width, the operands
/// and the broadcast width are bound to names first.
let private addFinish (em: Emitter) (add: string -> unit) (ind: string) (r: Row)
                      (oprs: string) (bcst: string) =
  let call = finishCall em r oprs bcst
  if ind.Length + call.Length <= 80 then add call
  else
    let oprs =
      if oprs.Contains " " then
        add (sprintf "let oprs = %s" oprs)
        "oprs"
      else oprs
    let bcst =
      if bcst.Contains " " then
        add (sprintf "let bcst = %s" bcst)
        "bcst"
      else bcst
    add (finishCall em r oprs bcst)

/// Binds an operand to a name; a register is wrapped into its operand value
/// at the binding, so that the finishing call names it plainly.
let private bindOpr (add: string -> unit) (o: Opr) (name: string) =
  if o.IsRegStatic then
    add (sprintf "let %s = Operands.oprReg (%s)" name o.Expr)
  else add (sprintf "let %s = %s" name o.Expr)

/// The body reading a row's operands and finishing the instruction.
let private body (em: Emitter) (ind: string) (r: Row) =
  let lines = ResizeArray<string>()
  let add (s: string) = lines.Add(ind + s)
  if r.HasModRM then add "st.Pos <- st.Pos + 1"
  let ops = r.OprSpecs |> Array.truncate r.OperandCount |> Array.map (operand em r)
  let bcstOf (o: Opr) =
    if o.Bcst <> 0<rt> then sprintf "(if isMem m then %s else 0<rt>)" (rt o.Bcst)
    else "0<rt>"
  let bcst =
    match ops |> Array.tryFind (fun o -> o.Bcst <> 0<rt>) with
    | Some o -> bcstOf o
    | None -> "0<rt>"
  if r.OperandCount = 0 then
    if em.Vex then
      addFinish em add ind r "NoOperand" "0<rt>"
    else
      let opsz =
        if r.IsByteString then "8<rt>"
        else sprintf "effOprSz &st %s" (szc r.EffSzCond)
      let isFar = if r.IsFarRet then "true" else "false"
      let selector =
        if r.IsNopOrPause then
          sprintf "(if Prefix.hasREPZ st.Pref then Prefix.REPZ else %s)"
            (pfx r.SelectorPrefixes)
        else pfx r.SelectorPrefixes
      add (sprintf "finish &st %s (NoOperand) (%s) %s %s" (opc r.Opcode) opsz isFar selector)
  else
    match ops with
    | [| a |] ->
      add (sprintf "let o1 = %s" a.Expr)
      let oprs =
        if a.IsRegStatic then "Operands.oneReg o1"
        elif a.NotReg then "OneOperand o1"
        else "Operands.oneOperand o1"
      addFinish em add ind r oprs bcst
    | [| a; b |] when a.RM.IsSome && b.IsRegStatic ->
      let rsz, msz = a.RM.Value
      let rmReg = if em.Vex then "rmRegV" else "rmReg"
      add (sprintf "let o2 = %s" b.Expr)
      add "if isReg m then"
      add (sprintf "  let o1 = %s &st m %s" rmReg (rt rsz))
      addFinish em (fun l -> add ("  " + l)) (ind + "  ") r "Operands.twoRegs o1 o2" "0<rt>"
      add "else"
      let memE =
        if em.Vex then sprintf "memV span &st m %s %s %s" (rt msz) (tt r.TupleType) (rt a.Bcst)
        else sprintf "mem span &st m %s" (rt msz)
      add (sprintf "  let o1 = %s" memE)
      addFinish em (fun l -> add ("  " + l)) (ind + "  ") r "TwoOperands(o1, Operands.oprReg o2)" (if a.Bcst <> 0<rt> then rt a.Bcst else "0<rt>")
    | [| a; b |] when a.IsRegStatic && b.RM.IsSome ->
      let rsz, msz = b.RM.Value
      let rmReg = if em.Vex then "rmRegV" else "rmReg"
      add (sprintf "let o1 = %s" a.Expr)
      add "if isReg m then"
      add (sprintf "  let o2 = %s &st m %s" rmReg (rt rsz))
      addFinish em (fun l -> add ("  " + l)) (ind + "  ") r "Operands.twoRegs o1 o2" "0<rt>"
      add "else"
      let memE =
        if em.Vex then sprintf "memV span &st m %s %s %s" (rt msz) (tt r.TupleType) (rt b.Bcst)
        else sprintf "mem span &st m %s" (rt msz)
      add (sprintf "  let o2 = %s" memE)
      addFinish em (fun l -> add ("  " + l)) (ind + "  ") r "TwoOperands(Operands.oprReg o1, o2)" (if b.Bcst <> 0<rt> then rt b.Bcst else "0<rt>")
    | [| a; b |] when a.IsRegStatic && b.IsRegStatic ->
      add (sprintf "let o1 = %s" a.Expr)
      add (sprintf "let o2 = %s" b.Expr)
      addFinish em add ind r "Operands.twoRegs o1 o2" bcst
    | [| a; b |] ->
      bindOpr add a "o1"
      bindOpr add b "o2"
      let oprs =
        if a.NotReg || b.NotReg then "TwoOperands(o1, o2)"
        else "Operands.twoOperands o1 o2"
      addFinish em add ind r oprs bcst
    | _ ->
      ops |> Array.iteri (fun i o -> bindOpr add o (sprintf "o%d" (i + 1)))
      let es = ops |> Array.mapi (fun i _ -> sprintf "o%d" (i + 1))
      let oprs =
        if ops.Length = 3 then sprintf "ThreeOperands(%s)" (String.Join(", ", es))
        else sprintf "FourOperands(%s)" (String.Join(", ", es))
      addFinish em add ind r oprs bcst
  lines

/// The candidates of one context, tried in order.
let private candidates (em: Emitter) (ind: string) (cands: Row list) hasDigitSwitch =
  let lines = ResizeArray<string>()
  let rec go first = function
    | [] ->
      if not first then lines.Add(ind + "else")
      lines.Add(ind + (if first then "" else "  ") + "raise ParsingFailureException")
    | (r: Row) :: rest ->
      let c = rowCond em r hasDigitSwitch
      let kw = if first then "if" else "elif"
      lines.Add(sprintf "%s%s %s then" ind kw c)
      lines.AddRange(body em (ind + "  ") r)
      go false rest
  go true cands
  lines

let private needsModRM (all: Row seq) =
  all |> Seq.exists (fun r -> r.HasModRM || r.MatchWord &&& MatchWord.Any = 0UL)

/// The code of one digit's chains (32-bit and 64-bit), switching on the
/// context to reach the rows in play. The accept masks number a state
/// (rexState * 2 + vexPresent) * 8 + prefState; the runtime numbers it
/// rexState * 8 + prefState, plus 24 in 64-bit mode.
let private digitBody (em: Emitter) (ind: string) (chain32: ResizeArray<Row>)
                      (chain64: ResizeArray<Row>) hasDigitSwitch =
  let lines = ResizeArray<string>()
  let groups = Dictionary<string, ResizeArray<int> * Row list>()
  let order = ResizeArray<string>()
  let vexBit = if em.Vex then 8 else 0
  for is64 in [ false; true ] do
    let chain = if is64 then chain64 else chain32
    for c in 0 .. 23 do
      let bit = 1UL <<< ((c / 8) * 16 + vexBit + (c % 8))
      let cands = chain |> Seq.filter (fun r -> r.Accept &&& bit <> 0UL) |> List.ofSeq
      if not cands.IsEmpty then
        let key = String.Join(",", cands |> List.map (fun r -> string (ident r)))
        let ctx = if is64 then c + 24 else c
        match groups.TryGetValue key with
        | true, (cs, _) -> cs.Add ctx
        | _ ->
          groups[key] <- (ResizeArray [ ctx ], cands)
          order.Add key
  if order.Count = 0 then
    lines.Add(ind + "raise ParsingFailureException")
  else
    lines.Add(ind + "match st.Ctx with")
    for key in order do
      let cs, cands = groups[key]
      lines.Add(sprintf "%s| %s ->" ind (String.Join(" | ", cs)))
      lines.AddRange(candidates em (ind + "  ") cands hasDigitSwitch)
    lines.Add(ind + "| _ ->")
    lines.Add(ind + "  raise ParsingFailureException")
  lines

let private slot (em: Emitter) (name: string) (heads32: Row[]) (heads64: Row[]) (map: int) (b: int) =
  let h32 = Array.init 8 (fun d -> heads32[(map <<< 11) ||| (b <<< 3) ||| d])
  let h64 = Array.init 8 (fun d -> heads64[(map <<< 11) ||| (b <<< 3) ||| d])
  if h64 |> Array.forall (fun h -> isNull (box h)) then None
  else
    let sameHead = h64 |> Array.forall (fun h -> obj.ReferenceEquals(h, h64[0]))
    let chains32 = h32 |> Array.map rows
    let chains64 = h64 |> Array.map rows
    let all = Seq.append (Seq.concat chains32) (Seq.concat chains64)
    let needsM = (not sameHead) || needsModRM all
    em.Line(sprintf "let private %s (span: ByteSpan) (st: byref<DState>) =" name)
    if needsM then em.Line "  let m = peek span &st"
    if sameHead then
      for l in digitBody em "  " chains32[0] chains64[0] false do em.Line l
    else
      em.Line "  match reg m with"
      for d in 0 .. 7 do
        if not (isNull (box h64[d])) then
          em.Line(sprintf "  | %d ->" d)
          for l in digitBody em "    " chains32[d] chains64[d] true do em.Line l
      em.Line "  | _ ->"
      em.Line "    raise ParsingFailureException"
    em.Line ""
    Some name

let private header (em: Emitter) (moduleName: string) (what: string) =
  em.Line(sprintf "/// The Intel %s as straight-line code, one function per" what)
  em.Line "/// opcode byte, generated by IntelParserGen from InstructionTable. Do not"
  em.Line "/// edit."
  em.Line(sprintf "module internal B2R2.FrontEnd.Intel.%s" moduleName)
  em.Line ""
  em.Line "open B2R2"
  em.Line "open B2R2.FrontEnd.BinLifter"
  em.Line "open B2R2.FrontEnd.Intel"
  em.Line "open B2R2.FrontEnd.Intel.DOps"
  em.Line "open type B2R2.FrontEnd.Intel.Operand"
  em.Line "open type B2R2.FrontEnd.Intel.Operands"
  em.Line ""

/// Emits the maps whose heads sit end to end in heads32/heads64, 2048 per map.
let private emitMaps (em: Emitter) prefix (heads32: Row[]) (heads64: Row[]) =
  let mapCount = heads64.Length / 2048
  let names = Array.init mapCount (fun _ -> Array.create 256 None)
  for map in 0 .. mapCount - 1 do
    for b in 0 .. 255 do
      names[map][b] <- slot em (sprintf "%s%dx%02x" prefix map b) heads32 heads64 map b
  for map in 0 .. mapCount - 1 do
    em.Line(sprintf "let private map%d (span: ByteSpan) (st: byref<DState>) (b: int) =" map)
    em.Line "  match b with"
    for b in 0 .. 255 do
      match names[map][b] with
      | Some n -> em.Line(sprintf "  | 0x%02X -> %s span &st" b n)
      | None -> ()
    em.Line "  | _ -> raise ParsingFailureException"
    em.Line ""
  em.Line "/// Parses the instruction whose opcode byte is b in the given map."
  em.Line "let parse (span: ByteSpan) (st: byref<DState>) (map: int) (b: int) ="
  em.Line "  match map with"
  for map in 0 .. mapCount - 2 do
    em.Line(sprintf "  | %d -> map%d span &st b" map map)
  em.Line(sprintf "  | _ -> map%d span &st b" (mapCount - 1))
  names |> Array.sumBy (fun a -> a |> Array.filter Option.isSome |> Array.length)

let private write (path: string) (em: Emitter) slots =
  File.WriteAllText(path, em.Text)
  printfn "wrote %s: %d slots, %d lines" path slots (em.Text.Split('\n').Length)

[<EntryPoint>]
let main argv =
  let outDir = argv[0]
  let legacy = Emitter false
  header legacy "DLegacy" "legacy opcode maps"
  let n = emitMaps legacy "m" InstructionTable.legacy32.Value InstructionTable.legacy64.Value
  write (Path.Combine(outDir, "DLegacy.fs")) legacy n
  let vex = Emitter true
  header vex "DVex" "VEX and EVEX opcode maps"
  let heads is64 =
    let maps = if is64 then InstructionTable.vex64 else InstructionTable.vex32
    maps |> Array.collect (fun (m: Lazy<Row[]>) -> m.Value)
  let n = emitMaps vex "v" (heads false) (heads true)
  write (Path.Combine(outDir, "DVex.fs")) vex n
  0

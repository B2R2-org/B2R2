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

module internal B2R2.Assembly.S390.AsmOpcode

open B2R2.Assembly.S390.AsmField
open B2R2.Assembly.S390.AsmLayout

/// <summary>
/// Represents what the encoder has to know about one instruction: the word its
/// opcode alone makes, how many bytes long it is, where its operands go, and
/// what the four bits from the twentieth on are for.
/// </summary>
type Row =
  { /// The bits the opcode itself sets, already in place.
    Bits: uint64
    /// How many bytes long the instruction is, which is what the distance to a
    /// place named further down a source is counted with.
    Length: int
    /// Where the operands go.
    Layout: Slot list
    /// What the four bits from the twentieth on are for.
    Bits20: Bits20
    /// Whether ESA/390 already had the instruction, which is what says whether
    /// a 32-bit target can be given it.
    Esa390: bool }

/// <summary>
/// Represents what the four bits from the twentieth on are for.
///
/// A handful of instructions are told from another one written almost the same
/// way by nothing more than whether those four bits hold anything, so an
/// encoder that left them at nothing would encode the other instruction.
/// </summary>
and Bits20 =
  /// Nothing in particular: the instruction is not one of those.
  | Bits20Free
  /// They have to hold something, and the instruction does not name them, so
  /// they are set to one.
  | Bits20Filled
  /// They have to hold something, and it is the instruction that says what, so
  /// naming nothing there is refused.
  | Bits20Named
  /// They have to hold nothing, and it is the instruction that says so, so
  /// naming anything there is refused.
  | Bits20Zeroed

/// The instructions that do not name the four bits from the twentieth on but
/// are told from another instruction by whether those bits hold something.
let private filled20 =
  set [ "adtr"
        "axtr"
        "cfdbr"
        "cfebr"
        "cfxbr"
        "cgdbr"
        "cgdtr"
        "cgebr"
        "cgxbr"
        "cgxtr"
        "cu12"
        "cu21"
        "ddtr"
        "dxtr"
        "fidbr"
        "fiebr"
        "fixbr"
        "mdtr"
        "mxtr"
        "sdtr"
        "sxtr" ]

/// The instructions that name those four bits themselves and so may not be
/// written with nothing there.
let private named20 =
  set [ "cdfbra"
        "cdgbra"
        "cdgtra"
        "cefbra"
        "cegbra"
        "csxtr"
        "cxfbra"
        "cxgbra"
        "cxgtra"
        "ldxbra"
        "ledbra"
        "lexbra" ]

/// The instructions that name those four bits themselves and, the other way
/// round, are told from another instruction by their holding nothing.
let private zeroed20 =
  set [ "adtra"
        "axtra"
        "cfdbra"
        "cfebra"
        "cfxbra"
        "cgdbra"
        "cgdtra"
        "cgebra"
        "cgxbra"
        "cgxtra"
        "ddtra"
        "dxtra"
        "fidbra"
        "fiebra"
        "fixbra"
        "mdtra"
        "mxtra"
        "sdtra"
        "sxtra" ]

/// The instructions ESA/390 already had, which are the only ones a 32-bit
/// target can be given. The names are read off the list B2R2's own S390 decoder
/// refuses everything outside of when the target is a 32-bit one.
let private esa390 =
  set [ "a"
        "ad"
        "adb"
        "adbr"
        "adr"
        "ae"
        "aeb"
        "aebr"
        "aer"
        "ah"
        "ahi"
        "al"
        "alc"
        "alcr"
        "alr"
        "ap"
        "ar"
        "au"
        "aur"
        "aw"
        "awr"
        "axbr"
        "axr"
        "bakr"
        "bal"
        "balr"
        "bas"
        "basr"
        "bassm"
        "bc"
        "bcr"
        "bct"
        "bctr"
        "bras"
        "brasl"
        "brc"
        "brcl"
        "brct"
        "brxh"
        "brxle"
        "bsa"
        "bsg"
        "bsm"
        "bxh"
        "bxle"
        "c"
        "cd"
        "cdb"
        "cdbr"
        "cdfbr"
        "cdfr"
        "cdr"
        "cds"
        "ce"
        "ceb"
        "cebr"
        "cefbr"
        "cefr"
        "cer"
        "cfc"
        "cfdbr"
        "cfdr"
        "cfebr"
        "cfer"
        "cfxbr"
        "cfxr"
        "ch"
        "chi"
        "cksm"
        "cl"
        "clc"
        "clcl"
        "clcle"
        "clclu"
        "cli"
        "clm"
        "clr"
        "clst"
        "cmpsc"
        "cp"
        "cpya"
        "cr"
        "cs"
        "csch"
        "csp"
        "cuse"
        "cutfu"
        "cuutf"
        "cvb"
        "cvd"
        "cxbr"
        "cxfbr"
        "cxfr"
        "cxr"
        "d"
        "dd"
        "ddb"
        "ddbr"
        "ddr"
        "de"
        "deb"
        "debr"
        "der"
        "didbr"
        "diebr"
        "dl"
        "dlr"
        "dp"
        "dr"
        "dxbr"
        "dxr"
        "ear"
        "ed"
        "edmk"
        "efpc"
        "epar"
        "epsw"
        "ereg"
        "esar"
        "esta"
        "ex"
        "fidbr"
        "fidr"
        "fiebr"
        "fier"
        "fixbr"
        "fixr"
        "hdr"
        "her"
        "hsch"
        "iac"
        "ic"
        "icm"
        "ipk"
        "ipm"
        "ipte"
        "iske"
        "ivsk"
        "kdb"
        "kdbr"
        "keb"
        "kebr"
        "kxbr"
        "l"
        "la"
        "lae"
        "lam"
        "larl"
        "lasp"
        "lcdbr"
        "lcdr"
        "lcebr"
        "lcer"
        "lcr"
        "lctl"
        "lcxbr"
        "lcxr"
        "ld"
        "lde"
        "ldeb"
        "ldebr"
        "lder"
        "ldr"
        "ldxbr"
        "ldxr"
        "le"
        "ledbr"
        "ledr"
        "ler"
        "lexbr"
        "lexr"
        "lfpc"
        "lh"
        "lhi"
        "lm"
        "lndbr"
        "lndr"
        "lnebr"
        "lner"
        "lnr"
        "lnxbr"
        "lnxr"
        "lpdbr"
        "lpdr"
        "lpebr"
        "lper"
        "lpr"
        "lpsw"
        "lpxbr"
        "lpxr"
        "lr"
        "lra"
        "lrv"
        "lrvh"
        "lrvr"
        "ltdbr"
        "ltdr"
        "ltebr"
        "lter"
        "ltr"
        "ltxbr"
        "ltxr"
        "lura"
        "lxd"
        "lxdb"
        "lxdbr"
        "lxdr"
        "lxe"
        "lxeb"
        "lxebr"
        "lxer"
        "lxr"
        "lzdr"
        "lzer"
        "lzxr"
        "m"
        "madb"
        "madbr"
        "maeb"
        "maebr"
        "mc"
        "md"
        "mdb"
        "mdbr"
        "mde"
        "mdeb"
        "mdebr"
        "mder"
        "mdr"
        "mee"
        "meeb"
        "meebr"
        "meer"
        "mh"
        "mhi"
        "ml"
        "mlr"
        "mp"
        "mr"
        "ms"
        "msch"
        "msdb"
        "msdbr"
        "mseb"
        "msebr"
        "msr"
        "msta"
        "mvc"
        "mvcdk"
        "mvcin"
        "mvck"
        "mvcl"
        "mvcle"
        "mvclu"
        "mvcp"
        "mvcs"
        "mvcsk"
        "mvi"
        "mvn"
        "mvo"
        "mvpg"
        "mvst"
        "mvz"
        "mxbr"
        "mxd"
        "mxdb"
        "mxdbr"
        "mxdr"
        "mxr"
        "n"
        "nc"
        "ni"
        "nr"
        "o"
        "oc"
        "oi"
        "or"
        "pack"
        "palb"
        "pc"
        "pgin"
        "pgout"
        "pka"
        "pku"
        "plo"
        "pr"
        "pt"
        "ptlb"
        "rchp"
        "rll"
        "rp"
        "rrbe"
        "rsch"
        "s"
        "sac"
        "sacf"
        "sal"
        "sam24"
        "sam31"
        "sar"
        "schm"
        "sck"
        "sckc"
        "sckpf"
        "sd"
        "sdb"
        "sdbr"
        "sdr"
        "se"
        "seb"
        "sebr"
        "ser"
        "sfpc"
        "sh"
        "sigp"
        "sl"
        "sla"
        "slb"
        "slbr"
        "slda"
        "sldl"
        "sll"
        "slr"
        "sp"
        "spka"
        "spm"
        "spt"
        "spx"
        "sqd"
        "sqdb"
        "sqdbr"
        "sqdr"
        "sqe"
        "sqeb"
        "sqebr"
        "sqer"
        "sqxbr"
        "sqxr"
        "sr"
        "sra"
        "srda"
        "srdl"
        "srl"
        "srnm"
        "srp"
        "srst"
        "ssar"
        "ssch"
        "sske"
        "ssm"
        "st"
        "stam"
        "stap"
        "stc"
        "stck"
        "stckc"
        "stcke"
        "stcm"
        "stcps"
        "stcrw"
        "stctl"
        "std"
        "ste"
        "stfl"
        "stfpc"
        "sth"
        "stidp"
        "stm"
        "stnsm"
        "stosm"
        "stpt"
        "stpx"
        "strv"
        "strvh"
        "stsch"
        "stsi"
        "stura"
        "su"
        "sur"
        "svc"
        "sw"
        "swr"
        "sxbr"
        "sxr"
        "tam"
        "tar"
        "tb"
        "tbdr"
        "tbedr"
        "tcdb"
        "tceb"
        "tcxb"
        "thder"
        "thdr"
        "tm"
        "tmlh"
        "tmll"
        "tp"
        "tpi"
        "tprot"
        "tr"
        "trace"
        "trap2"
        "trap4"
        "tre"
        "troo"
        "trot"
        "trt"
        "trto"
        "trtt"
        "ts"
        "tsch"
        "unpk"
        "unpka"
        "unpku"
        "upt"
        "x"
        "xc"
        "xi"
        "xr"
        "xsch"
        "zap" ]

/// What the four bits from the twentieth on are for, in the instruction of the
/// given name.
let private bits20Of name =
  if Set.contains name filled20 then Bits20Filled
  elif Set.contains name named20 then Bits20Named
  elif Set.contains name zeroed20 then Bits20Zeroed
  else Bits20Free

/// <summary>
/// Every instruction B2R2's own S390 decoder decodes, as the name it is written
/// under, the word its opcode alone makes, how many bytes long it is, and where
/// its operands go.
///
/// The rows are read off the decoder's own tables and kept in the order those
/// tables keep them, so that an instruction the decoder learns to read is one
/// the assembler learns to write.
/// </summary>
let private rows =
  [ "pr", 0x000000000101UL, 2, noOperand
    "upt", 0x000000000102UL, 2, noOperand
    "ptff", 0x000000000104UL, 2, noOperand
    "sckpf", 0x000000000107UL, 2, noOperand
    "pfpo", 0x00000000010AUL, 2, noOperand
    "tam", 0x00000000010BUL, 2, noOperand
    "sam24", 0x00000000010CUL, 2, noOperand
    "sam31", 0x00000000010DUL, 2, noOperand
    "sam64", 0x00000000010EUL, 2, noOperand
    "trap2", 0x0000000001FFUL, 2, noOperand
    "svc", 0x000000000A00UL, 2, uImm8to15
    "spm", 0x000000000400UL, 2, gr8to11
    "balr", 0x000000000500UL, 2, gr8GR12
    "bctr", 0x000000000600UL, 2, gr8GR12
    "bcr", 0x000000000700UL, 2, mgr8GR12
    "bsm", 0x000000000B00UL, 2, gr8GR12
    "bassm", 0x000000000C00UL, 2, gr8GR12
    "basr", 0x000000000D00UL, 2, gr8GR12
    "mvcl", 0x000000000E00UL, 2, gr8GR12
    "clcl", 0x000000000F00UL, 2, gr8GR12
    "lpr", 0x000000001000UL, 2, gr8GR12
    "lnr", 0x000000001100UL, 2, gr8GR12
    "ltr", 0x000000001200UL, 2, gr8GR12
    "lcr", 0x000000001300UL, 2, gr8GR12
    "nr", 0x000000001400UL, 2, gr8GR12
    "clr", 0x000000001500UL, 2, gr8GR12
    "or", 0x000000001600UL, 2, gr8GR12
    "xr", 0x000000001700UL, 2, gr8GR12
    "lr", 0x000000001800UL, 2, gr8GR12
    "cr", 0x000000001900UL, 2, gr8GR12
    "ar", 0x000000001A00UL, 2, gr8GR12
    "sr", 0x000000001B00UL, 2, gr8GR12
    "mr", 0x000000001C00UL, 2, gr8GR12
    "dr", 0x000000001D00UL, 2, gr8GR12
    "alr", 0x000000001E00UL, 2, gr8GR12
    "slr", 0x000000001F00UL, 2, gr8GR12
    "lpdr", 0x000000002000UL, 2, fpr8FPR12
    "lndr", 0x000000002100UL, 2, fpr8FPR12
    "ltdr", 0x000000002200UL, 2, fpr8FPR12
    "lcdr", 0x000000002300UL, 2, fpr8FPR12
    "hdr", 0x000000002400UL, 2, fpr8FPR12
    "ldxr", 0x000000002500UL, 2, fpr8FPR12
    "mxr", 0x000000002600UL, 2, fpr8FPR12
    "mxdr", 0x000000002700UL, 2, fpr8FPR12
    "ldr", 0x000000002800UL, 2, fpr8FPR12
    "cdr", 0x000000002900UL, 2, fpr8FPR12
    "adr", 0x000000002A00UL, 2, fpr8FPR12
    "sdr", 0x000000002B00UL, 2, fpr8FPR12
    "mdr", 0x000000002C00UL, 2, fpr8FPR12
    "ddr", 0x000000002D00UL, 2, fpr8FPR12
    "awr", 0x000000002E00UL, 2, fpr8FPR12
    "swr", 0x000000002F00UL, 2, fpr8FPR12
    "lper", 0x000000003000UL, 2, fpr8FPR12
    "lner", 0x000000003100UL, 2, fpr8FPR12
    "lter", 0x000000003200UL, 2, fpr8FPR12
    "lcer", 0x000000003300UL, 2, fpr8FPR12
    "her", 0x000000003400UL, 2, fpr8FPR12
    "ledr", 0x000000003500UL, 2, fpr8FPR12
    "axr", 0x000000003600UL, 2, fpr8FPR12
    "sxr", 0x000000003700UL, 2, fpr8FPR12
    "ler", 0x000000003800UL, 2, fpr8FPR12
    "cer", 0x000000003900UL, 2, fpr8FPR12
    "aer", 0x000000003A00UL, 2, fpr8FPR12
    "ser", 0x000000003B00UL, 2, fpr8FPR12
    "mder", 0x000000003C00UL, 2, fpr8FPR12
    "der", 0x000000003D00UL, 2, fpr8FPR12
    "aur", 0x000000003E00UL, 2, fpr8FPR12
    "sur", 0x000000003F00UL, 2, fpr8FPR12
    "sth", 0x000040000000UL, 4, gr8WIdx12M16D20
    "la", 0x000041000000UL, 4, gr8WIdx12M16D20
    "stc", 0x000042000000UL, 4, gr8WIdx12M16D20
    "ic", 0x000043000000UL, 4, gr8WIdx12M16D20
    "ex", 0x000044000000UL, 4, gr8WIdx12M16D20
    "bal", 0x000045000000UL, 4, gr8WIdx12M16D20
    "bct", 0x000046000000UL, 4, gr8WIdx12M16D20
    "bc", 0x000047000000UL, 4, mask8WIdx12M16D20
    "lh", 0x000048000000UL, 4, gr8WIdx12M16D20
    "ch", 0x000049000000UL, 4, gr8WIdx12M16D20
    "ah", 0x00004A000000UL, 4, gr8WIdx12M16D20
    "sh", 0x00004B000000UL, 4, gr8WIdx12M16D20
    "mh", 0x00004C000000UL, 4, gr8WIdx12M16D20
    "bas", 0x00004D000000UL, 4, gr8WIdx12M16D20
    "cvd", 0x00004E000000UL, 4, gr8WIdx12M16D20
    "cvb", 0x00004F000000UL, 4, gr8WIdx12M16D20
    "st", 0x000050000000UL, 4, gr8WIdx12M16D20
    "lae", 0x000051000000UL, 4, gr8WIdx12M16D20
    "n", 0x000054000000UL, 4, gr8WIdx12M16D20
    "cl", 0x000055000000UL, 4, gr8WIdx12M16D20
    "o", 0x000056000000UL, 4, gr8WIdx12M16D20
    "x", 0x000057000000UL, 4, gr8WIdx12M16D20
    "l", 0x000058000000UL, 4, gr8WIdx12M16D20
    "c", 0x000059000000UL, 4, gr8WIdx12M16D20
    "a", 0x00005A000000UL, 4, gr8WIdx12M16D20
    "s", 0x00005B000000UL, 4, gr8WIdx12M16D20
    "m", 0x00005C000000UL, 4, gr8WIdx12M16D20
    "d", 0x00005D000000UL, 4, gr8WIdx12M16D20
    "al", 0x00005E000000UL, 4, gr8WIdx12M16D20
    "sl", 0x00005F000000UL, 4, gr8WIdx12M16D20
    "std", 0x000060000000UL, 4, fpr8WIdx12M16D20
    "mxd", 0x000067000000UL, 4, fpr8WIdx12M16D20
    "ld", 0x000068000000UL, 4, fpr8WIdx12M16D20
    "cd", 0x000069000000UL, 4, fpr8WIdx12M16D20
    "ad", 0x00006A000000UL, 4, fpr8WIdx12M16D20
    "sd", 0x00006B000000UL, 4, fpr8WIdx12M16D20
    "md", 0x00006C000000UL, 4, fpr8WIdx12M16D20
    "dd", 0x00006D000000UL, 4, fpr8WIdx12M16D20
    "aw", 0x00006E000000UL, 4, fpr8WIdx12M16D20
    "sw", 0x00006F000000UL, 4, fpr8WIdx12M16D20
    "ste", 0x000070000000UL, 4, fpr8WIdx12M16D20
    "ms", 0x000071000000UL, 4, gr8WIdx12M16D20
    "le", 0x000078000000UL, 4, fpr8WIdx12M16D20
    "ce", 0x000079000000UL, 4, fpr8WIdx12M16D20
    "ae", 0x00007A000000UL, 4, fpr8WIdx12M16D20
    "se", 0x00007B000000UL, 4, fpr8WIdx12M16D20
    "mde", 0x00007C000000UL, 4, fpr8WIdx12M16D20
    "de", 0x00007D000000UL, 4, fpr8WIdx12M16D20
    "au", 0x00007E000000UL, 4, fpr8WIdx12M16D20
    "su", 0x00007F000000UL, 4, fpr8WIdx12M16D20
    "lra", 0x0000B1000000UL, 4, gr8WIdx12M16D20
    "brxh", 0x000084000000UL, 4, gr8SImmRUpperGR12
    "brxle", 0x000085000000UL, 4, gr8SImmRUpperGR12
    "bxh", 0x000086000000UL, 4, gr8WGR12M16D20
    "bxle", 0x000087000000UL, 4, gr8WGR12M16D20
    "srl", 0x000088000000UL, 4, gr8WNoneM16D20
    "sll", 0x000089000000UL, 4, gr8WNoneM16D20
    "sra", 0x00008A000000UL, 4, gr8WNoneM16D20
    "sla", 0x00008B000000UL, 4, gr8WNoneM16D20
    "srdl", 0x00008C000000UL, 4, gr8WNoneM16D20
    "sldl", 0x00008D000000UL, 4, gr8WNoneM16D20
    "srda", 0x00008E000000UL, 4, gr8WNoneM16D20
    "slda", 0x00008F000000UL, 4, gr8WNoneM16D20
    "stm", 0x000090000000UL, 4, gr8WGR12M16D20
    "lm", 0x000098000000UL, 4, gr8WGR12M16D20
    "trace", 0x000099000000UL, 4, gr8WGR12M16D20
    "lam", 0x00009A000000UL, 4, ar8WAR12M16D20
    "stam", 0x00009B000000UL, 4, ar8WAR12M16D20
    "mvcle", 0x0000A8000000UL, 4, gr8WGR12M16D20
    "clcle", 0x0000A9000000UL, 4, gr8WGR12M16D20
    "sigp", 0x0000AE000000UL, 4, gr8WGR12M16D20
    "stctl", 0x0000B6000000UL, 4, cr8WCR12M16D20
    "lctl", 0x0000B7000000UL, 4, cr8WCR12M16D20
    "cs", 0x0000BA000000UL, 4, gr8WGR12M16D20
    "cds", 0x0000BB000000UL, 4, gr8WGR12M16D20
    "clm", 0x0000BD000000UL, 4, gr8WMask12M16D20
    "stcm", 0x0000BE000000UL, 4, gr8WMask12M16D20
    "icm", 0x0000BF000000UL, 4, gr8WMask12M16D20
    "ssm", 0x000080000000UL, 4, noneM16D20
    "lpsw", 0x000082000000UL, 4, noneM16D20
    "tm", 0x000091000000UL, 4, noneM16D20UImm8
    "mvi", 0x000092000000UL, 4, noneM16D20UImm8
    "ts", 0x000093000000UL, 4, noneM16D20
    "ni", 0x000094000000UL, 4, noneM16D20UImm8
    "cli", 0x000095000000UL, 4, noneM16D20UImm8
    "oi", 0x000096000000UL, 4, noneM16D20UImm8
    "xi", 0x000097000000UL, 4, noneM16D20UImm8
    "stnsm", 0x0000AC000000UL, 4, noneM16D20UImm8
    "stosm", 0x0000AD000000UL, 4, noneM16D20UImm8
    "mc", 0x0000AF000000UL, 4, noneM16D20UImm8
    "niai", 0x0000B2FA0000UL, 4, uImm24UImm28
    "maebr", 0x0000B30E0000UL, 4, fpr16FPR28FPR24
    "msebr", 0x0000B30F0000UL, 4, fpr16FPR28FPR24
    "madbr", 0x0000B31E0000UL, 4, fpr16FPR28FPR24
    "msdbr", 0x0000B31F0000UL, 4, fpr16FPR28FPR24
    "maer", 0x0000B32E0000UL, 4, fpr16FPR28FPR24
    "mser", 0x0000B32F0000UL, 4, fpr16FPR28FPR24
    "maylr", 0x0000B3380000UL, 4, fpr16FPR28FPR24
    "mylr", 0x0000B3390000UL, 4, fpr16FPR28FPR24
    "mayr", 0x0000B33A0000UL, 4, fpr16FPR28FPR24
    "myr", 0x0000B33B0000UL, 4, fpr16FPR28FPR24
    "mayhr", 0x0000B33C0000UL, 4, fpr16FPR28FPR24
    "myhr", 0x0000B33D0000UL, 4, fpr16FPR28FPR24
    "madr", 0x0000B33E0000UL, 4, fpr16FPR28FPR24
    "msdr", 0x0000B33F0000UL, 4, fpr16FPR28FPR24
    "lbear", 0x0000B2000000UL, 4, noneM16D20
    "stbear", 0x0000B2010000UL, 4, noneM16D20
    "stidp", 0x0000B2020000UL, 4, noneM16D20
    "sck", 0x0000B2040000UL, 4, noneM16D20
    "stck", 0x0000B2050000UL, 4, noneM16D20
    "sckc", 0x0000B2060000UL, 4, noneM16D20
    "stckc", 0x0000B2070000UL, 4, noneM16D20
    "spt", 0x0000B2080000UL, 4, noneM16D20
    "stpt", 0x0000B2090000UL, 4, noneM16D20
    "spka", 0x0000B20A0000UL, 4, noneM16D20
    "ipk", 0x0000B20B0000UL, 4, noOperand
    "ptlb", 0x0000B20D0000UL, 4, noOperand
    "spx", 0x0000B2100000UL, 4, noneM16D20
    "stpx", 0x0000B2110000UL, 4, noneM16D20
    "stap", 0x0000B2120000UL, 4, noneM16D20
    "pc", 0x0000B2180000UL, 4, noneM16D20
    "sac", 0x0000B2190000UL, 4, noneM16D20
    "cfc", 0x0000B21A0000UL, 4, noneM16D20
    "csch", 0x0000B2300000UL, 4, noOperand
    "hsch", 0x0000B2310000UL, 4, noOperand
    "msch", 0x0000B2320000UL, 4, noneM16D20
    "ssch", 0x0000B2330000UL, 4, noneM16D20
    "stsch", 0x0000B2340000UL, 4, noneM16D20
    "tsch", 0x0000B2350000UL, 4, noneM16D20
    "tpi", 0x0000B2360000UL, 4, noneM16D20
    "sal", 0x0000B2370000UL, 4, noOperand
    "rsch", 0x0000B2380000UL, 4, noOperand
    "stcrw", 0x0000B2390000UL, 4, noneM16D20
    "stcps", 0x0000B23A0000UL, 4, noneM16D20
    "rchp", 0x0000B23B0000UL, 4, noOperand
    "schm", 0x0000B23C0000UL, 4, noOperand
    "xsch", 0x0000B2760000UL, 4, noOperand
    "rp", 0x0000B2770000UL, 4, noneM16D20
    "stcke", 0x0000B2780000UL, 4, noneM16D20
    "sacf", 0x0000B2790000UL, 4, noneM16D20
    "stckf", 0x0000B27C0000UL, 4, noneM16D20
    "stsi", 0x0000B27D0000UL, 4, noneM16D20
    "qpaci", 0x0000B28F0000UL, 4, noneM16D20
    "srnm", 0x0000B2990000UL, 4, noneM16D20
    "stfpc", 0x0000B29C0000UL, 4, noneM16D20
    "lfpc", 0x0000B29D0000UL, 4, noneM16D20
    "stfle", 0x0000B2B00000UL, 4, noneM16D20
    "stfl", 0x0000B2B10000UL, 4, noneM16D20
    "lpswe", 0x0000B2B20000UL, 4, noneM16D20
    "srnmb", 0x0000B2B80000UL, 4, noneM16D20
    "srnmt", 0x0000B2B90000UL, 4, noneM16D20
    "lfas", 0x0000B2BD0000UL, 4, noneM16D20
    "tend", 0x0000B2F80000UL, 4, noOperand
    "tabort", 0x0000B2FC0000UL, 4, noneM16D20
    "trap4", 0x0000B2FF0000UL, 4, noneM16D20
    "ipm", 0x0000B2220000UL, 4, gr24to27
    "ivsk", 0x0000B2230000UL, 4, gr24GR28
    "iac", 0x0000B2240000UL, 4, gr24to27
    "ssar", 0x0000B2250000UL, 4, gr24to27
    "epar", 0x0000B2260000UL, 4, gr24to27
    "esar", 0x0000B2270000UL, 4, gr24to27
    "pt", 0x0000B2280000UL, 4, gr24GR28
    "iske", 0x0000B2290000UL, 4, gr24GR28
    "rrbe", 0x0000B22A0000UL, 4, gr24GR28
    "tb", 0x0000B22C0000UL, 4, gr24GR28
    "dxr", 0x0000B22D0000UL, 4, fpr24FPR28
    "pgin", 0x0000B22E0000UL, 4, gr24GR28
    "pgout", 0x0000B22F0000UL, 4, gr24GR28
    "bakr", 0x0000B2400000UL, 4, gr24GR28
    "cksm", 0x0000B2410000UL, 4, gr24GR28
    "sqdr", 0x0000B2440000UL, 4, fpr24FPR28
    "sqer", 0x0000B2450000UL, 4, fpr24FPR28
    "stura", 0x0000B2460000UL, 4, gr24GR28
    "msta", 0x0000B2470000UL, 4, gr24to27
    "palb", 0x0000B2480000UL, 4, noOperand
    "ereg", 0x0000B2490000UL, 4, gr24GR28
    "esta", 0x0000B24A0000UL, 4, gr24GR28
    "lura", 0x0000B24B0000UL, 4, gr24GR28
    "tar", 0x0000B24C0000UL, 4, ar24GR28
    "cpya", 0x0000B24D0000UL, 4, ar24AR28
    "sar", 0x0000B24E0000UL, 4, ar24GR28
    "ear", 0x0000B24F0000UL, 4, gr24AR28
    "csp", 0x0000B2500000UL, 4, gr24GR28
    "msr", 0x0000B2520000UL, 4, gr24GR28
    "mvpg", 0x0000B2540000UL, 4, gr24GR28
    "mvst", 0x0000B2550000UL, 4, gr24GR28
    "cuse", 0x0000B2570000UL, 4, gr24GR28
    "bsg", 0x0000B2580000UL, 4, gr24GR28
    "bsa", 0x0000B25A0000UL, 4, gr24GR28
    "clst", 0x0000B25D0000UL, 4, gr24GR28
    "srst", 0x0000B25E0000UL, 4, gr24GR28
    "cmpsc", 0x0000B2630000UL, 4, gr24GR28
    "tre", 0x0000B2A50000UL, 4, gr24GR28
    "cuutf", 0x0000B2A60000UL, 4, gr24GR28
    "cutfu", 0x0000B2A70000UL, 4, gr24GR28
    "etnd", 0x0000B2EC0000UL, 4, gr24to27
    "lpebr", 0x0000B3000000UL, 4, fpr24FPR28
    "lnebr", 0x0000B3010000UL, 4, fpr24FPR28
    "ltebr", 0x0000B3020000UL, 4, fpr24FPR28
    "lcebr", 0x0000B3030000UL, 4, fpr24FPR28
    "ldebr", 0x0000B3040000UL, 4, fpr24FPR28
    "lxdbr", 0x0000B3050000UL, 4, fpr24FPR28
    "lxebr", 0x0000B3060000UL, 4, fpr24FPR28
    "mxdbr", 0x0000B3070000UL, 4, fpr24FPR28
    "kebr", 0x0000B3080000UL, 4, fpr24FPR28
    "cebr", 0x0000B3090000UL, 4, fpr24FPR28
    "aebr", 0x0000B30A0000UL, 4, fpr24FPR28
    "sebr", 0x0000B30B0000UL, 4, fpr24FPR28
    "mdebr", 0x0000B30C0000UL, 4, fpr24FPR28
    "debr", 0x0000B30D0000UL, 4, fpr24FPR28
    "lpdbr", 0x0000B3100000UL, 4, fpr24FPR28
    "lndbr", 0x0000B3110000UL, 4, fpr24FPR28
    "ltdbr", 0x0000B3120000UL, 4, fpr24FPR28
    "lcdbr", 0x0000B3130000UL, 4, fpr24FPR28
    "sqebr", 0x0000B3140000UL, 4, fpr24FPR28
    "sqdbr", 0x0000B3150000UL, 4, fpr24FPR28
    "sqxbr", 0x0000B3160000UL, 4, fpr24FPR28
    "meebr", 0x0000B3170000UL, 4, fpr24FPR28
    "kdbr", 0x0000B3180000UL, 4, fpr24FPR28
    "cdbr", 0x0000B3190000UL, 4, fpr24FPR28
    "adbr", 0x0000B31A0000UL, 4, fpr24FPR28
    "sdbr", 0x0000B31B0000UL, 4, fpr24FPR28
    "mdbr", 0x0000B31C0000UL, 4, fpr24FPR28
    "ddbr", 0x0000B31D0000UL, 4, fpr24FPR28
    "lder", 0x0000B3240000UL, 4, fpr24FPR28
    "lxdr", 0x0000B3250000UL, 4, fpr24FPR28
    "lxer", 0x0000B3260000UL, 4, fpr24FPR28
    "sqxr", 0x0000B3360000UL, 4, fpr24FPR28
    "meer", 0x0000B3370000UL, 4, fpr24FPR28
    "lpxbr", 0x0000B3400000UL, 4, fpr24FPR28
    "lnxbr", 0x0000B3410000UL, 4, fpr24FPR28
    "ltxbr", 0x0000B3420000UL, 4, fpr24FPR28
    "lcxbr", 0x0000B3430000UL, 4, fpr24FPR28
    "ledbr", 0x0000B3440000UL, 4, fpr24FPR28
    "ldxbr", 0x0000B3450000UL, 4, fpr24FPR28
    "lexbr", 0x0000B3460000UL, 4, fpr24FPR28
    "kxbr", 0x0000B3480000UL, 4, fpr24FPR28
    "cxbr", 0x0000B3490000UL, 4, fpr24FPR28
    "axbr", 0x0000B34A0000UL, 4, fpr24FPR28
    "sxbr", 0x0000B34B0000UL, 4, fpr24FPR28
    "mxbr", 0x0000B34C0000UL, 4, fpr24FPR28
    "dxbr", 0x0000B34D0000UL, 4, fpr24FPR28
    "thder", 0x0000B3580000UL, 4, fpr24FPR28
    "thdr", 0x0000B3590000UL, 4, fpr24FPR28
    "lpxr", 0x0000B3600000UL, 4, fpr24FPR28
    "lnxr", 0x0000B3610000UL, 4, fpr24FPR28
    "ltxr", 0x0000B3620000UL, 4, fpr24FPR28
    "lcxr", 0x0000B3630000UL, 4, fpr24FPR28
    "lxr", 0x0000B3650000UL, 4, fpr24FPR28
    "lexr", 0x0000B3660000UL, 4, fpr24FPR28
    "fixr", 0x0000B3670000UL, 4, fpr24FPR28
    "cxr", 0x0000B3690000UL, 4, fpr24FPR28
    "lpdfr", 0x0000B3700000UL, 4, fpr24FPR28
    "lndfr", 0x0000B3710000UL, 4, fpr24FPR28
    "lcdfr", 0x0000B3730000UL, 4, fpr24FPR28
    "lzer", 0x0000B3740000UL, 4, fpr24FPR28
    "lzdr", 0x0000B3750000UL, 4, fpr24FPR28
    "lzxr", 0x0000B3760000UL, 4, fpr24FPR28
    "fier", 0x0000B3770000UL, 4, fpr24FPR28
    "fidr", 0x0000B37F0000UL, 4, fpr24FPR28
    "sfpc", 0x0000B3840000UL, 4, gr24to27
    "sfasr", 0x0000B3850000UL, 4, gr24to27
    "efpc", 0x0000B38C0000UL, 4, gr24to27
    "cefbr", 0x0000B3940000UL, 4, fpr24GR28
    "cdfbr", 0x0000B3950000UL, 4, fpr24GR28
    "cxfbr", 0x0000B3960000UL, 4, fpr24GR28
    "cegbr", 0x0000B3A40000UL, 4, fpr24GR28
    "cdgbr", 0x0000B3A50000UL, 4, fpr24GR28
    "cxgbr", 0x0000B3A60000UL, 4, fpr24GR28
    "cefr", 0x0000B3B40000UL, 4, fpr24GR28
    "cdfr", 0x0000B3B50000UL, 4, fpr24GR28
    "cxfr", 0x0000B3B60000UL, 4, fpr24GR28
    "ldgr", 0x0000B3C10000UL, 4, fpr24GR28
    "cegr", 0x0000B3C40000UL, 4, fpr24GR28
    "cdgr", 0x0000B3C50000UL, 4, fpr24GR28
    "cxgr", 0x0000B3C60000UL, 4, fpr24GR28
    "lgdr", 0x0000B3CD0000UL, 4, gr24FPR28
    "ltdtr", 0x0000B3D60000UL, 4, fpr24FPR28
    "ltxtr", 0x0000B3DE0000UL, 4, fpr24FPR28
    "kdtr", 0x0000B3E00000UL, 4, fpr24FPR28
    "cudtr", 0x0000B3E20000UL, 4, gr24FPR28
    "cdtr", 0x0000B3E40000UL, 4, fpr24FPR28
    "eedtr", 0x0000B3E50000UL, 4, gr24FPR28
    "esdtr", 0x0000B3E70000UL, 4, gr24FPR28
    "kxtr", 0x0000B3E80000UL, 4, fpr24FPR28
    "cuxtr", 0x0000B3EA0000UL, 4, gr24FPR28
    "cxtr", 0x0000B3EC0000UL, 4, fpr24FPR28
    "eextr", 0x0000B3ED0000UL, 4, gr24FPR28
    "esxtr", 0x0000B3EF0000UL, 4, gr24FPR28
    "cdgtr", 0x0000B3F10000UL, 4, fpr24GR28
    "cdutr", 0x0000B3F20000UL, 4, fpr24GR28
    "cdstr", 0x0000B3F30000UL, 4, fpr24GR28
    "cedtr", 0x0000B3F40000UL, 4, fpr24FPR28
    "cxgtr", 0x0000B3F90000UL, 4, fpr24GR28
    "cxutr", 0x0000B3FA0000UL, 4, fpr24GR28
    "cxstr", 0x0000B3FB0000UL, 4, fpr24GR28
    "cextr", 0x0000B3FC0000UL, 4, fpr24FPR28
    "lpgr", 0x0000B9000000UL, 4, gr24GR28
    "lngr", 0x0000B9010000UL, 4, gr24GR28
    "ltgr", 0x0000B9020000UL, 4, gr24GR28
    "lcgr", 0x0000B9030000UL, 4, gr24GR28
    "lgr", 0x0000B9040000UL, 4, gr24GR28
    "lurag", 0x0000B9050000UL, 4, gr24GR28
    "lgbr", 0x0000B9060000UL, 4, gr24GR28
    "lghr", 0x0000B9070000UL, 4, gr24GR28
    "agr", 0x0000B9080000UL, 4, gr24GR28
    "sgr", 0x0000B9090000UL, 4, gr24GR28
    "algr", 0x0000B90A0000UL, 4, gr24GR28
    "slgr", 0x0000B90B0000UL, 4, gr24GR28
    "msgr", 0x0000B90C0000UL, 4, gr24GR28
    "dsgr", 0x0000B90D0000UL, 4, gr24GR28
    "eregg", 0x0000B90E0000UL, 4, gr24GR28
    "lrvgr", 0x0000B90F0000UL, 4, gr24GR28
    "lpgfr", 0x0000B9100000UL, 4, gr24GR28
    "lngfr", 0x0000B9110000UL, 4, gr24GR28
    "ltgfr", 0x0000B9120000UL, 4, gr24GR28
    "lcgfr", 0x0000B9130000UL, 4, gr24GR28
    "lgfr", 0x0000B9140000UL, 4, gr24GR28
    "llgfr", 0x0000B9160000UL, 4, gr24GR28
    "llgtr", 0x0000B9170000UL, 4, gr24GR28
    "agfr", 0x0000B9180000UL, 4, gr24GR28
    "sgfr", 0x0000B9190000UL, 4, gr24GR28
    "algfr", 0x0000B91A0000UL, 4, gr24GR28
    "slgfr", 0x0000B91B0000UL, 4, gr24GR28
    "msgfr", 0x0000B91C0000UL, 4, gr24GR28
    "dsgfr", 0x0000B91D0000UL, 4, gr24GR28
    "kmac", 0x0000B91E0000UL, 4, gr24GR28
    "lrvr", 0x0000B91F0000UL, 4, gr24GR28
    "cgr", 0x0000B9200000UL, 4, gr24GR28
    "clgr", 0x0000B9210000UL, 4, gr24GR28
    "sturg", 0x0000B9250000UL, 4, gr24GR28
    "lbr", 0x0000B9260000UL, 4, gr24GR28
    "lhr", 0x0000B9270000UL, 4, gr24GR28
    "pckmo", 0x0000B9280000UL, 4, noOperand
    "kmf", 0x0000B92A0000UL, 4, gr24GR28
    "kmo", 0x0000B92B0000UL, 4, gr24GR28
    "pcc", 0x0000B92C0000UL, 4, noOperand
    "km", 0x0000B92E0000UL, 4, gr24GR28
    "kmc", 0x0000B92F0000UL, 4, gr24GR28
    "cgfr", 0x0000B9300000UL, 4, gr24GR28
    "clgfr", 0x0000B9310000UL, 4, gr24GR28
    "sortl", 0x0000B9380000UL, 4, gr24GR28
    "kdsa", 0x0000B93A0000UL, 4, gr24GR28
    "nnpa", 0x0000B93B0000UL, 4, noOperand
    "prno", 0x0000B93C0000UL, 4, gr24GR28
    "kimd", 0x0000B93E0000UL, 4, gr24GR28
    "klmd", 0x0000B93F0000UL, 4, gr24GR28
    "bctgr", 0x0000B9460000UL, 4, gr24GR28
    "ngr", 0x0000B9800000UL, 4, gr24GR28
    "ogr", 0x0000B9810000UL, 4, gr24GR28
    "xgr", 0x0000B9820000UL, 4, gr24GR28
    "flogr", 0x0000B9830000UL, 4, gr24GR28
    "llgcr", 0x0000B9840000UL, 4, gr24GR28
    "llghr", 0x0000B9850000UL, 4, gr24GR28
    "mlgr", 0x0000B9860000UL, 4, gr24GR28
    "dlgr", 0x0000B9870000UL, 4, gr24GR28
    "alcgr", 0x0000B9880000UL, 4, gr24GR28
    "slbgr", 0x0000B9890000UL, 4, gr24GR28
    "cspg", 0x0000B98A0000UL, 4, gr24GR28
    "epsw", 0x0000B98D0000UL, 4, gr24GR28
    "llcr", 0x0000B9940000UL, 4, gr24GR28
    "llhr", 0x0000B9950000UL, 4, gr24GR28
    "mlr", 0x0000B9960000UL, 4, gr24GR28
    "dlr", 0x0000B9970000UL, 4, gr24GR28
    "alcr", 0x0000B9980000UL, 4, gr24GR28
    "slbr", 0x0000B9990000UL, 4, gr24GR28
    "epair", 0x0000B99A0000UL, 4, gr24to27
    "esair", 0x0000B99B0000UL, 4, gr24to27
    "esea", 0x0000B99D0000UL, 4, gr24to27
    "pti", 0x0000B99E0000UL, 4, gr24GR28
    "ssair", 0x0000B99F0000UL, 4, gr24to27
    "tpei", 0x0000B9A10000UL, 4, gr24GR28
    "ptf", 0x0000B9A20000UL, 4, gr24to27
    "irbm", 0x0000B9AC0000UL, 4, gr24GR28
    "rrbm", 0x0000B9AE0000UL, 4, gr24GR28
    "pfmf", 0x0000B9AF0000UL, 4, gr24GR28
    "cu41", 0x0000B9B20000UL, 4, gr24GR28
    "cu42", 0x0000B9B30000UL, 4, gr24GR28
    "srstu", 0x0000B9BE0000UL, 4, gr24GR28
    "chhr", 0x0000B9CD0000UL, 4, gr24GR28
    "clhhr", 0x0000B9CF0000UL, 4, gr24GR28
    "chlr", 0x0000B9DD0000UL, 4, gr24GR28
    "clhlr", 0x0000B9DF0000UL, 4, gr24GR28
    "popcnt", 0x0000B9E10000UL, 4, gr24GR28
    "ipte", 0x0000B2210000UL, 4, gr24GR28GR16Mask20
    "sske", 0x0000B22B0000UL, 4, gr24GR28Mask16
    "cu21", 0x0000B2A60000UL, 4, gr24GR28Mask16
    "cu12", 0x0000B2A70000UL, 4, gr24GR28Mask16
    "ppa", 0x0000B2E80000UL, 4, gr24GR28Mask16
    "ledbra", 0x0000B3440000UL, 4, fpr24FPR28Mask16Mask20
    "ldxbra", 0x0000B3450000UL, 4, fpr24FPR28Mask16Mask20
    "lexbra", 0x0000B3460000UL, 4, fpr24FPR28Mask16Mask20
    "fixbr", 0x0000B3470000UL, 4, fpr24FPR28Mask16
    "fixbra", 0x0000B3470000UL, 4, fpr24FPR28Mask16Mask20
    "tbedr", 0x0000B3500000UL, 4, fpr24FPR28Mask16
    "tbdr", 0x0000B3510000UL, 4, fpr24FPR28Mask16
    "diebr", 0x0000B3530000UL, 4, fpr24FPR28FPR16Mask20
    "fiebr", 0x0000B3570000UL, 4, fpr24FPR28Mask16
    "fiebra", 0x0000B3570000UL, 4, fpr24FPR28Mask16Mask20
    "didbr", 0x0000B35B0000UL, 4, fpr24FPR28FPR16Mask20
    "fidbr", 0x0000B35F0000UL, 4, fpr24FPR28Mask16
    "fidbra", 0x0000B35F0000UL, 4, fpr24FPR28Mask16Mask20
    "cpsdr", 0x0000B3720000UL, 4, fpr24FPR28FPR16
    "celfbr", 0x0000B3900000UL, 4, fpr24GR28Mask16Mask20
    "cdlfbr", 0x0000B3910000UL, 4, fpr24GR28Mask16Mask20
    "cxlfbr", 0x0000B3920000UL, 4, fpr24GR28Mask16Mask20
    "cefbra", 0x0000B3940000UL, 4, fpr24GR28Mask16Mask20
    "cdfbra", 0x0000B3950000UL, 4, fpr24GR28Mask16Mask20
    "cxfbra", 0x0000B3960000UL, 4, fpr24GR28Mask16Mask20
    "cfebr", 0x0000B3980000UL, 4, gr24FPR28Mask16
    "cfebra", 0x0000B3980000UL, 4, gr24FPR28Mask16Mask20
    "cfdbr", 0x0000B3990000UL, 4, gr24FPR28Mask16
    "cfdbra", 0x0000B3990000UL, 4, gr24FPR28Mask16Mask20
    "cfxbr", 0x0000B39A0000UL, 4, gr24FPR28Mask16
    "cfxbra", 0x0000B39A0000UL, 4, gr24FPR28Mask16Mask20
    "clfebr", 0x0000B39C0000UL, 4, gr24FPR28Mask16Mask20
    "clfdbr", 0x0000B39D0000UL, 4, gr24FPR28Mask16Mask20
    "clfxbr", 0x0000B39E0000UL, 4, gr24FPR28Mask16Mask20
    "celgbr", 0x0000B3A00000UL, 4, fpr24GR28Mask16Mask20
    "cdlgbr", 0x0000B3A10000UL, 4, fpr24GR28Mask16Mask20
    "cxlgbr", 0x0000B3A20000UL, 4, fpr24GR28Mask16Mask20
    "cegbra", 0x0000B3A40000UL, 4, fpr24GR28Mask16Mask20
    "cdgbra", 0x0000B3A50000UL, 4, fpr24GR28Mask16Mask20
    "cxgbra", 0x0000B3A60000UL, 4, fpr24GR28Mask16Mask20
    "cgebr", 0x0000B3A80000UL, 4, gr24FPR28Mask16
    "cgebra", 0x0000B3A80000UL, 4, gr24FPR28Mask16Mask20
    "cgdbr", 0x0000B3A90000UL, 4, gr24FPR28Mask16
    "cgdbra", 0x0000B3A90000UL, 4, gr24FPR28Mask16Mask20
    "cgxbr", 0x0000B3AA0000UL, 4, gr24FPR28Mask16
    "cgxbra", 0x0000B3AA0000UL, 4, gr24FPR28Mask16Mask20
    "clgebr", 0x0000B3AC0000UL, 4, gr24FPR28Mask16Mask20
    "clgdbr", 0x0000B3AD0000UL, 4, gr24FPR28Mask16Mask20
    "clgxbr", 0x0000B3AE0000UL, 4, gr24FPR28Mask16Mask20
    "cfer", 0x0000B3B80000UL, 4, gr24FPR28Mask16
    "cfdr", 0x0000B3B90000UL, 4, gr24FPR28Mask16
    "cfxr", 0x0000B3BA0000UL, 4, gr24FPR28Mask16
    "cger", 0x0000B3C80000UL, 4, gr24FPR28Mask16
    "cgdr", 0x0000B3C90000UL, 4, gr24FPR28Mask16
    "cgxr", 0x0000B3CA0000UL, 4, gr24FPR28Mask16
    "mdtr", 0x0000B3D00000UL, 4, fpr24FPR28FPR16
    "mdtra", 0x0000B3D00000UL, 4, fpr24FPR28FPR16Mask20
    "ddtr", 0x0000B3D10000UL, 4, fpr24FPR28FPR16
    "ddtra", 0x0000B3D10000UL, 4, fpr24FPR28FPR16Mask20
    "adtr", 0x0000B3D20000UL, 4, fpr24FPR28FPR16
    "adtra", 0x0000B3D20000UL, 4, fpr24FPR28FPR16Mask20
    "sdtr", 0x0000B3D30000UL, 4, fpr24FPR28FPR16
    "sdtra", 0x0000B3D30000UL, 4, fpr24FPR28FPR16Mask20
    "ldetr", 0x0000B3D40000UL, 4, fpr24FPR28Mask20
    "ledtr", 0x0000B3D50000UL, 4, fpr24FPR28Mask16Mask20
    "fidtr", 0x0000B3D70000UL, 4, fpr24FPR28Mask16Mask20
    "mxtr", 0x0000B3D80000UL, 4, fpr24FPR28FPR16
    "mxtra", 0x0000B3D80000UL, 4, fpr24FPR28FPR16Mask20
    "dxtr", 0x0000B3D90000UL, 4, fpr24FPR28FPR16
    "dxtra", 0x0000B3D90000UL, 4, fpr24FPR28FPR16Mask20
    "axtr", 0x0000B3DA0000UL, 4, fpr24FPR28FPR16
    "axtra", 0x0000B3DA0000UL, 4, fpr24FPR28FPR16Mask20
    "sxtr", 0x0000B3DB0000UL, 4, fpr24FPR28FPR16
    "sxtra", 0x0000B3DB0000UL, 4, fpr24FPR28FPR16Mask20
    "lxdtr", 0x0000B3DC0000UL, 4, fpr24FPR28Mask20
    "ldxtr", 0x0000B3DD0000UL, 4, fpr24FPR28Mask16Mask20
    "fixtr", 0x0000B3DF0000UL, 4, fpr24FPR28Mask16Mask20
    "cgdtr", 0x0000B3E10000UL, 4, gr24FPR28Mask16
    "cgdtra", 0x0000B3E10000UL, 4, gr24FPR28Mask16Mask20
    "csdtr", 0x0000B3E30000UL, 4, gr24FPR28Mask20
    "cgxtr", 0x0000B3E90000UL, 4, gr24FPR28Mask16
    "cgxtra", 0x0000B3E90000UL, 4, gr24FPR28Mask16Mask20
    "csxtr", 0x0000B3EB0000UL, 4, gr24FPR28Mask20
    "cdgtra", 0x0000B3F10000UL, 4, fpr24GR28Mask16Mask20
    "qadtr", 0x0000B3F50000UL, 4, fpr24FPR28FPR16Mask20
    "iedtr", 0x0000B3F60000UL, 4, fpr24GR28FPR16
    "rrdtr", 0x0000B3F70000UL, 4, fpr24GR28FPR16Mask20
    "cxgtra", 0x0000B3F90000UL, 4, fpr24GR28Mask16Mask20
    "qaxtr", 0x0000B3FD0000UL, 4, fpr24FPR28FPR16Mask20
    "iextr", 0x0000B3FE0000UL, 4, fpr24GR28FPR16
    "rrxtr", 0x0000B3FF0000UL, 4, fpr24GR28FPR16Mask20
    "kma", 0x0000B9290000UL, 4, gr24GR28GR16
    "kmctr", 0x0000B92D0000UL, 4, gr24GR28GR16
    "dfltcc", 0x0000B9390000UL, 4, gr24GR28GR16
    "cfdtr", 0x0000B9410000UL, 4, gr24FPR28Mask16Mask20
    "clgdtr", 0x0000B9420000UL, 4, gr24FPR28Mask16Mask20
    "clfdtr", 0x0000B9430000UL, 4, gr24FPR28Mask16Mask20
    "cfxtr", 0x0000B9490000UL, 4, gr24FPR28Mask16Mask20
    "clgxtr", 0x0000B94A0000UL, 4, gr24FPR28Mask16Mask20
    "clfxtr", 0x0000B94B0000UL, 4, gr24FPR28Mask16Mask20
    "cdftr", 0x0000B9510000UL, 4, fpr24GR28Mask16Mask20
    "cdlgtr", 0x0000B9520000UL, 4, fpr24GR28Mask16Mask20
    "cdlftr", 0x0000B9530000UL, 4, fpr24GR28Mask16Mask20
    "cxftr", 0x0000B9590000UL, 4, fpr24GR28Mask16Mask20
    "cxlgtr", 0x0000B95A0000UL, 4, fpr24GR28Mask16Mask20
    "cxlftr", 0x0000B95B0000UL, 4, fpr24GR28Mask16Mask20
    "cgrt", 0x0000B9600000UL, 4, gr24GR28Mask16
    "clgrt", 0x0000B9610000UL, 4, gr24GR28Mask16
    "crt", 0x0000B9720000UL, 4, gr24GR28Mask16
    "clrt", 0x0000B9730000UL, 4, gr24GR28Mask16
    "idte", 0x0000B98E0000UL, 4, gr24GR28GR16Mask20
    "crdte", 0x0000B98F0000UL, 4, gr24GR28GR16Mask20
    "trtt", 0x0000B9900000UL, 4, gr24GR28Mask16
    "trto", 0x0000B9910000UL, 4, gr24GR28Mask16
    "trot", 0x0000B9920000UL, 4, gr24GR28Mask16
    "troo", 0x0000B9930000UL, 4, gr24GR28Mask16
    "lptea", 0x0000B9AA0000UL, 4, gr24GR28GR16Mask20
    "cu14", 0x0000B9B00000UL, 4, gr24GR28Mask16
    "cu24", 0x0000B9B10000UL, 4, gr24GR28Mask16
    "trtre", 0x0000B9BD0000UL, 4, gr24GR28Mask16
    "trte", 0x0000B9BF0000UL, 4, gr24GR28Mask16
    "ahhhr", 0x0000B9C80000UL, 4, gr24GR28GR16
    "shhhr", 0x0000B9C90000UL, 4, gr24GR28GR16
    "alhhhr", 0x0000B9CA0000UL, 4, gr24GR28GR16
    "slhhhr", 0x0000B9CB0000UL, 4, gr24GR28GR16
    "ahhlr", 0x0000B9D80000UL, 4, gr24GR28GR16
    "shhlr", 0x0000B9D90000UL, 4, gr24GR28GR16
    "alhhlr", 0x0000B9DA0000UL, 4, gr24GR28GR16
    "slhhlr", 0x0000B9DB0000UL, 4, gr24GR28GR16
    "locfhr", 0x0000B9E00000UL, 4, gr24GR28Mask16
    "locgr", 0x0000B9E20000UL, 4, gr24GR28Mask16
    "ngrk", 0x0000B9E40000UL, 4, gr24GR28GR16
    "ogrk", 0x0000B9E60000UL, 4, gr24GR28GR16
    "xgrk", 0x0000B9E70000UL, 4, gr24GR28GR16
    "agrk", 0x0000B9E80000UL, 4, gr24GR28GR16
    "sgrk", 0x0000B9E90000UL, 4, gr24GR28GR16
    "algrk", 0x0000B9EA0000UL, 4, gr24GR28GR16
    "slgrk", 0x0000B9EB0000UL, 4, gr24GR28GR16
    "mgrk", 0x0000B9EC0000UL, 4, gr24GR28GR16
    "msgrkc", 0x0000B9ED0000UL, 4, gr24GR28GR16
    "locr", 0x0000B9F20000UL, 4, gr24GR28Mask16
    "nrk", 0x0000B9F40000UL, 4, gr24GR28GR16
    "ork", 0x0000B9F60000UL, 4, gr24GR28GR16
    "xrk", 0x0000B9F70000UL, 4, gr24GR28GR16
    "ark", 0x0000B9F80000UL, 4, gr24GR28GR16
    "srk", 0x0000B9F90000UL, 4, gr24GR28GR16
    "alrk", 0x0000B9FA0000UL, 4, gr24GR28GR16
    "slrk", 0x0000B9FB0000UL, 4, gr24GR28GR16
    "msrkc", 0x0000B9FD0000UL, 4, gr24GR28GR16
    "iihh", 0x0000A5000000UL, 4, gr8HWImm
    "iihl", 0x0000A5010000UL, 4, gr8HWImm
    "iilh", 0x0000A5020000UL, 4, gr8HWImm
    "iill", 0x0000A5030000UL, 4, gr8HWImm
    "nihh", 0x0000A5040000UL, 4, gr8HWImm
    "nihl", 0x0000A5050000UL, 4, gr8HWImm
    "nilh", 0x0000A5060000UL, 4, gr8HWImm
    "nill", 0x0000A5070000UL, 4, gr8HWImm
    "oihh", 0x0000A5080000UL, 4, gr8HWImm
    "oihl", 0x0000A5090000UL, 4, gr8HWImm
    "oilh", 0x0000A50A0000UL, 4, gr8HWImm
    "oill", 0x0000A50B0000UL, 4, gr8HWImm
    "llihh", 0x0000A50C0000UL, 4, gr8HWImm
    "llihl", 0x0000A50D0000UL, 4, gr8HWImm
    "llilh", 0x0000A50E0000UL, 4, gr8HWImm
    "llill", 0x0000A50F0000UL, 4, gr8HWImm
    "tmlh", 0x0000A7000000UL, 4, gr8HWImmM
    "tmll", 0x0000A7010000UL, 4, gr8HWImmM
    "tmhh", 0x0000A7020000UL, 4, gr8HWImmM
    "tmhl", 0x0000A7030000UL, 4, gr8HWImmM
    "brc", 0x0000A7040000UL, 4, bit8MaskSImmRUpper
    "bras", 0x0000A7050000UL, 4, gr8SImmRUpper
    "brct", 0x0000A7060000UL, 4, gr8SImmRUpper
    "brctg", 0x0000A7070000UL, 4, gr8SImmRUpper
    "lhi", 0x0000A7080000UL, 4, gr8SImmUpper
    "lghi", 0x0000A7090000UL, 4, gr8SImmUpper
    "ahi", 0x0000A70A0000UL, 4, gr8SImmUpper
    "aghi", 0x0000A70B0000UL, 4, gr8SImmUpper
    "mhi", 0x0000A70C0000UL, 4, gr8SImmUpper
    "mghi", 0x0000A70D0000UL, 4, gr8SImmUpper
    "chi", 0x0000A70E0000UL, 4, gr8SImmUpper
    "cghi", 0x0000A70F0000UL, 4, gr8SImmUpper
    "lasp", 0xE50000000000UL, 6, m16D20M32D36
    "tprot", 0xE50100000000UL, 6, m16D20M32D36
    "strag", 0xE50200000000UL, 6, m16D20M32D36
    "mvcrl", 0xE50A00000000UL, 6, m16D20M32D36
    "mvcsk", 0xE50E00000000UL, 6, m16D20M32D36
    "mvcdk", 0xE50F00000000UL, 6, m16D20M32D36
    "mvhhi", 0xE54400000000UL, 6, m16D20SImm32to47CQ
    "mvghi", 0xE54800000000UL, 6, m16D20SImm32to47CQ
    "mvhi", 0xE54C00000000UL, 6, m16D20SImm32to47CQ
    "chhsi", 0xE55400000000UL, 6, m16D20SImm32to47CQ
    "clhhsi", 0xE55500000000UL, 6, m16D20UImm32to47Q
    "cghsi", 0xE55800000000UL, 6, m16D20SImm32to47CQ
    "clghsi", 0xE55900000000UL, 6, m16D20UImm32to47Q
    "chsi", 0xE55C00000000UL, 6, m16D20SImm32to47CQ
    "clfhsi", 0xE55D00000000UL, 6, m16D20UImm32to47Q
    "tbegin", 0xE56000000000UL, 6, m16D20UImm32to47Q
    "tbeginc", 0xE56100000000UL, 6, m16D20UImm32to47Q
    "bpp", 0xC70000000000UL, 6, mask8QSImmRQM32D36
    "bprp", 0xC50000000000UL, 6, mask8Imm12Imm24
    "trtr", 0xD00000000000UL, 6, grl8QM32D36
    "mvn", 0xD10000000000UL, 6, grl8QM32D36
    "mvc", 0xD20000000000UL, 6, grl8QM32D36
    "mvz", 0xD30000000000UL, 6, grl8QM32D36
    "nc", 0xD40000000000UL, 6, grl8QM32D36
    "clc", 0xD50000000000UL, 6, grl8QM32D36
    "oc", 0xD60000000000UL, 6, grl8QM32D36
    "xc", 0xD70000000000UL, 6, grl8QM32D36
    "mvck", 0xD90000000000UL, 6, idx8M16D20M32D36GR12Q
    "mvcp", 0xDA0000000000UL, 6, idx8M16D20M32D36GR12Q
    "mvcs", 0xDB0000000000UL, 6, idx8M16D20M32D36GR12Q
    "tr", 0xDC0000000000UL, 6, grl8QM32D36
    "trt", 0xDD0000000000UL, 6, grl8QM32D36
    "ed", 0xDE0000000000UL, 6, grl8QM32D36
    "edmk", 0xDF0000000000UL, 6, grl8QM32D36
    "pku", 0xE10000000000UL, 6, m16D20GRL8Q
    "unpku", 0xE20000000000UL, 6, grl8QM32D36
    "mvcin", 0xE80000000000UL, 6, grl8QM32D36
    "pka", 0xE90000000000UL, 6, m16D20GRL8Q
    "unpka", 0xEA0000000000UL, 6, grl8QM32D36
    "plo", 0xEE0000000000UL, 6, gr8QM16D20GR12QM32D36
    "lmd", 0xEF0000000000UL, 6, gr8QM16D20GR12QM32D36
    "srp", 0xF00000000000UL, 6, grl8QM32D36UImm4
    "mvo", 0xF10000000000UL, 6, grl8QGRL12Q
    "pack", 0xF20000000000UL, 6, grl8QGRL12Q
    "unpk", 0xF30000000000UL, 6, grl8QGRL12Q
    "zap", 0xF80000000000UL, 6, grl8QGRL12Q
    "cp", 0xF90000000000UL, 6, grl8QGRL12Q
    "ap", 0xFA0000000000UL, 6, grl8QGRL12Q
    "sp", 0xFB0000000000UL, 6, grl8QGRL12Q
    "mp", 0xFC0000000000UL, 6, grl8QGRL12Q
    "dp", 0xFD0000000000UL, 6, grl8QGRL12Q
    "mvcos", 0xC80000000000UL, 6, m16D20M32D36GR8Q
    "ectg", 0xC80100000000UL, 6, m16D20M32D36GR8Q
    "csst", 0xC80200000000UL, 6, m16D20M32D36GR8Q
    "lpd", 0xC80400000000UL, 6, m16D20M32D36GR8Q
    "lpdg", 0xC80500000000UL, 6, m16D20M32D36GR8Q
    "larl", 0xC00000000000UL, 6, gr8QSImm16to47RQ
    "lgfi", 0xC00100000000UL, 6, gr8QSImm16to47Q
    "brcl", 0xC00400000000UL, 6, mask8QSImm16to47RQ
    "brasl", 0xC00500000000UL, 6, gr8QSImm16to47RQ
    "xihf", 0xC00600000000UL, 6, gr8QUImm16to47CQ
    "xilf", 0xC00700000000UL, 6, gr8QUImm16to47CQ
    "iihf", 0xC00800000000UL, 6, gr8QUImm16to47CQ
    "iilf", 0xC00900000000UL, 6, gr8QUImm16to47CQ
    "nihf", 0xC00A00000000UL, 6, gr8QUImm16to47CQ
    "nilf", 0xC00B00000000UL, 6, gr8QUImm16to47CQ
    "oihf", 0xC00C00000000UL, 6, gr8QUImm16to47CQ
    "oilf", 0xC00D00000000UL, 6, gr8QUImm16to47CQ
    "llihf", 0xC00E00000000UL, 6, gr8QUImm16to47CQ
    "llilf", 0xC00F00000000UL, 6, gr8QUImm16to47CQ
    "msgfi", 0xC20000000000UL, 6, gr8QSImm16to47Q
    "msfi", 0xC20100000000UL, 6, gr8QSImm16to47Q
    "slgfi", 0xC20400000000UL, 6, gr8QUImm16to47CQ
    "slfi", 0xC20500000000UL, 6, gr8QUImm16to47CQ
    "agfi", 0xC20800000000UL, 6, gr8QSImm16to47Q
    "afi", 0xC20900000000UL, 6, gr8QSImm16to47Q
    "algfi", 0xC20A00000000UL, 6, gr8QUImm16to47CQ
    "alfi", 0xC20B00000000UL, 6, gr8QUImm16to47CQ
    "cgfi", 0xC20C00000000UL, 6, gr8QSImm16to47Q
    "cfi", 0xC20D00000000UL, 6, gr8QSImm16to47Q
    "clgfi", 0xC20E00000000UL, 6, gr8QUImm16to47CQ
    "clfi", 0xC20F00000000UL, 6, gr8QUImm16to47CQ
    "llhrl", 0xC40200000000UL, 6, gr8QSImm16to47RQ
    "lghrl", 0xC40400000000UL, 6, gr8QSImm16to47RQ
    "lhrl", 0xC40500000000UL, 6, gr8QSImm16to47RQ
    "llghrl", 0xC40600000000UL, 6, gr8QSImm16to47RQ
    "sthrl", 0xC40700000000UL, 6, gr8QSImm16to47RQ
    "lgrl", 0xC40800000000UL, 6, gr8QSImm16to47RQ
    "stgrl", 0xC40B00000000UL, 6, gr8QSImm16to47RQ
    "lgfrl", 0xC40C00000000UL, 6, gr8QSImm16to47RQ
    "lrl", 0xC40D00000000UL, 6, gr8QSImm16to47RQ
    "llgfrl", 0xC40E00000000UL, 6, gr8QSImm16to47RQ
    "strl", 0xC40F00000000UL, 6, gr8QSImm16to47RQ
    "exrl", 0xC60000000000UL, 6, gr8QSImm16to47RQ
    "pfdrl", 0xC60200000000UL, 6, mask8QSImm16to47RQ
    "cghrl", 0xC60400000000UL, 6, gr8QSImm16to47RQ
    "chrl", 0xC60500000000UL, 6, gr8QSImm16to47RQ
    "clghrl", 0xC60600000000UL, 6, gr8QSImm16to47RQ
    "clhrl", 0xC60700000000UL, 6, gr8QSImm16to47RQ
    "cgrl", 0xC60800000000UL, 6, gr8QSImm16to47RQ
    "clgrl", 0xC60A00000000UL, 6, gr8QSImm16to47RQ
    "cgfrl", 0xC60C00000000UL, 6, gr8QSImm16to47RQ
    "crl", 0xC60D00000000UL, 6, gr8QSImm16to47RQ
    "clgfrl", 0xC60E00000000UL, 6, gr8QSImm16to47RQ
    "clrl", 0xC60F00000000UL, 6, gr8QSImm16to47RQ
    "brcth", 0xCC0600000000UL, 6, gr8QSImm16to47RQ
    "aih", 0xCC0800000000UL, 6, gr8QSImm16to47Q
    "alsih", 0xCC0A00000000UL, 6, gr8QSImm16to47Q
    "alsihn", 0xCC0B00000000UL, 6, gr8QSImm16to47Q
    "cih", 0xCC0D00000000UL, 6, gr8QSImm16to47Q
    "clih", 0xCC0F00000000UL, 6, gr8QUImm16to47CQ
    "lochi", 0xEC0000000042UL, 6, gr8QSImmUpperQMask12Q
    "brxhg", 0xEC0000000044UL, 6, gr8QSImmUpperRQGR12Q
    "brxlg", 0xEC0000000045UL, 6, gr8QSImmUpperRQGR12Q
    "locghi", 0xEC0000000046UL, 6, gr8QSImmUpperQMask12Q
    "lochhi", 0xEC000000004EUL, 6, gr8QSImmUpperQMask12Q
    "risblg", 0xEC0000000051UL, 6, gr8QGR12QUImmUpper24to32Q
    "rnsbg", 0xEC0000000054UL, 6, gr8QGR12QUImmUpper24to32Q
    "risbg", 0xEC0000000055UL, 6, gr8QGR12QUImmUpper24to32Q
    "rosbg", 0xEC0000000056UL, 6, gr8QGR12QUImmUpper24to32Q
    "rxsbg", 0xEC0000000057UL, 6, gr8QGR12QUImmUpper24to32Q
    "risbgn", 0xEC0000000059UL, 6, gr8QGR12QUImmUpper24to32Q
    "risbhg", 0xEC000000005DUL, 6, gr8QGR12QUImmUpper24to32Q
    "cgrj", 0xEC0000000064UL, 6, gr8QGR12QMask32SImmUpperRQ
    "clgrj", 0xEC0000000065UL, 6, gr8QGR12QMask32SImmUpperRQ
    "cgit", 0xEC0000000070UL, 6, gr8QSImmUpperQMask32Q
    "clgit", 0xEC0000000071UL, 6, gr8QUImmUpperQMask32Q
    "cit", 0xEC0000000072UL, 6, gr8QSImmUpperQMask32Q
    "clfit", 0xEC0000000073UL, 6, gr8QUImmUpperQMask32Q
    "crj", 0xEC0000000076UL, 6, gr8QGR12QMask32SImmUpperRQ
    "clrj", 0xEC0000000077UL, 6, gr8QGR12QMask32SImmUpperRQ
    "cgij", 0xEC000000007CUL, 6, gr8QSImm32BQMask12SImmUpperRQ
    "clgij", 0xEC000000007DUL, 6, gr8QUImm32CQMask12SImmUpperRQ
    "cij", 0xEC000000007EUL, 6, gr8QSImm32BQMask12SImmUpperRQ
    "clij", 0xEC000000007FUL, 6, gr8QUImm32CQMask12SImmUpperRQ
    "ahik", 0xEC00000000D8UL, 6, gr8QSImmUpperQGR12Q
    "aghik", 0xEC00000000D9UL, 6, gr8QSImmUpperQGR12Q
    "alhsik", 0xEC00000000DAUL, 6, gr8QSImmUpperQGR12Q
    "alghsik", 0xEC00000000DBUL, 6, gr8QSImmUpperQGR12Q
    "cgib", 0xEC00000000FCUL, 6, gr8QSImm32BQMask12NBase16Disp20
    "clgib", 0xEC00000000FDUL, 6, gr8QUImm32CQMask12NBase16Disp20
    "cib", 0xEC00000000FEUL, 6, gr8QSImm32BQMask12NBase16Disp20
    "clib", 0xEC00000000FFUL, 6, gr8QUImm32CQMask12NBase16Disp20
    "cgrb", 0xEC00000000E4UL, 6, gr8QGR12QMask32NBase16Disp20
    "clgrb", 0xEC00000000E5UL, 6, gr8QGR12QMask32NBase16Disp20
    "crb", 0xEC00000000F6UL, 6, gr8QGR12QMask32NBase16Disp20
    "clrb", 0xEC00000000F7UL, 6, gr8QGR12QMask32NBase16Disp20
    "tp", 0xEB00000000C0UL, 6, grl8Q
    "czdt", 0xED00000000A8UL, 6, fpr32QGRL8QMask36
    "czxt", 0xED00000000A9UL, 6, fpr32QGRL8QMask36
    "cdzt", 0xED00000000AAUL, 6, fpr32QGRL8QMask36
    "cxzt", 0xED00000000ABUL, 6, fpr32QGRL8QMask36
    "cpdt", 0xED00000000ACUL, 6, fpr32QGRL8QMask36
    "cpxt", 0xED00000000ADUL, 6, fpr32QGRL8QMask36
    "cdpt", 0xED00000000AEUL, 6, fpr32QGRL8QMask36
    "cxpt", 0xED00000000AFUL, 6, fpr32QGRL8QMask36
    "lmg", 0xEB0000000004UL, 6, gr8QM16D20GR12Q
    "srag", 0xEB000000000AUL, 6, gr8QM16D20GR12Q
    "slag", 0xEB000000000BUL, 6, gr8QM16D20GR12Q
    "srlg", 0xEB000000000CUL, 6, gr8QM16D20GR12Q
    "sllg", 0xEB000000000DUL, 6, gr8QM16D20GR12Q
    "tracg", 0xEB000000000FUL, 6, gr8QM16D20GR12Q
    "csy", 0xEB0000000014UL, 6, gr8QM16D20GR12Q
    "rllg", 0xEB000000001CUL, 6, gr8QM16D20GR12Q
    "rll", 0xEB000000001DUL, 6, gr8QM16D20GR12Q
    "clmh", 0xEB0000000020UL, 6, gr8QM16D20Mask12Q
    "clmy", 0xEB0000000021UL, 6, gr8QM16D20Mask12Q
    "clt", 0xEB0000000023UL, 6, gr8QM16D20Mask12Q
    "stmg", 0xEB0000000024UL, 6, gr8QM16D20GR12Q
    "stctg", 0xEB0000000025UL, 6, cr8QM16D20CR12Q
    "stmh", 0xEB0000000026UL, 6, gr8QM16D20GR12Q
    "clgt", 0xEB000000002BUL, 6, gr8QM16D20Mask12Q
    "stcmh", 0xEB000000002CUL, 6, gr8QM16D20Mask12Q
    "stcmy", 0xEB000000002DUL, 6, gr8QM16D20Mask12Q
    "lctlg", 0xEB000000002FUL, 6, gr8QM16D20GR12Q
    "csg", 0xEB0000000030UL, 6, gr8QM16D20GR12Q
    "cdsy", 0xEB0000000031UL, 6, gr8QM16D20GR12Q
    "cdsg", 0xEB000000003EUL, 6, gr8QM16D20GR12Q
    "bxhg", 0xEB0000000044UL, 6, gr8QM16D20GR12Q
    "bxleg", 0xEB0000000045UL, 6, gr8QM16D20GR12Q
    "ecag", 0xEB000000004CUL, 6, gr8QM16D20GR12Q
    "icmh", 0xEB0000000080UL, 6, gr8QM16D20Mask12Q
    "icmy", 0xEB0000000081UL, 6, gr8QM16D20Mask12Q
    "mvclu", 0xEB000000008EUL, 6, gr8QM16D20GR12Q
    "clclu", 0xEB000000008FUL, 6, gr8QM16D20GR12Q
    "stmy", 0xEB0000000090UL, 6, gr8QM16D20GR12Q
    "lmh", 0xEB0000000096UL, 6, gr8QM16D20GR12Q
    "lmy", 0xEB0000000098UL, 6, gr8QM16D20GR12Q
    "lamy", 0xEB000000009AUL, 6, ar8QM16D20AR12Q
    "stamy", 0xEB000000009BUL, 6, ar8QM16D20AR12Q
    "srak", 0xEB00000000DCUL, 6, gr8QM16D20GR12Q
    "slak", 0xEB00000000DDUL, 6, gr8QM16D20GR12Q
    "srlk", 0xEB00000000DEUL, 6, gr8QM16D20GR12Q
    "sllk", 0xEB00000000DFUL, 6, gr8QM16D20GR12Q
    "locfh", 0xEB00000000E0UL, 6, gr8QM16D20Mask12Q
    "stocfh", 0xEB00000000E1UL, 6, gr8QM16D20Mask12Q
    "locg", 0xEB00000000E2UL, 6, gr8QM16D20Mask12Q
    "stocg", 0xEB00000000E3UL, 6, gr8QM16D20Mask12Q
    "lang", 0xEB00000000E4UL, 6, gr8QM16D20GR12Q
    "laog", 0xEB00000000E6UL, 6, gr8QM16D20GR12Q
    "laxg", 0xEB00000000E7UL, 6, gr8QM16D20GR12Q
    "laag", 0xEB00000000E8UL, 6, gr8QM16D20GR12Q
    "laalg", 0xEB00000000EAUL, 6, gr8QM16D20GR12Q
    "loc", 0xEB00000000F2UL, 6, gr8QM16D20Mask12Q
    "stoc", 0xEB00000000F3UL, 6, gr8QM16D20Mask12Q
    "lan", 0xEB00000000F4UL, 6, gr8QM16D20GR12Q
    "lao", 0xEB00000000F6UL, 6, gr8QM16D20GR12Q
    "lax", 0xEB00000000F7UL, 6, gr8QM16D20GR12Q
    "laa", 0xEB00000000F8UL, 6, gr8QM16D20GR12Q
    "laal", 0xEB00000000FAUL, 6, gr8QM16D20GR12Q
    "lcbb", 0xE70000000027UL, 6, gr8QIdx12M16D20Mask32Q
    "ldeb", 0xED0000000004UL, 6, fpr8QIdx12M16D20
    "lxdb", 0xED0000000005UL, 6, fpr8QIdx12M16D20
    "lxeb", 0xED0000000006UL, 6, fpr8QIdx12M16D20
    "mxdb", 0xED0000000007UL, 6, fpr8QIdx12M16D20
    "keb", 0xED0000000008UL, 6, fpr8QIdx12M16D20
    "ceb", 0xED0000000009UL, 6, fpr8QIdx12M16D20
    "aeb", 0xED000000000AUL, 6, fpr8QIdx12M16D20
    "seb", 0xED000000000BUL, 6, fpr8QIdx12M16D20
    "mdeb", 0xED000000000CUL, 6, fpr8QIdx12M16D20
    "deb", 0xED000000000DUL, 6, fpr8QIdx12M16D20
    "tceb", 0xED0000000010UL, 6, fpr8QIdx12M16D20
    "tcdb", 0xED0000000011UL, 6, fpr8QIdx12M16D20
    "tcxb", 0xED0000000012UL, 6, fpr8QIdx12M16D20
    "sqeb", 0xED0000000014UL, 6, fpr8QIdx12M16D20
    "sqdb", 0xED0000000015UL, 6, fpr8QIdx12M16D20
    "meeb", 0xED0000000017UL, 6, fpr8QIdx12M16D20
    "kdb", 0xED0000000018UL, 6, fpr8QIdx12M16D20
    "cdb", 0xED0000000019UL, 6, fpr8QIdx12M16D20
    "adb", 0xED000000001AUL, 6, fpr8QIdx12M16D20
    "sdb", 0xED000000001BUL, 6, fpr8QIdx12M16D20
    "mdb", 0xED000000001CUL, 6, fpr8QIdx12M16D20
    "ddb", 0xED000000001DUL, 6, fpr8QIdx12M16D20
    "lde", 0xED0000000024UL, 6, fpr8QIdx12M16D20
    "lxd", 0xED0000000025UL, 6, fpr8QIdx12M16D20
    "lxe", 0xED0000000026UL, 6, fpr8QIdx12M16D20
    "sqe", 0xED0000000034UL, 6, fpr8QIdx12M16D20
    "sqd", 0xED0000000035UL, 6, fpr8QIdx12M16D20
    "mee", 0xED0000000037UL, 6, fpr8QIdx12M16D20
    "tdcet", 0xED0000000050UL, 6, fpr8QIdx12M16D20
    "tdget", 0xED0000000051UL, 6, fpr8QIdx12M16D20
    "tdcdt", 0xED0000000054UL, 6, fpr8QIdx12M16D20
    "tdgdt", 0xED0000000055UL, 6, fpr8QIdx12M16D20
    "tdcxt", 0xED0000000058UL, 6, fpr8QIdx12M16D20
    "tdgxt", 0xED0000000059UL, 6, fpr8QIdx12M16D20
    "ltg", 0xE30000000002UL, 6, gr8QIdx12M16D20
    "lrag", 0xE30000000003UL, 6, gr8QIdx12M16D20
    "lg", 0xE30000000004UL, 6, gr8QIdx12M16D20
    "cvby", 0xE30000000006UL, 6, gr8QIdx12M16D20
    "ag", 0xE30000000008UL, 6, gr8QIdx12M16D20
    "sg", 0xE30000000009UL, 6, gr8QIdx12M16D20
    "alg", 0xE3000000000AUL, 6, gr8QIdx12M16D20
    "slg", 0xE3000000000BUL, 6, gr8QIdx12M16D20
    "msg", 0xE3000000000CUL, 6, gr8QIdx12M16D20
    "dsg", 0xE3000000000DUL, 6, gr8QIdx12M16D20
    "cvbg", 0xE3000000000EUL, 6, gr8QIdx12M16D20
    "lrvg", 0xE3000000000FUL, 6, gr8QIdx12M16D20
    "lt", 0xE30000000012UL, 6, gr8QIdx12M16D20
    "lray", 0xE30000000013UL, 6, gr8QIdx12M16D20
    "lgf", 0xE30000000014UL, 6, gr8QIdx12M16D20
    "lgh", 0xE30000000015UL, 6, gr8QIdx12M16D20
    "llgf", 0xE30000000016UL, 6, gr8QIdx12M16D20
    "llgt", 0xE30000000017UL, 6, gr8QIdx12M16D20
    "agf", 0xE30000000018UL, 6, gr8QIdx12M16D20
    "sgf", 0xE30000000019UL, 6, gr8QIdx12M16D20
    "algf", 0xE3000000001AUL, 6, gr8QIdx12M16D20
    "slgf", 0xE3000000001BUL, 6, gr8QIdx12M16D20
    "msgf", 0xE3000000001CUL, 6, gr8QIdx12M16D20
    "dsgf", 0xE3000000001DUL, 6, gr8QIdx12M16D20
    "lrv", 0xE3000000001EUL, 6, gr8QIdx12M16D20
    "lrvh", 0xE3000000001FUL, 6, gr8QIdx12M16D20
    "cg", 0xE30000000020UL, 6, gr8QIdx12M16D20
    "clg", 0xE30000000021UL, 6, gr8QIdx12M16D20
    "stg", 0xE30000000024UL, 6, gr8QIdx12M16D20
    "ntstg", 0xE30000000025UL, 6, gr8QIdx12M16D20
    "cvdy", 0xE30000000026UL, 6, gr8QIdx12M16D20
    "lzrg", 0xE3000000002AUL, 6, gr8QIdx12M16D20
    "cvdg", 0xE3000000002EUL, 6, gr8QIdx12M16D20
    "strvg", 0xE3000000002FUL, 6, gr8QIdx12M16D20
    "cgf", 0xE30000000030UL, 6, gr8QIdx12M16D20
    "clgf", 0xE30000000031UL, 6, gr8QIdx12M16D20
    "ltgf", 0xE30000000032UL, 6, gr8QIdx12M16D20
    "cgh", 0xE30000000034UL, 6, gr8QIdx12M16D20
    "pfd", 0xE30000000036UL, 6, mask8QIdx12M16D20
    "agh", 0xE30000000038UL, 6, gr8QIdx12M16D20
    "sgh", 0xE30000000039UL, 6, gr8QIdx12M16D20
    "llzrgf", 0xE3000000003AUL, 6, gr8QIdx12M16D20
    "lzrf", 0xE3000000003BUL, 6, gr8QIdx12M16D20
    "mgh", 0xE3000000003CUL, 6, gr8QIdx12M16D20
    "strv", 0xE3000000003EUL, 6, gr8QIdx12M16D20
    "strvh", 0xE3000000003FUL, 6, gr8QIdx12M16D20
    "bctg", 0xE30000000046UL, 6, gr8QIdx12M16D20
    "bic", 0xE30000000047UL, 6, mask8QIdx12M16D20
    "llgfsg", 0xE30000000048UL, 6, gr8QIdx12M16D20
    "stgsc", 0xE30000000049UL, 6, gr8QIdx12M16D20
    "lgg", 0xE3000000004CUL, 6, gr8QIdx12M16D20
    "lgsc", 0xE3000000004DUL, 6, gr8QIdx12M16D20
    "sty", 0xE30000000050UL, 6, gr8QIdx12M16D20
    "msy", 0xE30000000051UL, 6, gr8QIdx12M16D20
    "msc", 0xE30000000053UL, 6, gr8QIdx12M16D20
    "ny", 0xE30000000054UL, 6, gr8QIdx12M16D20
    "cly", 0xE30000000055UL, 6, gr8QIdx12M16D20
    "oy", 0xE30000000056UL, 6, gr8QIdx12M16D20
    "xy", 0xE30000000057UL, 6, gr8QIdx12M16D20
    "ly", 0xE30000000058UL, 6, gr8QIdx12M16D20
    "cy", 0xE30000000059UL, 6, gr8QIdx12M16D20
    "ay", 0xE3000000005AUL, 6, gr8QIdx12M16D20
    "sy", 0xE3000000005BUL, 6, gr8QIdx12M16D20
    "mfy", 0xE3000000005CUL, 6, gr8QIdx12M16D20
    "aly", 0xE3000000005EUL, 6, gr8QIdx12M16D20
    "sly", 0xE3000000005FUL, 6, gr8QIdx12M16D20
    "sthy", 0xE30000000070UL, 6, gr8QIdx12M16D20
    "lay", 0xE30000000071UL, 6, gr8QIdx12M16D20
    "stcy", 0xE30000000072UL, 6, gr8QIdx12M16D20
    "icy", 0xE30000000073UL, 6, gr8QIdx12M16D20
    "laey", 0xE30000000075UL, 6, gr8QIdx12M16D20
    "lb", 0xE30000000076UL, 6, gr8QIdx12M16D20
    "lgb", 0xE30000000077UL, 6, gr8QIdx12M16D20
    "lhy", 0xE30000000078UL, 6, gr8QIdx12M16D20
    "chy", 0xE30000000079UL, 6, gr8QIdx12M16D20
    "ahy", 0xE3000000007AUL, 6, gr8QIdx12M16D20
    "shy", 0xE3000000007BUL, 6, gr8QIdx12M16D20
    "mhy", 0xE3000000007CUL, 6, gr8QIdx12M16D20
    "ng", 0xE30000000080UL, 6, gr8QIdx12M16D20
    "og", 0xE30000000081UL, 6, gr8QIdx12M16D20
    "xg", 0xE30000000082UL, 6, gr8QIdx12M16D20
    "msgc", 0xE30000000083UL, 6, gr8QIdx12M16D20
    "mg", 0xE30000000084UL, 6, gr8QIdx12M16D20
    "lgat", 0xE30000000085UL, 6, gr8QIdx12M16D20
    "mlg", 0xE30000000086UL, 6, gr8QIdx12M16D20
    "dlg", 0xE30000000087UL, 6, gr8QIdx12M16D20
    "alcg", 0xE30000000088UL, 6, gr8QIdx12M16D20
    "slbg", 0xE30000000089UL, 6, gr8QIdx12M16D20
    "stpq", 0xE3000000008EUL, 6, gr8QIdx12M16D20
    "lpq", 0xE3000000008FUL, 6, gr8QIdx12M16D20
    "llgc", 0xE30000000090UL, 6, gr8QIdx12M16D20
    "llgh", 0xE30000000091UL, 6, gr8QIdx12M16D20
    "llc", 0xE30000000094UL, 6, gr8QIdx12M16D20
    "llh", 0xE30000000095UL, 6, gr8QIdx12M16D20
    "ml", 0xE30000000096UL, 6, gr8QIdx12M16D20
    "dl", 0xE30000000097UL, 6, gr8QIdx12M16D20
    "alc", 0xE30000000098UL, 6, gr8QIdx12M16D20
    "slb", 0xE30000000099UL, 6, gr8QIdx12M16D20
    "llgtat", 0xE3000000009CUL, 6, gr8QIdx12M16D20
    "llgfat", 0xE3000000009DUL, 6, gr8QIdx12M16D20
    "lat", 0xE3000000009FUL, 6, gr8QIdx12M16D20
    "lbh", 0xE300000000C0UL, 6, gr8QIdx12M16D20
    "llch", 0xE300000000C2UL, 6, gr8QIdx12M16D20
    "stch", 0xE300000000C3UL, 6, gr8QIdx12M16D20
    "lhh", 0xE300000000C4UL, 6, gr8QIdx12M16D20
    "llhh", 0xE300000000C6UL, 6, gr8QIdx12M16D20
    "sthh", 0xE300000000C7UL, 6, gr8QIdx12M16D20
    "lfhat", 0xE300000000C8UL, 6, gr8QIdx12M16D20
    "lfh", 0xE300000000CAUL, 6, gr8QIdx12M16D20
    "stfh", 0xE300000000CBUL, 6, gr8QIdx12M16D20
    "chf", 0xE300000000CDUL, 6, gr8QIdx12M16D20
    "clhf", 0xE300000000CFUL, 6, gr8QIdx12M16D20
    "ley", 0xED0000000064UL, 6, fpr8QIdx12MemBase16DispL20
    "ldy", 0xED0000000065UL, 6, fpr8QIdx12MemBase16DispL20
    "stey", 0xED0000000066UL, 6, fpr8QIdx12MemBase16DispL20
    "stdy", 0xED0000000067UL, 6, fpr8QIdx12MemBase16DispL20
    "maeb", 0xED000000000EUL, 6, fpr32QIdx12M16D20FPR8Q
    "mseb", 0xED000000000FUL, 6, fpr32QIdx12M16D20FPR8Q
    "madb", 0xED000000001EUL, 6, fpr32QIdx12M16D20FPR8Q
    "msdb", 0xED000000001FUL, 6, fpr32QIdx12M16D20FPR8Q
    "mae", 0xED000000002EUL, 6, fpr32QIdx12M16D20FPR8Q
    "mse", 0xED000000002FUL, 6, fpr32QIdx12M16D20FPR8Q
    "mayl", 0xED0000000038UL, 6, fpr32QIdx12M16D20FPR8Q
    "myl", 0xED0000000039UL, 6, fpr32QIdx12M16D20FPR8Q
    "may", 0xED000000003AUL, 6, fpr32QIdx12M16D20FPR8Q
    "my", 0xED000000003BUL, 6, fpr32QIdx12M16D20FPR8Q
    "mayh", 0xED000000003CUL, 6, fpr32QIdx12M16D20FPR8Q
    "myh", 0xED000000003DUL, 6, fpr32QIdx12M16D20FPR8Q
    "mad", 0xED000000003EUL, 6, fpr32QIdx12M16D20FPR8Q
    "msd", 0xED000000003FUL, 6, fpr32QIdx12M16D20FPR8Q
    "sldt", 0xED0000000040UL, 6, fpr32QIdx12M16D20FPR8Q
    "srdt", 0xED0000000041UL, 6, fpr32QIdx12M16D20FPR8Q
    "slxt", 0xED0000000048UL, 6, fpr32QIdx12M16D20FPR8Q
    "srxt", 0xED0000000049UL, 6, fpr32QIdx12M16D20FPR8Q
    "tmy", 0xEB0000000051UL, 6, m16D20LUImm8to15Q
    "mviy", 0xEB0000000052UL, 6, m16D20LUImm8to15Q
    "niy", 0xEB0000000054UL, 6, m16D20LUImm8to15Q
    "cliy", 0xEB0000000055UL, 6, m16D20LUImm8to15Q
    "oiy", 0xEB0000000056UL, 6, m16D20LUImm8to15Q
    "xiy", 0xEB0000000057UL, 6, m16D20LUImm8to15Q
    "asi", 0xEB000000006AUL, 6, m16D20LSImm8to15Q
    "alsi", 0xEB000000006EUL, 6, m16D20LUImm8to15Q
    "lpswey", 0xEB0000000071UL, 6, m16D20L
    "agsi", 0xEB000000007AUL, 6, m16D20LSImm8to15Q
    "algsi", 0xEB000000007EUL, 6, m16D20LUImm8to15Q
    "vlip", 0xE60000000049UL, 6, vr8QUImmUpperQUImm4
    "vcvd", 0xE60000000058UL, 6, vr8QGR12QUImm8Mask24
    "vsrp", 0xE60000000059UL, 6, vr8QVR12QUImm8sMask24
    "vcvdg", 0xE6000000005AUL, 6, vr8QGR12QUImm8Mask24
    "vpsop", 0xE6000000005BUL, 6, vr8QVR12QUImm8sMask24
    "vpkzr", 0xE60000000070UL, 6, vr8QVR12QVR16QUImm8Mask24
    "vap", 0xE60000000071UL, 6, vr8QVR12QVR16QUImm8Mask24
    "vsrpr", 0xE60000000072UL, 6, vr8QVR12QVR16QUImm8Mask24
    "vsp", 0xE60000000073UL, 6, vr8QVR12QVR16QUImm8Mask24
    "vmp", 0xE60000000078UL, 6, vr8QVR12QVR16QUImm8Mask24
    "vmsp", 0xE60000000079UL, 6, vr8QVR12QVR16QUImm8Mask24
    "vdp", 0xE6000000007AUL, 6, vr8QVR12QVR16QUImm8Mask24
    "vrp", 0xE6000000007BUL, 6, vr8QVR12QVR16QUImm8Mask24
    "vsdp", 0xE6000000007EUL, 6, vr8QVR12QVR16QUImm8Mask24
    "vleib", 0xE70000000040UL, 6, vr8QUImm16Mask32
    "vleih", 0xE70000000041UL, 6, vr8QUImm16Mask32
    "vleig", 0xE70000000042UL, 6, vr8QUImm16Mask32
    "vleif", 0xE70000000043UL, 6, vr8QUImm16Mask32
    "vgbm", 0xE70000000044UL, 6, vr8QUImm16
    "vrepi", 0xE70000000045UL, 6, vr8QUImm16Mask32
    "vgm", 0xE70000000046UL, 6, vr8QUImm8sMask32
    "vftci", 0xE7000000004AUL, 6, vr8QVR12QUImm12Mask32Mask28
    "vrep", 0xE7000000004DUL, 6, vr8QUImmUpperVR12QMask32
    "verim", 0xE70000000072UL, 6, vr8QVR12QVR16QUImm8Mask32
    "vsldb", 0xE70000000077UL, 6, vr8QVR12QVR16QUImm8
    "vsld", 0xE70000000086UL, 6, vr8QVR12QVR16QUImm8
    "vsrd", 0xE70000000087UL, 6, vr8QVR12QVR16QUImm8
    "vcvb", 0xE60000000050UL, 6, gr8QVR12QMask24Mask28
    "vclzdp", 0xE60000000051UL, 6, vr8QVR12QMask24
    "vcvbg", 0xE60000000052UL, 6, gr8QVR12QMask24Mask28
    "vupkzh", 0xE60000000054UL, 6, vr8QVR12QMask24
    "vcnf", 0xE60000000055UL, 6, vr8QVR12QMask32Mask28
    "vclfnh", 0xE60000000056UL, 6, vr8QVR12QMask32Mask28
    "vupkzl", 0xE6000000005CUL, 6, vr8QVR12QMask24
    "vcfn", 0xE6000000005DUL, 6, vr8QVR12QMask32Mask28
    "vclfnl", 0xE6000000005EUL, 6, vr8QVR12QMask32Mask28
    "vtp", 0xE6000000005FUL, 6, vr12Q
    "vschp", 0xE60000000074UL, 6, vr8QVR12QVR16QMask32Mask24
    "vcrnf", 0xE60000000075UL, 6, vr8QVR12QVR16QMask32Mask28
    "vcp", 0xE60000000077UL, 6, vr12QVR16QMask24
    "vscshp", 0xE6000000007CUL, 6, vr8QVR12QVR16Q
    "vcsph", 0xE6000000007DUL, 6, vr8QVR12QVR16QMask24
    "vpopct", 0xE70000000050UL, 6, vr8QVR12QMask32
    "vctz", 0xE70000000052UL, 6, vr8QVR12QMask32
    "vclz", 0xE70000000053UL, 6, vr8QVR12QMask32
    "vlr", 0xE70000000056UL, 6, vr8QVR12Q
    "vistr", 0xE7000000005CUL, 6, vr8QVR12QMask32Mask24
    "vseg", 0xE7000000005FUL, 6, vr8QVR12QMask32
    "vmrl", 0xE70000000060UL, 6, vr8QVR12QVR16QMask32
    "vmrh", 0xE70000000061UL, 6, vr8QVR12QVR16QMask32
    "vlvgp", 0xE70000000062UL, 6, vr8QGR12QGR16Q
    "vsum", 0xE70000000064UL, 6, vr8QVR12QVR16QMask32
    "vsumg", 0xE70000000065UL, 6, vr8QVR12QVR16QMask32
    "vcksm", 0xE70000000066UL, 6, vr8QVR12QVR16Q
    "vsumq", 0xE70000000067UL, 6, vr8QVR12QVR16QMask32
    "vn", 0xE70000000068UL, 6, vr8QVR12QVR16Q
    "vnc", 0xE70000000069UL, 6, vr8QVR12QVR16Q
    "vo", 0xE7000000006AUL, 6, vr8QVR12QVR16Q
    "vno", 0xE7000000006BUL, 6, vr8QVR12QVR16Q
    "vnx", 0xE7000000006CUL, 6, vr8QVR12QVR16Q
    "vx", 0xE7000000006DUL, 6, vr8QVR12QVR16Q
    "vnn", 0xE7000000006EUL, 6, vr8QVR12QVR16Q
    "voc", 0xE7000000006FUL, 6, vr8QVR12QVR16Q
    "veslv", 0xE70000000070UL, 6, vr8QVR12QVR16QMask32
    "verllv", 0xE70000000073UL, 6, vr8QVR12QVR16QMask32
    "vsl", 0xE70000000074UL, 6, vr8QVR12QVR16Q
    "vslb", 0xE70000000075UL, 6, vr8QVR12QVR16Q
    "vesrlv", 0xE70000000078UL, 6, vr8QVR12QVR16QMask32
    "vesrav", 0xE7000000007AUL, 6, vr8QVR12QVR16QMask32
    "vsrl", 0xE7000000007CUL, 6, vr8QVR12QVR16Q
    "vsrlb", 0xE7000000007DUL, 6, vr8QVR12QVR16Q
    "vsra", 0xE7000000007EUL, 6, vr8QVR12QVR16Q
    "vsrab", 0xE7000000007FUL, 6, vr8QVR12QVR16Q
    "vfee", 0xE70000000080UL, 6, vr8QVR12QVR16QMask32Mask24
    "vfene", 0xE70000000081UL, 6, vr8QVR12QVR16QMask32Mask24
    "vfae", 0xE70000000082UL, 6, vr8QVR12QVR16QMask32Mask24
    "vpdi", 0xE70000000084UL, 6, vr8QVR12QVR16QMask32
    "vbperm", 0xE70000000085UL, 6, vr8QVR12QVR16Q
    "vstrc", 0xE7000000008AUL, 6, vr8QVR12QVR16QVR32QMask20Mask24
    "vstrs", 0xE7000000008BUL, 6, vr8QVR12QVR16QVR32QMask20Mask24
    "vperm", 0xE7000000008CUL, 6, vr8QVR12QVR16QVR32Q
    "vsel", 0xE7000000008DUL, 6, vr8QVR12QVR16QVR32Q
    "vfms", 0xE7000000008EUL, 6, vr8QVR12QVR16QVR32QMask28Mask20
    "vfma", 0xE7000000008FUL, 6, vr8QVR12QVR16QVR32QMask28Mask20
    "vpk", 0xE70000000094UL, 6, vr8QVR12QVR16QMask32
    "vpkls", 0xE70000000095UL, 6, vr8QVR12QVR16QMask32Mask24
    "vpks", 0xE70000000097UL, 6, vr8QVR12QVR16QMask32Mask24
    "vfnms", 0xE7000000009EUL, 6, vr8QVR12QVR16QVR32QMask28Mask20
    "vfnma", 0xE7000000009FUL, 6, vr8QVR12QVR16QVR32QMask28Mask20
    "vmlh", 0xE700000000A1UL, 6, vr8QVR12QVR16QMask32
    "vml", 0xE700000000A2UL, 6, vr8QVR12QVR16QMask32
    "vmh", 0xE700000000A3UL, 6, vr8QVR12QVR16QMask32
    "vmle", 0xE700000000A4UL, 6, vr8QVR12QVR16QMask32
    "vmlo", 0xE700000000A5UL, 6, vr8QVR12QVR16QMask32
    "vme", 0xE700000000A6UL, 6, vr8QVR12QVR16QMask32
    "vmo", 0xE700000000A7UL, 6, vr8QVR12QVR16QMask32
    "vmalh", 0xE700000000A9UL, 6, vr8QVR12QVR16QVR32QMask20
    "vmal", 0xE700000000AAUL, 6, vr8QVR12QVR16QVR32QMask20
    "vmah", 0xE700000000ABUL, 6, vr8QVR12QVR16QVR32QMask20
    "vmale", 0xE700000000ACUL, 6, vr8QVR12QVR16QVR32QMask20
    "vmalo", 0xE700000000ADUL, 6, vr8QVR12QVR16QVR32QMask20
    "vmae", 0xE700000000AEUL, 6, vr8QVR12QVR16QVR32QMask20
    "vmao", 0xE700000000AFUL, 6, vr8QVR12QVR16QVR32QMask20
    "vgfm", 0xE700000000B4UL, 6, vr8QVR12QVR16QMask32
    "vmsl", 0xE700000000B8UL, 6, vr8QVR12QVR16QVR32QMask20Mask24
    "vaccc", 0xE700000000B9UL, 6, vr8QVR12QVR16QVR32Q
    "vac", 0xE700000000BBUL, 6, vr8QVR12QVR16QVR32QMask20
    "vgfma", 0xE700000000BCUL, 6, vr8QVR12QVR16QVR32QMask20
    "vsbcbi", 0xE700000000BDUL, 6, vr8QVR12QVR16QVR32QMask20
    "vsbi", 0xE700000000BFUL, 6, vr8QVR12QVR16QVR32QMask20
    "vclfp", 0xE700000000C0UL, 6, vr8QVR12QMask32Mask28Mask24
    "vcfpl", 0xE700000000C1UL, 6, vr8QVR12QMask32Mask28Mask24
    "vcsfp", 0xE700000000C2UL, 6, vr8QVR12QMask32Mask28Mask24
    "vcfps", 0xE700000000C3UL, 6, vr8QVR12QMask32Mask28Mask24
    "vfll", 0xE700000000C4UL, 6, vr8QVR12QMask32Mask28
    "vflr", 0xE700000000C5UL, 6, vr8QVR12QMask32Mask28Mask24
    "vfi", 0xE700000000C7UL, 6, vr8QVR12QMask32Mask28Mask24
    "wfk", 0xE700000000CAUL, 6, vr8QVR12QMask32Mask28
    "wfc", 0xE700000000CBUL, 6, vr8QVR12QMask32Mask28
    "vfpso", 0xE700000000CCUL, 6, vr8QVR12QMask32Mask28Mask24
    "vfsq", 0xE700000000CEUL, 6, vr8QVR12QMask32Mask28
    "vupll", 0xE700000000D4UL, 6, vr8QVR12QMask32
    "vuplh", 0xE700000000D5UL, 6, vr8QVR12QMask32
    "vupl", 0xE700000000D6UL, 6, vr8QVR12QMask32
    "vuph", 0xE700000000D7UL, 6, vr8QVR12Q
    "vtm", 0xE700000000D8UL, 6, vr8QVR12QMask32
    "vecl", 0xE700000000D9UL, 6, vr8QVR12QMask32
    "vec", 0xE700000000DBUL, 6, vr8QVR12QMask32
    "vlc", 0xE700000000DEUL, 6, vr8QVR12QMask32
    "vlp", 0xE700000000DFUL, 6, vr8QVR12QMask32
    "vfs", 0xE700000000E2UL, 6, vr8QVR12QMask32
    "vfa", 0xE700000000E3UL, 6, vr8QVR12QVR16QMask32Mask28
    "vfd", 0xE700000000E5UL, 6, vr8QVR12QVR16QMask32Mask28
    "vfm", 0xE700000000E7UL, 6, vr8QVR12QVR16QMask32Mask28
    "vfce", 0xE700000000E8UL, 6, vr8QVR12QVR16QMask32Mask28Mask24
    "vfche", 0xE700000000EAUL, 6, vr8QVR12QVR16QMask32Mask28Mask24
    "vfch", 0xE700000000EBUL, 6, vr8QVR12QVR16QMask32Mask28Mask24
    "vfmin", 0xE700000000EEUL, 6, vr8QVR12QVR16QMask32Mask28Mask24
    "vfmax", 0xE700000000EFUL, 6, vr8QVR12QVR16QMask32Mask28Mask24
    "vavgl", 0xE700000000F0UL, 6, vr8QVR12QVR16QMask32
    "vacc", 0xE700000000F1UL, 6, vr8QVR12QVR16QMask32
    "vavg", 0xE700000000F2UL, 6, vr8QVR12QVR16QMask32
    "va", 0xE700000000F3UL, 6, vr8QVR12QVR16QMask32
    "vscbi", 0xE700000000F5UL, 6, vr8QVR12QVR16QMask32
    "vs", 0xE700000000F7UL, 6, vr8QVR12QVR16QMask32
    "vceq", 0xE700000000F8UL, 6, vr8QVR12QVR16QMask32Mask24
    "vchl", 0xE700000000F9UL, 6, vr8QVR12QVR16QMask32Mask24
    "vch", 0xE700000000FBUL, 6, vr8QVR12QVR16QMask32Mask24
    "vmnl", 0xE700000000FCUL, 6, vr8QVR12QVR16QMask32
    "vmxl", 0xE700000000FDUL, 6, vr8QVR12QVR16QMask32
    "vmn", 0xE700000000FEUL, 6, vr8QVR12QVR16QMask32
    "vmx", 0xE700000000FFUL, 6, vr8QVR12QVR16QMask32
    "vlrlr", 0xE60000000037UL, 6, vr32QM16D20GR12Q
    "vstrlr", 0xE6000000003FUL, 6, vr32QM16D20GR12Q
    "vlgv", 0xE70000000021UL, 6, gr8QM16D20VR12QMask32
    "vlvg", 0xE70000000022UL, 6, vr8QM16D20GR12QMask32
    "vesl", 0xE70000000030UL, 6, vr8QM16D20VR12QMask32
    "verll", 0xE70000000033UL, 6, vr8QM16D20VR12QMask32
    "vlm", 0xE70000000036UL, 6, vr8QM16D20VR12QMask32
    "vll", 0xE70000000037UL, 6, vr8QM16D20GR12Q
    "vesrl", 0xE70000000038UL, 6, vr8QM16D20VR12QMask32
    "vesra", 0xE7000000003AUL, 6, vr8QM16D20VR12QMask32
    "vstm", 0xE7000000003EUL, 6, vr8QM16D20VR12QMask32
    "vstl", 0xE7000000003FUL, 6, vr8QM16D20GR12Q
    "vgeg", 0xE70000000012UL, 6, vr8QVIdxM16D20Mask32
    "vgef", 0xE70000000013UL, 6, vr8QVIdxM16D20Mask32
    "vsceg", 0xE7000000001AUL, 6, vr8QVIdxM16D20Mask32
    "vscef", 0xE7000000001BUL, 6, vr8QVIdxM16D20Mask32
    "vlebrh", 0xE60000000001UL, 6, vr8QIdxM16D20Mask32
    "vlebrg", 0xE60000000002UL, 6, vr8QIdxM16D20Mask32
    "vlebrf", 0xE60000000003UL, 6, vr8QIdxM16D20Mask32
    "vllebrz", 0xE60000000004UL, 6, vr8QIdxM16D20Mask32
    "vlbrrep", 0xE60000000005UL, 6, vr8QIdxM16D20Mask32
    "vlbr", 0xE60000000006UL, 6, vr8QIdxM16D20Mask32
    "vler", 0xE60000000007UL, 6, vr8QIdxM16D20Mask32
    "vstebrh", 0xE60000000009UL, 6, vr8QIdxM16D20Mask32
    "vstebrg", 0xE6000000000AUL, 6, vr8QIdxM16D20Mask32
    "vstebrf", 0xE6000000000BUL, 6, vr8QIdxM16D20Mask32
    "vster", 0xE6000000000FUL, 6, vr8QIdxM16D20Mask32
    "vleb", 0xE70000000000UL, 6, vr8QIdxM16D20Mask32
    "vleh", 0xE70000000001UL, 6, vr8QIdxM16D20Mask32
    "vleg", 0xE70000000002UL, 6, vr8QIdxM16D20Mask32
    "vlef", 0xE70000000003UL, 6, vr8QIdxM16D20Mask32
    "vllez", 0xE70000000004UL, 6, vr8QIdxM16D20Mask32
    "vlrep", 0xE70000000005UL, 6, vr8QIdxM16D20Mask32
    "vl", 0xE70000000006UL, 6, vr8QIdxM16D20Mask32
    "vlbb", 0xE70000000007UL, 6, vr8QIdxM16D20Mask32
    "vsteb", 0xE70000000008UL, 6, vr8QIdxM16D20Mask32
    "vsteh", 0xE70000000009UL, 6, vr8QIdxM16D20Mask32
    "vsteg", 0xE7000000000AUL, 6, vr8QIdxM16D20Mask32
    "vstef", 0xE7000000000BUL, 6, vr8QIdxM16D20Mask32
    "vst", 0xE7000000000EUL, 6, vr8QIdxM16D20Mask32
    "vpkz", 0xE60000000034UL, 6, vr32QM16D20UImm8
    "vlrl", 0xE60000000035UL, 6, vr32QM16D20UImm8
    "vupkz", 0xE6000000003CUL, 6, vr32QM16D20UImm8
    "vstrl", 0xE6000000003DUL, 6, vr32QM16D20UImm8 ]

/// Builds the lookup from a name to what an instruction of that name encodes
/// as. Each assembler builds its own and lets it go when it goes, rather than
/// the rows living for as long as the process does.
let buildTable () =
  rows
  |> List.map (fun (name, bits, length, layout) ->
    name,
    { Bits = bits
      Length = length
      Layout = layout
      Bits20 = bits20Of name
      Esa390 = Set.contains name esa390 })
  |> Map.ofList

// vim: set tw=80 sts=2 sw=2:

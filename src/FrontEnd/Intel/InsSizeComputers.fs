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

module internal B2R2.FrontEnd.Intel.InsSizeComputers

open B2R2
open B2R2.FrontEnd.BinLifter

/// AHR12LIb ALIb ALOb ALR8LIb BHR15LIb BLR11LIb CHR13LIb CLR9LIb DHR14LIb
/// DLR10LIb Eb Eb1 EbCL EbGb EbIb GbEb IbAL Jb ObAL XbYb
type Byte () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 8<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 8<rt>
    phlp.RegSize <- 8<rt>
    phlp.OperationSize <- 8<rt>

/// GwMw EvSw EwGw MwGw SwEw
type Word () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 16<rt>
    phlp.RegSize <- 16<rt>
    phlp.OperationSize <- 16<rt>

/// ALDX DXAL DXEAX EAX EAXDX EAXIb EBP EBX ECX EDI EDX ESI ESP Ev Ev1 EvCL EvGv
/// EvGvCL EvGvIb EvIb EvSIb EvSIz EyGy GvEv GvEvSIb GvEvSIz GvEy GvMa GvMv
/// GyByEy GyEy GyEyBy GyEyIb GyMy Ib IbEAX Iw IwIb Mv MyGy Mz OvRAX RAXIv RAXOv
/// RAXrAX RAXrBP RAXrBX RAXrCX RAXrDI RAXrDX RAXrSI RAXrSP RAXSIz RAXz RBPIv
/// RBPz RBXIv RBXz RCXIv RCXz RDIIv RDIz RDXIv RDXz RSIIv RSIz RSPIv RSPz Rv Ry
/// SIb SIz
type Def () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// HxUxIb MpdVpd MpsVps MxVx MZxzVZxz VpdHpdWpd VpdHpdWpdIb VpdWpd VpsHpsWps
/// VpsHpsWpsIb VpsWps VsdHsdWsdIb VssHssWssIb VxHxWsd VxHxWss VxHxWx VxHxWxIb
/// VxMx VxWx VxWxIb VZxzWZxz WpdVpd WpsVps WsdHxVsd WssHxVss WxVx WZxzVZxz
type VecDef () =
  inherit InsSizeComputer ()
  override _.Render (phlp: ParsingHelper) _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- vLen
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- vLen
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

type VecDefRC () =
  inherit InsSizeComputer ()
  override _.RenderEVEX (span, phlp: ParsingHelper, _) =
    let vInfo = Option.get phlp.VEXInfo
    let vLen = vInfo.VectorLength
    let modRM = phlp.PeekByte span
    let evex = Option.get vInfo.EVEXPrx
    if Operands.modIsReg modRM && evex.B = 1uy then
      phlp.MemEffOprSize <- 512<rt>
      phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
      phlp.MemEffRegSize <- 512<rt>
      phlp.RegSize <- 512<rt>
      phlp.OperationSize <- 512<rt>
    else
      phlp.MemEffOprSize <- vLen
      phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
      phlp.MemEffRegSize <- vLen
      phlp.RegSize <- vLen
      phlp.OperationSize <- vLen

/// GvEd Md
type DV () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// Md
type D () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- 32<rt>

/// Ew Mw
type MemW () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 16<rt>
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- 16<rt>

/// CS ES DS FS GS SS
type RegW () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- 16<rt>
    phlp.OperationSize <- 16<rt>

/// GvEw
type WV () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 16<rt>
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// RAX RCX RDX RBX RSP RBP RSI RDI Jz
type D64 () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// GzMp
type PZ () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    let oprSize =
      if phlp.Prefixes &&& Prefix.OPSIZE = Prefix.OPSIZE then 32<rt>
      else 48<rt>
    phlp.MemEffOprSize <- oprSize
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// EdVdqIb
type DDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 32<rt>

/// MdqVdq VdqHdqUdq VdqHdqWdqIb VdqMdq VdqUdq VdqWdq VdqWdqIb WdqVdq
type DqDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// VdqWdqd VdqMd VdqHdqWdqd VdqWdqdIb MdVdq VdqHdqUdqdIb
type DqdDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// WdqdVdq MdVdq
type DqdDqMR () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 32<rt>

/// VdqWdqq VdqMq VdqHdqMq VdqHdqWdqq VdqWdqqIb WdqqVdq MqVdq
type DqqDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// WdqqVdq MqVdq
type DqqDqMR () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 64<rt>

/// VxWxq
type XqX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (vLen, effAddrSz, vLen)
      | _ -> Terminator.futureFeature () (* EVEX *)
    phlp.MemEffOprSize <- mopr
    phlp.MemEffAddrSize <- maddr
    phlp.MemEffRegSize <- mreg
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// BNBNdqq BNdqqBN
type DqqDqWS () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    let struct (mopr, maddr, mreg) =
      match phlp.WordSize with
      | WordSize.Bit32 -> struct (64<rt>, effAddrSz, 128<rt>)
      | WordSize.Bit64 -> struct (128<rt>, effAddrSz, 128<rt>)
      | _ -> raise ParsingFailureException
    phlp.MemEffOprSize <- mopr
    phlp.MemEffAddrSize <- maddr
    phlp.MemEffRegSize <- mreg
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- effOprSz

/// BNEv BNMv BNMib VdqEy VssHssEy VsdHsdEy
type VyDq () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// EyVdq MibBN
type VyDqMR () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- effOprSz

/// RyCd RyDd CdRy DdRy
type DY () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    let effRegSz = WordSize.toRegType phlp.WordSize
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effRegSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// VdqQpi VdqNq
type QDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 64<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// PpiWdqq
type DqqQ () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 64<rt>
    phlp.OperationSize <- 64<rt>

/// PpiWdq PqUdq
type DqQ () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 64<rt>
    phlp.OperationSize <- 64<rt>

/// GyWdqd
type DqdY () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// GyWdqq
type DqqY () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// GyUdq
type DqY () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// UdqIb Mdq
type Dq () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// PqQd
type DQ () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 64<rt>
    phlp.RegSize <- 64<rt>
    phlp.OperationSize <- 64<rt>

/// PqQq PqQqIb QqPq MqPq
type QQ () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 64<rt>
    phlp.RegSize <- 64<rt>
    phlp.OperationSize <- 64<rt>

/// EyPq
type YQ () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- 64<rt>
    phlp.OperationSize <- effOprSz

/// PqEy
type YQRM () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- 64<rt>
    phlp.OperationSize <- 64<rt>

/// PqEdwIb
type DwQ () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- 64<rt>
    phlp.OperationSize <- 64<rt>

/// VdqEdwIb VdqHdqEdwIb
type DwDq () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- effOprSz

/// EdwVdqIb
type DwDqMR () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 16<rt>

/// GdNqIb GdNq
type QD () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 64<rt>
    phlp.RegSize <- 32<rt>
    phlp.OperationSize <- 32<rt>

/// GdUdqIb GdUdq
type Dqd () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 32<rt>
    phlp.OperationSize <- 32<rt>

/// VxHxWdq
type XDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VdqWx
type DqX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- vLen
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- vLen
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- vLen

/// GdUx
type XD () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- vLen
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- vLen
    phlp.RegSize <- 32<rt>
    phlp.OperationSize <- 32<rt>

/// VxWdqqdq
type DqqdqX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (128<rt>, effAddrSz, 128<rt>)
      | _ -> Terminator.futureFeature () (* EVEX *)
    phlp.MemEffOprSize <- mopr
    phlp.MemEffAddrSize <- maddr
    phlp.MemEffRegSize <- mreg
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VxWdqdq
type DqddqX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (32<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
      | _ -> Terminator.futureFeature () (* EVEX *)
    phlp.MemEffOprSize <- mopr
    phlp.MemEffAddrSize <- maddr
    phlp.MemEffRegSize <- mreg
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VdqWdqw
type DqwDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// VxWdqw
type DqwX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VqqMdq VqqHqqWdqIb
type DqQqq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 256<rt>
    phlp.OperationSize <- 256<rt>

/// VxWdqb
type DqbX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 8<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VdqEdbIb VdqHdqEdbIb
type DbDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 8<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// GvEb Mb
type BV () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 8<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 8<rt>
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// NqIb Mq
type Q () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 64<rt>
    phlp.RegSize <- 64<rt>
    phlp.OperationSize <- 64<rt>

/// Ms
type S () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let effOprSz = if phlp.WordSize = WordSize.Bit32 then 48<rt> else 80<rt>
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// VxMd
type DX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VZxzWdqd VxHxWdqd
type DqdXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VxHxWdqq
type DqqX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// Ap Ep Mp
type P () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    let struct (regSz, oprSz) =
      if effOprSz = 16<rt> then struct (16<rt>, 32<rt>)
      elif effOprSz = 32<rt> then struct (32<rt>, 48<rt>)
      else struct (64<rt>, 80<rt>)
    phlp.MemEffOprSize <- oprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- regSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- oprSz

/// GvMp
type PRM () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    let struct (regSz, oprSz) =
      if effOprSz = 16<rt> then struct (16<rt>, 32<rt>)
      elif effOprSz = 32<rt> then struct (32<rt>, 48<rt>)
      else struct (64<rt>, 80<rt>)
    phlp.MemEffOprSize <- oprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- regSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// VZxzWxq
type XqXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (64<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (128<rt>, effAddrSz, 128<rt>)
      | 512<rt> -> struct (256<rt>, effAddrSz, 256<rt>)
      | _ -> raise ParsingFailureException
    phlp.MemEffOprSize <- mopr
    phlp.MemEffAddrSize <- maddr
    phlp.MemEffRegSize <- mreg
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VZxzWx
type XXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (vLen, effAddrSz, vLen)
      | 256<rt> -> struct (128<rt>, effAddrSz, 128<rt>)
      | 512<rt> -> struct (256<rt>, effAddrSz, 256<rt>)
      | _ -> raise ParsingFailureException
    phlp.MemEffOprSize <- mopr
    phlp.MemEffAddrSize <- maddr
    phlp.MemEffRegSize <- mreg
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VxWZxz
type XzX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    let regSize =
      match vLen with
      | 128<rt> -> vLen
      | 256<rt> -> 128<rt>
      | 512<rt> -> 256<rt>
      | _ -> raise ParsingFailureException
    phlp.MemEffOprSize <- vLen
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- vLen
    phlp.RegSize <- regSize
    phlp.OperationSize <- regSize

/// VZxzHxWZxz VZxzHxWZxzIb
type XzXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- vLen
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- vLen
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VqqWdqq
type DqqQq () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 256<rt>
    phlp.OperationSize <- 256<rt>

/// VZxzWdqq
type DqqXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// WqqVZxz WZqqVZxzIb WqqVZxzIb VqqHqqWqq
type QqXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 256<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 256<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- 256<rt>

/// VZxzHxWqqIb
type QqXzRM () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 256<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 256<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VxWdqd
type DqdX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VZxzRd
type DXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VZxzRq
type QXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 64<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// WdqVqqIb
type DqQq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 256<rt>
    phlp.OperationSize <- 128<rt>

/// WdqVZxzIb
type DqXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- 128<rt>

/// VdqHdqEyIb
type YDq () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// VdqHdqEyIb
type Qq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffOprSize <- 256<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 256<rt>
    phlp.RegSize <- 256<rt>
    phlp.OperationSize <- 256<rt>

/// VxWdqwd
type DqwdX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    let struct (mopr, maddr, mreg) =
      match vLen with
      | 128<rt> -> struct (16<rt>, effAddrSz, 128<rt>)
      | 256<rt> -> struct (32<rt>, effAddrSz, 128<rt>)
      | _ -> Terminator.futureFeature () (* EVEX *)
    phlp.MemEffOprSize <- mopr
    phlp.MemEffAddrSize <- maddr
    phlp.MemEffRegSize <- mreg
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// EyGy - WordSize
type Y () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = if phlp.WordSize = WordSize.Bit64 then 64<rt> else 32<rt>
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// GyUps GyUpd
type YP () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- vLen
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// KnKm MKn
type QQb () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 8<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- 8<rt>

/// KnKm MKn
type QQd () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- 32<rt>

/// KnKm MKn
type QQw () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- 16<rt>

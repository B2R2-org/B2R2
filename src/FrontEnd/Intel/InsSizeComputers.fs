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
type SzByte () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 8<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 8<rt>
    phlp.RegSize <- 8<rt>
    phlp.OperationSize <- 8<rt>

/// GwMw EvSw EwGw MwGw SwEw
type SzWord () =
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
type SzDef () =
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
type SzVecDef () =
  inherit InsSizeComputer ()
  override _.Render (phlp: ParsingHelper) _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- vLen
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- vLen
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

type SzVecDefRC () =
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
type SzDV () =
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
type SzD () =
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
type SzMemW () =
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
type SzRegW () =
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
type SzWV () =
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
type SzD64 () =
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
type SzPZ () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    let oprSize =
      if phlp.Prefixes &&& Prefix.PrxOPSIZE = Prefix.PrxOPSIZE then 32<rt>
      else 48<rt>
    phlp.MemEffOprSize <- oprSize
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// EdVdqIb
type SzDDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 32<rt>

/// MdqVdq VdqHdqUdq VdqHdqWdqIb VdqMdq VdqUdq VdqWdq VdqWdqIb WdqVdq
type SzDqDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// VdqWdqd VdqMd VdqHdqWdqd VdqWdqdIb MdVdq VdqHdqUdqdIb
type SzDqdDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// WdqdVdq MdVdq
type SzDqdDqMR () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 32<rt>

/// VdqWdqq VdqMq VdqHdqMq VdqHdqWdqq VdqWdqqIb WdqqVdq MqVdq
type SzDqqDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// WdqqVdq MqVdq
type SzDqqDqMR () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 64<rt>

/// VxWxq
type SzXqX () =
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
type SzDqqDqWS () =
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
type SzVyDq () =
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
type SzVyDqMR () =
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
type SzDY () =
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
type SzQDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 64<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// PpiWdqq
type SzDqqQ () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 64<rt>
    phlp.OperationSize <- 64<rt>

/// PpiWdq PqUdq
type SzDqQ () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 64<rt>
    phlp.OperationSize <- 64<rt>

/// GyWdqd
type SzDqdY () =
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
type SzDqqY () =
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
type SzDqY () =
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
type SzDq () =
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
type SzDQ () =
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
type SzQQ () =
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
type SzYQ () =
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
type SzYQRM () =
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
type SzDwQ () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- 64<rt>
    phlp.OperationSize <- 64<rt>

/// VdqEdwIb VdqHdqEdwIb
type SzDwDq () =
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
type SzDwDqMR () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 16<rt>

/// GdNqIb GdNq
type SzQD () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 64<rt>
    phlp.RegSize <- 32<rt>
    phlp.OperationSize <- 32<rt>

/// GdUdqIb GdUdq
type SzDqd () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 32<rt>
    phlp.OperationSize <- 32<rt>

/// VxHxWdq
type SzXDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VdqWx
type SzDqX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- vLen
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- vLen
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- vLen

/// GdUx
type SzXD () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- vLen
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- vLen
    phlp.RegSize <- 32<rt>
    phlp.OperationSize <- 32<rt>

/// VxWdqqdq
type SzDqqdqX () =
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
type SzDqddqX () =
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
type SzDqwDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// VxWdqw
type SzDqwX () =
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
type SzDqQqq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 256<rt>
    phlp.OperationSize <- 256<rt>

/// VxWdqb
type SzDqbX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 8<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VdqEdbIb VdqHdqEdbIb
type SzDbDq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 8<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- 128<rt>
    phlp.OperationSize <- 128<rt>

/// GvEb Mb
type SzBV () =
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
type SzQ () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 64<rt>
    phlp.RegSize <- 64<rt>
    phlp.OperationSize <- 64<rt>

/// Ms
type SzS () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let effOprSz = if phlp.WordSize = WordSize.Bit32 then 48<rt> else 80<rt>
    phlp.MemEffOprSize <- effOprSz
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- effOprSz

/// VxMd
type SzDX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VZxzWdqd VxHxWdqd
type SzDqdXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VxHxWdqq
type SzDqqX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// Ap Ep Mp
type SzP () =
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
type SzPRM () =
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
type SzXqXz () =
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
type SzXXz () =
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
type SzXzX () =
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
type SzXzXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- vLen
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- vLen
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VqqWdqq
type SzDqqQq () =
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
type SzDqqXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// WqqVZxz WZqqVZxzIb WqqVZxzIb VqqHqqWqq
type SzQqXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 256<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 256<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- 256<rt>

/// VZxzHxWqqIb
type SzQqXzRM () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 256<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 256<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VxWdqd
type SzDqdX () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VZxzRd
type SzDXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 32<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 32<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// VZxzRq
type SzQXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 64<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 64<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- vLen

/// WdqVqqIb
type SzDqQq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- 256<rt>
    phlp.OperationSize <- 128<rt>

/// WdqVZxzIb
type SzDqXz () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let vLen = (Option.get phlp.VEXInfo).VectorLength
    phlp.MemEffOprSize <- 128<rt>
    phlp.MemEffAddrSize <- ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffRegSize <- 128<rt>
    phlp.RegSize <- vLen
    phlp.OperationSize <- 128<rt>

/// VdqHdqEyIb
type SzYDq () =
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
type SzQq () =
  inherit InsSizeComputer ()
  override _.Render phlp _ =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    phlp.MemEffOprSize <- 256<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- 256<rt>
    phlp.RegSize <- 256<rt>
    phlp.OperationSize <- 256<rt>

/// VxWdqwd
type SzDqwdX () =
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
type SzY () =
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
type SzYP () =
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
type SzQQb () =
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
type SzQQd () =
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
type SzQQw () =
  inherit InsSizeComputer ()
  override _.Render phlp szCond =
    let effAddrSz = ParsingHelper.GetEffAddrSize phlp
    let effOprSz = ParsingHelper.GetEffOprSize phlp szCond
    phlp.MemEffOprSize <- 16<rt>
    phlp.MemEffAddrSize <- effAddrSz
    phlp.MemEffRegSize <- effOprSz
    phlp.RegSize <- effOprSz
    phlp.OperationSize <- 16<rt>

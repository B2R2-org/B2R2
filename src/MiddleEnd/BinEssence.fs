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

namespace B2R2.MiddleEnd

open B2R2.FrontEnd
open B2R2.BinCorpus
open B2R2.BinGraph

/// Represent the "essence" of a binary code. This is the primary data structure
/// for storing various information about a binary, such as its CFG, FileFormat
/// information, etc.
type BinEssence = {
  /// BInary handler.
  BinHandler: BinHandler
  /// The apparatus holds crucial machinery about binary code and their lifted
  /// statements. For example, it provides a convenient mapping from an address
  /// to the corresponding instruction and IR statements.
  Apparatus: Apparatus
  /// Super Control Flow Graph.
  SCFG: SCFG
}
with
  static member private Run hdl scfg app analyses =
    analyses
    |> List.fold (fun (scfg, app) (analysis: IAnalysis) ->
#if DEBUG
      printfn "[*] %s started." analysis.Name
#endif
      analysis.Run hdl scfg app) (scfg, app)

  static member private AnalyzeOnce hdl app (scfg: SCFG) analyses =
    BinEssence.Run hdl scfg { app with Modified = false } analyses

  static member private AnalyzeInLoop hdl app (scfg: SCFG) analyses =
    let scfg', app' =
      BinEssence.Run hdl scfg { app with Modified = false } analyses
    if not app'.Modified then
      { BinHandler = hdl
        Apparatus = app'
        SCFG = scfg' }
    else
#if DEBUG
      printfn "[*] Go to the next phase ..."
#endif
      let scfg' = SCFG (hdl, app')
      BinEssence.AnalyzeInLoop hdl app' scfg' analyses

  static member Init hdl postAnalyses =
    let oneTimeAnalyses =
      [ LibcAnalysis () :> IAnalysis
        EVMCodeCopyAnalysis () :> IAnalysis ]
#if DEBUG
    let startTime = System.DateTime.Now
#endif
    let app = Apparatus.init hdl
    let scfg = SCFG (hdl, app)
    let scfg, app = BinEssence.AnalyzeOnce hdl app scfg oneTimeAnalyses
#if DEBUG
    printfn "[*] Start post analysis."
#endif
    let ess = BinEssence.AnalyzeInLoop hdl app scfg postAnalyses
#if DEBUG
    let endTime = System.DateTime.Now
    endTime.Subtract(startTime).TotalSeconds
    |> printfn "[*] All done in %f sec."
#endif
    ess

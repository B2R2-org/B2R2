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
  static member private PostAnalysis hdl scfg app =
    [ (LibcAnalysis () :> IPostAnalysis, "LibC analysis")
      (EVMCodeCopyAnalysis () :> IPostAnalysis, "EVM codecopy analysis")
      (NoReturnAnalysis () :> IPostAnalysis, "NoReturn analysis") ]
    |> List.fold (fun app (analysis, name) ->
      printfn "[*] %s started." name
      analysis.Run hdl scfg app) app

  static member private Analysis hdl app (scfg: SCFG) analyzers =
#if DEBUG
    printfn "[*] Start post analysis."
#endif
    let app' = BinEssence.PostAnalysis hdl scfg { app with Modified = false }
    if not app'.Modified then
#if DEBUG
      printfn "[*] All done."
#endif
      { BinHandler = hdl
        Apparatus = app'
        SCFG = scfg }
    else
#if DEBUG
      printfn "[*] Go to the next phase ..."
#endif
      let scfg' = SCFG (hdl, app')
      BinEssence.Analysis hdl app' scfg' analyzers

  static member Init hdl =
    let app = Apparatus.init hdl
    let scfg = SCFG (hdl, app)
    BinEssence.Analysis hdl app scfg []

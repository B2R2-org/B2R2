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

module B2R2.RearEnd.Transformer.Compiler

open System.IO
open System.Text
open System.Reflection
open FSharp.Compiler.CodeAnalysis
open FSharp.Compiler.Symbols
open FSharp.Compiler.Text
open FSharp.Compiler.Interactive.Shell

let rec retrieveActionName = function
  | [ FSharpImplementationFileDeclaration.Entity (_, subDecls) ] ->
    retrieveActionName subDecls
  | FSharpImplementationFileDeclaration.Entity (e, _) :: _ ->
    e.FullName
  | _ -> invalidOp "An action should be defined in the file."

let retrieveAction filePath =
  let tmpPath = Path.GetTempFileName ()
  File.Copy (filePath, tmpPath, true)
  let checker = FSharpChecker.Create (keepAssemblyContents=true)
  let txt = SourceText.ofString (File.ReadAllText filePath)
  let projOptions, _ =
    checker.GetProjectOptionsFromScript (filePath, txt)
    |> Async.RunSynchronously
  let results =
    checker.ParseAndCheckProject projOptions
    |> Async.RunSynchronously
  File.Delete tmpPath
  let decls = results.AssemblyContents.ImplementationFiles[0].Declarations
  if decls.Length = 1 then decls |> retrieveActionName
  else invalidArg (nameof filePath) "An action should be defined in the file."

let compile filePath =
  if File.Exists filePath then
    let filePath = Path.GetFullPath filePath
    let actionName = retrieveAction filePath
    let dllPath = Assembly.GetEntryAssembly().Location
    let args = [| "fsi.exe"
                  "--noninteractive"
                  "--nologo"
                  "--gui-"
                  "--reference:" + dllPath |]
    use inStream = new StringReader ""
    use outStream = new StringWriter (StringBuilder ())
    use errStream = new StringWriter (StringBuilder ())
    let conf = FsiEvaluationSession.GetDefaultConfiguration ()
    let fsiSession =
      FsiEvaluationSession.Create (conf, args, inStream, outStream, errStream)
    fsiSession.EvalInteraction $"#load \"{filePath}\""
    match fsiSession.EvalExpressionNonThrowing $"{actionName} ()" with
    | Choice1Of2 (Some v), _ -> v.ReflectionType
    | Choice1Of2 None, _ -> invalidArg (nameof filePath) "No action found."
    | Choice2Of2 exn, diag ->
      printfn "%A, %A" exn diag; exit 1
  else
    invalidOp $"File not found: {filePath}"
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

namespace B2R2.MiddleEnd.SymEval

open System
open System.ComponentModel
open System.Diagnostics
open System.IO
open System.Text
open System.Threading.Tasks

type Z3CliOptions =
  { Executable: string option
    Timeout: int }

type private Z3ProcessOutput =
  { ExitCode: int
    Stdout: string
    Stderr: string }

/// Represents an SMT solver that communicates with Z3 through its CLI.
type Z3Solver(?options: Z3CliOptions) =
  static let defaultTimeout = 5000

  static let defaultOptions =
    { Executable = None
      Timeout = defaultTimeout }

  let options = defaultArg options defaultOptions

  let solverFailure failure = SolverFailure failure |> Error

  let z3ExitFailure exitCode stdout stderr =
    SolverNonZeroExit(exitCode, stdout, stderr) |> solverFailure

  let trySerialize fn =
    try fn () |> Ok with
    | :? ArgumentException as ex ->
      SolverSerializationFailure ex.Message |> solverFailure
    | :? InvalidOperationException as ex ->
      SolverSerializationFailure ex.Message |> solverFailure

  let isNullOrEmpty s = String.IsNullOrEmpty s

  let env name =
    match Environment.GetEnvironmentVariable name with
    | null | "" -> None
    | value -> Some value

  let containsPathSeparator (path: string) =
    path.IndexOfAny [| Path.DirectorySeparatorChar
                       Path.AltDirectorySeparatorChar |] >= 0

  let fileExistsWithExeFallback path =
    File.Exists path || File.Exists(path + ".exe")

  let isRunnable (fileName: string) =
    if Path.IsPathRooted fileName || containsPathSeparator fileName then
      fileExistsWithExeFallback fileName
    else
      match Environment.GetEnvironmentVariable "PATH" with
      | null | "" -> fileExistsWithExeFallback fileName
      | pathVar ->
        pathVar.Split Path.PathSeparator
        |> Array.exists (fun path ->
          Path.Combine(path, fileName) |> fileExistsWithExeFallback)

  let getExecutable () =
    match options.Executable with
    | Some executable when not (isNullOrEmpty executable) -> executable
    | _ ->
      match env "Z3_PATH" with
      | Some executable -> executable
      | None -> "z3"

  let makeStartInfo executable =
    let startInfo = ProcessStartInfo()
    startInfo.FileName <- executable
    startInfo.Arguments <- "-in"
    startInfo.UseShellExecute <- false
    startInfo.RedirectStandardInput <- true
    startInfo.RedirectStandardOutput <- true
    startInfo.RedirectStandardError <- true
    startInfo.CreateNoWindow <- true
    startInfo

  let startZ3 executable =
    try
      let proc = new Process()
      proc.StartInfo <- makeStartInfo executable
      if proc.Start() |> not then
        proc.Dispose()
        SolverStartFailure(executable, "Process.Start returned false.")
        |> solverFailure
      else Ok proc
    with
    | :? Win32Exception as ex ->
      SolverStartFailure(executable, ex.Message) |> solverFailure
    | :? InvalidOperationException as ex ->
      SolverStartFailure(executable, ex.Message) |> solverFailure

  let getRunnableExecutable () =
    let executable = getExecutable ()
    if not (isRunnable executable) then
      SolverNotFound executable |> solverFailure
    else Ok executable

  let killProcess (proc: Process) =
    try proc.Kill true with _ -> ()

  let makeTimeoutBudget timeout =
    let stopwatch = Stopwatch.StartNew()
    fun () -> max 0 (timeout - int stopwatch.ElapsedMilliseconds)

  let timeoutFailure () =
    SolverTimeout options.Timeout |> solverFailure

  let waitForExit (proc: Process) (remainingTimeout: unit -> int) =
    if proc.WaitForExit(remainingTimeout ()) then Ok()
    else
      killProcess proc
      timeoutFailure ()

  let waitTask (proc: Process) (remainingTimeout: unit -> int)
               (task: Task<'T>) =
    if task.Wait(remainingTimeout ()) then Ok task.Result
    else
      killProcess proc
      timeoutFailure ()

  let stdoutWithStatus (statusLine: string) (stdoutRest: string) =
    (StringBuilder().AppendLine(statusLine).Append(stdoutRest)).ToString()

  let finishZ3Output (proc: Process) remainingTimeout stdout
                     (stderrTask: Task<string>) =
    match waitForExit proc remainingTimeout with
    | Error e -> Error e
    | Ok() ->
      if proc.ExitCode = 0 then Ok stdout
      else z3ExitFailure proc.ExitCode stdout stderrTask.Result

  let runZ3Process (smtlib: string) =
    getRunnableExecutable ()
    |> Result.bind startZ3
    |> Result.bind (fun proc ->
      use proc = proc
      try
        let stdoutTask = proc.StandardOutput.ReadToEndAsync()
        let stderrTask = proc.StandardError.ReadToEndAsync()
        proc.StandardInput.Write smtlib
        proc.StandardInput.Close()
        match waitForExit proc (fun () -> options.Timeout) with
        | Ok() ->
          Ok { ExitCode = proc.ExitCode
               Stdout = stdoutTask.Result
               Stderr = stderrTask.Result }
        | Error e -> Error e
      with
      | :? IOException as ex ->
        SolverCommunicationFailure ex.Message |> solverFailure)

  let runZ3 smtlib =
    match runZ3Process smtlib with
    | Ok output when output.ExitCode = 0 -> Ok output.Stdout
    | Ok output -> z3ExitFailure output.ExitCode output.Stdout output.Stderr
    | Error e -> Error e

  let parseOutput stdout =
    match Z3OutputParser.parse stdout with
    | Ok output -> Ok output
    | Error(SolverFailure(SolverOutputParseFailure(msg, _))) ->
      SolverOutputParseFailure(msg, stdout) |> solverFailure
    | Error err -> Error err

  let parseStatusLine (line: string) =
    match line.Trim() with
    | "sat" -> Ok Sat
    | "unsat" -> Ok Unsat
    | "unknown" -> Ok Unknown
    | line ->
      SolverOutputParseFailure($"Unexpected z3 status: {line}", "")
      |> solverFailure

  let finishValueQuery (proc: Process) remainingTimeout statusLine stdoutRest
                       (stderrTask: Task<string>) onSuccess =
    let stdout = stdoutWithStatus statusLine stdoutRest
    finishZ3Output proc remainingTimeout stdout stderrTask
    |> Result.bind onSuccess

  let runZ3ValueQuery (prefix: string) (getValueCommand: string) =
    getRunnableExecutable ()
    |> Result.bind startZ3
    |> Result.bind (fun proc ->
      use proc = proc
      let remainingTimeout = makeTimeoutBudget options.Timeout
      try
        let stderrTask = proc.StandardError.ReadToEndAsync()
        proc.StandardInput.Write prefix
        proc.StandardInput.Flush()
        let statusTask = proc.StandardOutput.ReadLineAsync()
        match waitTask proc remainingTimeout statusTask with
        | Error e -> Error e
        | Ok statusLine ->
          match statusLine with
          | null ->
            proc.StandardInput.Close()
            SolverOutputParseFailure
              ("z3 terminated without a check-sat result.", "")
            |> solverFailure
          | statusLine ->
            match parseStatusLine statusLine with
            | Error e ->
              proc.StandardInput.Close()
              Error e
            | Ok Sat ->
              proc.StandardInput.WriteLine getValueCommand
              proc.StandardInput.Close()
              let stdoutRestTask = proc.StandardOutput.ReadToEndAsync()
              finishValueQuery proc remainingTimeout statusLine
                stdoutRestTask.Result stderrTask parseOutput
            | Ok status ->
              proc.StandardInput.Close()
              let stdoutRestTask = proc.StandardOutput.ReadToEndAsync()
              let onSuccess _ = Ok { Status = status; Values = [] }
              finishValueQuery proc remainingTimeout statusLine
                stdoutRestTask.Result stderrTask onSuccess
      with
      | :? IOException as ex ->
        SolverCommunicationFailure ex.Message |> solverFailure)

  let checkSat pathCondition =
    trySerialize (fun () -> SMTLibSerializer.serializeSatQuery pathCondition)
    |> Result.bind runZ3
    |> Result.bind parseOutput
    |> Result.map (fun output -> output.Status)

  let getValues pathCondition values =
    match trySerialize (fun () ->
            SMTLibSerializer.serializeValueQueryPrefix pathCondition values),
          trySerialize (fun () ->
            SMTLibSerializer.serializeGetValueCommand values) with
    | Ok prefix, Ok getValueCommand ->
      runZ3ValueQuery prefix getValueCommand
    | Error e, _ | _, Error e -> Error e

  static member DefaultTimeout = defaultTimeout

  static member DefaultOptions = defaultOptions

  member _.CheckSat pathCondition = checkSat pathCondition

  member _.GetValues(pathCondition, values) =
    getValues pathCondition values

  member _.IsSatisfiable pathCondition =
    match checkSat pathCondition with
    | Ok Sat -> Ok true
    | Ok Unsat -> Ok false
    | Ok Unknown -> SolverFailure SolverReturnedUnknown |> Error
    | Error e -> Error e

  interface ISolver with
    member this.CheckSat pathCondition = this.CheckSat pathCondition

    member this.GetValues(pathCondition, values) =
      this.GetValues(pathCondition, values)

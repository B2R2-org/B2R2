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

namespace B2R2.RearEnd.Transformer

open System
open System.IO
open System.Reflection
open System.Runtime.InteropServices
open System.Runtime.Loader

type private TransformerPluginLoadContext(pluginPath: string) =
  inherit AssemblyLoadContext(isCollectible = false)

  let pluginDir = Path.GetDirectoryName pluginPath
  let resolver = AssemblyDependencyResolver pluginPath

  let tryFindDefaultAssembly (name: AssemblyName) =
    AssemblyLoadContext.Default.Assemblies
    |> Seq.tryFind (fun assembly ->
      assembly.GetName().Name = name.Name)
    |> function
      | Some assembly -> assembly
      | None ->
        try
          AssemblyLoadContext.Default.LoadFromAssemblyName name
        with _ ->
          null

  let shouldShareHostAssembly (name: AssemblyName) =
    name.Name = "FSharp.Core"
    || name.Name.StartsWith("B2R2.", StringComparison.Ordinal)

  let tryResolvePluginAssembly (name: AssemblyName) =
    let resolved = resolver.ResolveAssemblyToPath name
    if isNull resolved then
      let path = Path.Combine(pluginDir, name.Name + ".dll")
      if File.Exists path then path else null
    else
      resolved

  let probeNativeLibrary name =
    let candidates =
      if RuntimeInformation.IsOSPlatform OSPlatform.Windows then
        [ name + ".dll"; "lib" + name + ".dll" ]
      elif RuntimeInformation.IsOSPlatform OSPlatform.OSX then
        [ "lib" + name + ".dylib"; name + ".dylib" ]
      else
        [ "lib" + name + ".so"; name + ".so" ]
    candidates
    |> List.map (fun file -> Path.Combine(pluginDir, file))
    |> List.tryFind File.Exists
    |> Option.defaultValue null

  override _.Load name =
    if shouldShareHostAssembly name then
      match tryFindDefaultAssembly name with
      | null ->
        match tryResolvePluginAssembly name with
        | null -> null
        | path -> base.LoadFromAssemblyPath path
      | assembly -> assembly
    else
      match tryResolvePluginAssembly name with
      | null -> null
      | path -> base.LoadFromAssemblyPath path

  override _.LoadUnmanagedDll name =
    let resolved = resolver.ResolveUnmanagedDllToPath name
    if isNull resolved then
      match probeNativeLibrary name with
      | null -> 0n
      | path -> base.LoadUnmanagedDllFromPath path
    else
      base.LoadUnmanagedDllFromPath resolved

  member this.LoadPluginAssembly() =
    this.LoadFromAssemblyPath pluginPath

[<RequireQualifiedAccess>]
module TransformerPluginLoader =
  let private loaderExceptionText (error: ReflectionTypeLoadException) =
    error.LoaderExceptions
    |> Array.choose (fun exn ->
      if isNull exn then None else Some exn.Message)
    |> String.concat Environment.NewLine

  let exportedTypes path =
    if File.Exists path then
      try
        let fullPath = Path.GetFullPath path
        let context = TransformerPluginLoadContext fullPath
        let assembly = context.LoadPluginAssembly()
        assembly.GetExportedTypes()
      with :? ReflectionTypeLoadException as error ->
        let detail = loaderExceptionText error
        invalidOp $"Failed to load plugin types: {detail}"
    else
      invalidOp $"File not found: {path}"

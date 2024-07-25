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

[<RequireQualifiedAccess>]
module B2R2.MiddleEnd.DataFlow.Tests.Binaries

open B2R2
open B2R2.FrontEnd
open B2R2.MiddleEnd
open B2R2.MiddleEnd.ControlFlowAnalysis
open B2R2.MiddleEnd.ControlFlowAnalysis.Strategies

type Binary = Binary of byte[] * Architecture

let loadOne (Binary (code, arch)) =
  let isa = ISA.Init arch Endian.Little
  let hdl = BinHandle (code, isa, ArchOperationMode.NoMode, None, false)
  let exnInfo = ExceptionInfo hdl
  let funcId = FunctionIdentification (hdl, exnInfo)
  let strategies =
    [| funcId :> ICFGBuildingStrategy<_, _>; CFGRecovery () |]
  BinaryBrew (hdl, exnInfo, strategies)

(*
  Example 1: Fibonacci function

  unsigned int fib(unsigned int m)
  {
      unsigned int f0 = 0, f1 = 1, f2, i;
      if (m <= 1) return m;
      else {
          for (i = 2; i <= m; i++) {
              f2 = f0 + f1;
              f0 = f1;
              f1 = f2;
          }
          return f2;
      }
  }

  00000000: 8B 54 24 04        mov         edx,dword ptr [esp+4]
  00000004: 56                 push        esi
  00000005: 33 F6              xor         esi,esi
  00000007: 8D 4E 01           lea         ecx,[esi+1]
  0000000A: 3B D1              cmp         edx,ecx
  0000000C: 77 04              ja          00000012
  0000000E: 8B C2              mov         eax,edx
  00000010: 5E                 pop         esi
  00000011: C3                 ret
  00000012: 4A                 dec         edx
  00000013: 8D 04 31           lea         eax,[ecx+esi]
  00000016: 8D 31              lea         esi,[ecx]
  00000018: 8B C8              mov         ecx,eax
  0000001A: 83 EA 01           sub         edx,1
  0000001D: 75 F4              jne         00000013
  0000001F: 5E                 pop         esi
  00000020: C3                 ret

  8B5424045633F68D4E013BD177048BC25EC34A8D04318D318BC883EA0175F45EC3
*)
let private code1 =
  [| 0x8Buy; 0x54uy; 0x24uy; 0x04uy; 0x56uy; 0x33uy; 0xF6uy; 0x8Duy; 0x4Euy;
     0x01uy; 0x3Buy; 0xD1uy; 0x77uy; 0x04uy; 0x8Buy; 0xC2uy; 0x5Euy; 0xC3uy;
     0x4Auy; 0x8Duy; 0x04uy; 0x31uy; 0x8Duy; 0x31uy; 0x8Buy; 0xC8uy; 0x83uy;
     0xEAuy; 0x01uy; 0x75uy; 0xF4uy; 0x5Euy; 0xC3uy |]

let sample1 = Binary (code1, Architecture.IntelX86)

(*
  Example 2: Constant Propagation Test (from Dragon Book, p636)

  void example(int cond)
  {
      int x, y, z;
      if (cond) {
          x = 2;
          y = 3;
      }
      else {
          x = 3;
          y = 2;
      }
      z = x + y;
  }

  0000000000000000 <example>:
   0:   f3 0f 1e fa             endbr64
   4:   55                      push   rbp
   5:   48 89 e5                mov    rbp,rsp
   8:   89 7d ec                mov    DWORD PTR [rbp-0x14],edi
   b:   83 7d ec 00             cmp    DWORD PTR [rbp-0x14],0x0
   f:   74 10                   je     21 <example+0x21>
  11:   c7 45 f4 02 00 00 00    mov    DWORD PTR [rbp-0xc],0x2
  18:   c7 45 f8 03 00 00 00    mov    DWORD PTR [rbp-0x8],0x3
  1f:   eb 0e                   jmp    2f <example+0x2f>
  21:   c7 45 f4 03 00 00 00    mov    DWORD PTR [rbp-0xc],0x3
  28:   c7 45 f8 02 00 00 00    mov    DWORD PTR [rbp-0x8],0x2
  2f:   8b 55 f4                mov    edx,DWORD PTR [rbp-0xc]
  32:   8b 45 f8                mov    eax,DWORD PTR [rbp-0x8]
  35:   01 d0                   add    eax,edx
  37:   89 45 fc                mov    DWORD PTR [rbp-0x4],eax
  3a:   90                      nop
  3b:   5d                      pop    rbp
  3c:   c3                      ret

  00000000: f30f 1efa 5548 89e5 897d ec83 7dec 0074  ....UH...}..}..t
  00000010: 10c7 45f4 0200 0000 c745 f803 0000 00eb  ..E......E......
  00000020: 0ec7 45f4 0300 0000 c745 f802 0000 008b  ..E......E......
  00000030: 55f4 8b45 f801 d089 45fc 905d c3         U..E....E..].
*)
let private code2 =
  [| 0xF3uy; 0x0Fuy; 0x1Euy; 0xFAuy; 0x55uy; 0x48uy; 0x89uy; 0xE5uy; 0x89uy;
     0x7Duy; 0xECuy; 0x83uy; 0x7Duy; 0xECuy; 0x00uy; 0x74uy; 0x10uy; 0xC7uy;
     0x45uy; 0xF4uy; 0x02uy; 0x00uy; 0x00uy; 0x00uy; 0xC7uy; 0x45uy; 0xF8uy;
     0x03uy; 0x00uy; 0x00uy; 0x00uy; 0xEBuy; 0x0Euy; 0xC7uy; 0x45uy; 0xF4uy;
     0x03uy; 0x00uy; 0x00uy; 0x00uy; 0xC7uy; 0x45uy; 0xF8uy; 0x02uy; 0x00uy;
     0x00uy; 0x00uy; 0x8Buy; 0x55uy; 0xF4uy; 0x8Buy; 0x45uy; 0xF8uy; 0x01uy;
     0xD0uy; 0x89uy; 0x45uy; 0xFCuy; 0x90uy; 0x5Duy; 0xC3uy |]

let sample2 = Binary (code2, Architecture.IntelX64)

(*
  Example 3: Untouched Value Propagation Test

  void example(int arg1, int arg2) {
      int a = arg1;
      int b = arg2 + 1;
      int c = arg2;
      int d = 1;
      c = c + 1;
  }

  0000000000000000 <example>:
   0:   f3 0f 1e fa             endbr64
   4:   55                      push   rbp
   5:   48 89 e5                mov    rbp,rsp
   8:   48 83 ec 20             sub    rsp,0x20
   c:   89 7d ec                mov    DWORD PTR [rbp-0x14],edi
   f:   89 75 e8                mov    DWORD PTR [rbp-0x18],esi
  12:   8b 45 ec                mov    eax,DWORD PTR [rbp-0x14]
  15:   89 45 f0                mov    DWORD PTR [rbp-0x10],eax
  18:   8b 45 e8                mov    eax,DWORD PTR [rbp-0x18]
  1b:   83 c0 01                add    eax,0x1
  1e:   89 45 f4                mov    DWORD PTR [rbp-0xc],eax
  21:   8b 45 e8                mov    eax,DWORD PTR [rbp-0x18]
  24:   89 45 f8                mov    DWORD PTR [rbp-0x8],eax
  27:   c7 45 fc 01 00 00 00    mov    DWORD PTR [rbp-0x4],0x1
  2e:   83 45 f8 01             add    DWORD PTR [rbp-0x8],0x1
  32:   8b 4d fc                mov    ecx,DWORD PTR [rbp-0x4]
  35:   8b 55 f8                mov    edx,DWORD PTR [rbp-0x8]
  38:   8b 75 f4                mov    esi,DWORD PTR [rbp-0xc]
  3b:   8b 45 f0                mov    eax,DWORD PTR [rbp-0x10]
  3e:   89 c7                   mov    edi,eax
  40:   c9                      leave
  41:   c3                      ret

  00000000: f30f 1efa 5548 89e5 4883 ec20 897d ec89  ....UH..H.. .}..
  00000010: 75e8 8b45 ec89 45f0 8b45 e883 c001 8945  u..E..E..E.....E
  00000020: f48b 45e8 8945 f8c7 45fc 0100 0000 8345  ..E..E..E......E
  00000030: f801 8b4d fc8b 55f8 8b75 f48b 45f0 89c7  ...M..U..u..E...
  00000040: c9c3                                     ..
*)
let private code3 =
  [| 0xf3uy; 0x0fuy; 0x1euy; 0xfauy; 0x55uy; 0x48uy; 0x89uy; 0xe5uy;
     0x48uy; 0x83uy; 0xecuy; 0x20uy; 0x89uy; 0x7duy; 0xecuy; 0x89uy;
     0x75uy; 0xe8uy; 0x8buy; 0x45uy; 0xecuy; 0x89uy; 0x45uy; 0xf0uy;
     0x8buy; 0x45uy; 0xe8uy; 0x83uy; 0xc0uy; 0x01uy; 0x89uy; 0x45uy;
     0xf4uy; 0x8buy; 0x45uy; 0xe8uy; 0x89uy; 0x45uy; 0xf8uy; 0xc7uy;
     0x45uy; 0xfcuy; 0x01uy; 0x00uy; 0x00uy; 0x00uy; 0x83uy; 0x45uy;
     0xf8uy; 0x01uy; 0x8buy; 0x4duy; 0xfcuy; 0x8buy; 0x55uy; 0xf8uy;
     0x8buy; 0x75uy; 0xf4uy; 0x8buy; 0x45uy; 0xf0uy; 0x89uy; 0xc7uy;
     0xc9uy; 0xc3uy; |]

let sample3 = Binary (code3, Architecture.IntelX64)

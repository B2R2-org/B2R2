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

namespace B2R2.MiddleEnd.LLVM

open B2R2
open B2R2.FrontEnd

/// An element in the register context.
[<Struct>]
type RegisterElement = {
  /// Register ID.
  RID: RegisterID
  /// Register's original type.
  RType: RegType
  /// The space (in bytes) occupied by the register in the context.
  Size: int
  /// Field offset in the context.
  Offset: int
}

/// Register context.
type LLVMContext = {
  /// Register context.
  Context: Map<RegisterID, RegisterElement>
  /// The size of the register context.
  ContextSize: int
}
with
  member this.DereferenceableAttribute with get () =
    "dereferenceable(" + string this.ContextSize + ")"

[<RequireQualifiedAccess>]
module private LLVMContext =
  let ofRegisterElements (regs: RegisterElement[]) =
    let last = Array.last regs
    let ctxt = Map.ofArray (regs |> Array.map (fun r -> r.RID, r))
    let size = last.Offset + last.Size
    { Context = ctxt; ContextSize = size }

[<RequireQualifiedAccess>]
module X64Context =
  open type Intel.Register
  let init () =
    let rid = Intel.Register.toRegID
    [| { RID = rid RAX; RType = 64<rt>; Size = 8; Offset = 0 }
       { RID = rid RBX; RType = 64<rt>; Size = 8; Offset = 8 }
       { RID = rid RCX; RType = 64<rt>; Size = 8; Offset = 16 }
       { RID = rid RDX; RType = 64<rt>; Size = 8; Offset = 24 }
       { RID = rid RSP; RType = 64<rt>; Size = 8; Offset = 32 }
       { RID = rid RBP; RType = 64<rt>; Size = 8; Offset = 40 }
       { RID = rid RSI; RType = 64<rt>; Size = 8; Offset = 48 }
       { RID = rid RDI; RType = 64<rt>; Size = 8; Offset = 56 }
       { RID = rid R8; RType = 64<rt>; Size = 8; Offset = 64 }
       { RID = rid R9; RType = 64<rt>; Size = 8; Offset = 72 }
       { RID = rid R10; RType = 64<rt>; Size = 8; Offset = 80 }
       { RID = rid R11; RType = 64<rt>; Size = 8; Offset = 88 }
       { RID = rid R12; RType = 64<rt>; Size = 8; Offset = 96 }
       { RID = rid R13; RType = 64<rt>; Size = 8; Offset = 104 }
       { RID = rid R14; RType = 64<rt>; Size = 8; Offset = 112 }
       { RID = rid R15; RType = 64<rt>; Size = 8; Offset = 120 }
       { RID = rid RIP; RType = 64<rt>; Size = 8; Offset = 128 }
       { RID = rid OF; RType = 1<rt>; Size = 1; Offset = 136 }
       { RID = rid DF; RType = 1<rt>; Size = 1; Offset = 137 }
       { RID = rid IF; RType = 1<rt>; Size = 1; Offset = 138 }
       { RID = rid SF; RType = 1<rt>; Size = 1; Offset = 139 }
       { RID = rid ZF; RType = 1<rt>; Size = 1; Offset = 140 }
       { RID = rid AF; RType = 1<rt>; Size = 1; Offset = 141 }
       { RID = rid PF; RType = 1<rt>; Size = 1; Offset = 142 }
       { RID = rid CF; RType = 1<rt>; Size = 1; Offset = 143 }
       { RID = rid FCW; RType = 16<rt>; Size = 2; Offset = 144 }
       { RID = rid FSW; RType = 16<rt>; Size = 2; Offset = 146 }
       { RID = rid FTW; RType = 16<rt>; Size = 2; Offset = 148 }
       { RID = rid FOP; RType = 16<rt>; Size = 2; Offset = 150 }
       { RID = rid FIP; RType = 64<rt>; Size = 8; Offset = 152 }
       { RID = rid FDP; RType = 64<rt>; Size = 8; Offset = 160 }
       { RID = rid FCS; RType = 16<rt>; Size = 2; Offset = 168 }
       { RID = rid FDS; RType = 16<rt>; Size = 2; Offset = 170 }
       { RID = rid ST0A; RType = 64<rt>; Size = 8; Offset = 172 }
       { RID = rid ST0B; RType = 16<rt>; Size = 2; Offset = 180 }
       { RID = rid ST1A; RType = 64<rt>; Size = 8; Offset = 182 }
       { RID = rid ST1B; RType = 16<rt>; Size = 2; Offset = 190 }
       { RID = rid ST2A; RType = 64<rt>; Size = 8; Offset = 192 }
       { RID = rid ST2B; RType = 16<rt>; Size = 2; Offset = 200 }
       { RID = rid ST3A; RType = 64<rt>; Size = 8; Offset = 202 }
       { RID = rid ST3B; RType = 16<rt>; Size = 2; Offset = 210 }
       { RID = rid ST4A; RType = 64<rt>; Size = 8; Offset = 212 }
       { RID = rid ST4B; RType = 16<rt>; Size = 2; Offset = 220 }
       { RID = rid ST5A; RType = 64<rt>; Size = 8; Offset = 222 }
       { RID = rid ST5B; RType = 16<rt>; Size = 2; Offset = 230 }
       { RID = rid ST6A; RType = 64<rt>; Size = 8; Offset = 232 }
       { RID = rid ST6B; RType = 16<rt>; Size = 2; Offset = 240 }
       { RID = rid ST7A; RType = 64<rt>; Size = 8; Offset = 242 }
       { RID = rid ST7B; RType = 16<rt>; Size = 2; Offset = 250 }
       { RID = rid ZMM0A; RType = 64<rt>; Size = 8; Offset = 252 }
       { RID = rid ZMM0B; RType = 64<rt>; Size = 8; Offset = 260 }
       { RID = rid ZMM1A; RType = 64<rt>; Size = 8; Offset = 268 }
       { RID = rid ZMM1B; RType = 64<rt>; Size = 8; Offset = 276 }
       { RID = rid ZMM2A; RType = 64<rt>; Size = 8; Offset = 284 }
       { RID = rid ZMM2B; RType = 64<rt>; Size = 8; Offset = 292 }
       { RID = rid ZMM3A; RType = 64<rt>; Size = 8; Offset = 300 }
       { RID = rid ZMM3B; RType = 64<rt>; Size = 8; Offset = 308 }
       { RID = rid ZMM4A; RType = 64<rt>; Size = 8; Offset = 316 }
       { RID = rid ZMM4B; RType = 64<rt>; Size = 8; Offset = 324 }
       { RID = rid ZMM5A; RType = 64<rt>; Size = 8; Offset = 332 }
       { RID = rid ZMM5B; RType = 64<rt>; Size = 8; Offset = 340 }
       { RID = rid ZMM6A; RType = 64<rt>; Size = 8; Offset = 348 }
       { RID = rid ZMM6B; RType = 64<rt>; Size = 8; Offset = 356 }
       { RID = rid ZMM7A; RType = 64<rt>; Size = 8; Offset = 364 }
       { RID = rid ZMM7B; RType = 64<rt>; Size = 8; Offset = 372 }
       { RID = rid ZMM8A; RType = 64<rt>; Size = 8; Offset = 380 }
       { RID = rid ZMM8B; RType = 64<rt>; Size = 8; Offset = 388 }
       { RID = rid ZMM9A; RType = 64<rt>; Size = 8; Offset = 396 }
       { RID = rid ZMM9B; RType = 64<rt>; Size = 8; Offset = 404 }
       { RID = rid ZMM10A; RType = 64<rt>; Size = 8; Offset = 412 }
       { RID = rid ZMM10B; RType = 64<rt>; Size = 8; Offset = 420 }
       { RID = rid ZMM11A; RType = 64<rt>; Size = 8; Offset = 428 }
       { RID = rid ZMM11B; RType = 64<rt>; Size = 8; Offset = 436 }
       { RID = rid ZMM12A; RType = 64<rt>; Size = 8; Offset = 444 }
       { RID = rid ZMM12B; RType = 64<rt>; Size = 8; Offset = 452 }
       { RID = rid ZMM13A; RType = 64<rt>; Size = 8; Offset = 460 }
       { RID = rid ZMM13B; RType = 64<rt>; Size = 8; Offset = 468 }
       { RID = rid ZMM14A; RType = 64<rt>; Size = 8; Offset = 476 }
       { RID = rid ZMM14B; RType = 64<rt>; Size = 8; Offset = 484 }
       { RID = rid ZMM15A; RType = 64<rt>; Size = 8; Offset = 492 }
       { RID = rid ZMM15B; RType = 64<rt>; Size = 8; Offset = 500 }
       { RID = rid MXCSR; RType = 32<rt>; Size = 4; Offset = 508 }
       { RID = rid MXCSRMASK; RType = 32<rt>; Size = 4; Offset = 512 }
       { RID = rid CSBase; RType = 64<rt>; Size = 8; Offset = 516 }
       { RID = rid DSBase; RType = 64<rt>; Size = 8; Offset = 524 } |]
    |> LLVMContext.ofRegisterElements

[<RequireQualifiedAccess>]
module X86Context =
  open type Intel.Register
  let init () =
    let rid = Intel.Register.toRegID
    [| { RID = rid EAX; RType = 32<rt>; Size = 4; Offset = 0 }
       { RID = rid EBX; RType = 32<rt>; Size = 4; Offset = 4 }
       { RID = rid ECX; RType = 32<rt>; Size = 4; Offset = 8 }
       { RID = rid EDX; RType = 32<rt>; Size = 4; Offset = 12 }
       { RID = rid ESP; RType = 32<rt>; Size = 4; Offset = 16 }
       { RID = rid EBP; RType = 32<rt>; Size = 4; Offset = 20 }
       { RID = rid ESI; RType = 32<rt>; Size = 4; Offset = 24 }
       { RID = rid EDI; RType = 32<rt>; Size = 4; Offset = 28 }
       { RID = rid EIP; RType = 32<rt>; Size = 4; Offset = 32 }
       { RID = rid OF; RType = 1<rt>; Size = 1; Offset = 36 }
       { RID = rid DF; RType = 1<rt>; Size = 1; Offset = 37 }
       { RID = rid IF; RType = 1<rt>; Size = 1; Offset = 38 }
       { RID = rid SF; RType = 1<rt>; Size = 1; Offset = 39 }
       { RID = rid ZF; RType = 1<rt>; Size = 1; Offset = 40 }
       { RID = rid AF; RType = 1<rt>; Size = 1; Offset = 41 }
       { RID = rid PF; RType = 1<rt>; Size = 1; Offset = 42 }
       { RID = rid CF; RType = 1<rt>; Size = 1; Offset = 43 }
       { RID = rid FCW; RType = 16<rt>; Size = 2; Offset = 44 }
       { RID = rid FSW; RType = 16<rt>; Size = 2; Offset = 46 }
       { RID = rid FTW; RType = 16<rt>; Size = 2; Offset = 48 }
       { RID = rid FOP; RType = 16<rt>; Size = 2; Offset = 50 }
       { RID = rid FIP; RType = 64<rt>; Size = 8; Offset = 52 }
       { RID = rid FDP; RType = 64<rt>; Size = 8; Offset = 60 }
       { RID = rid FCS; RType = 16<rt>; Size = 2; Offset = 68 }
       { RID = rid FDS; RType = 16<rt>; Size = 2; Offset = 70 }
       { RID = rid ST0A; RType = 64<rt>; Size = 8; Offset = 72 }
       { RID = rid ST0B; RType = 16<rt>; Size = 2; Offset = 80 }
       { RID = rid ST1A; RType = 64<rt>; Size = 8; Offset = 82 }
       { RID = rid ST1B; RType = 16<rt>; Size = 2; Offset = 90 }
       { RID = rid ST2A; RType = 64<rt>; Size = 8; Offset = 92 }
       { RID = rid ST2B; RType = 16<rt>; Size = 2; Offset = 100 }
       { RID = rid ST3A; RType = 64<rt>; Size = 8; Offset = 102 }
       { RID = rid ST3B; RType = 16<rt>; Size = 2; Offset = 110 }
       { RID = rid ST4A; RType = 64<rt>; Size = 8; Offset = 112 }
       { RID = rid ST4B; RType = 16<rt>; Size = 2; Offset = 120 }
       { RID = rid ST5A; RType = 64<rt>; Size = 8; Offset = 122 }
       { RID = rid ST5B; RType = 16<rt>; Size = 2; Offset = 130 }
       { RID = rid ST6A; RType = 64<rt>; Size = 8; Offset = 132 }
       { RID = rid ST6B; RType = 16<rt>; Size = 2; Offset = 140 }
       { RID = rid ST7A; RType = 64<rt>; Size = 8; Offset = 142 }
       { RID = rid ST7B; RType = 16<rt>; Size = 2; Offset = 150 }
       { RID = rid ZMM0A; RType = 64<rt>; Size = 8; Offset = 152 }
       { RID = rid ZMM0B; RType = 64<rt>; Size = 8; Offset = 160 }
       { RID = rid ZMM1A; RType = 64<rt>; Size = 8; Offset = 168 }
       { RID = rid ZMM1B; RType = 64<rt>; Size = 8; Offset = 176 }
       { RID = rid ZMM2A; RType = 64<rt>; Size = 8; Offset = 184 }
       { RID = rid ZMM2B; RType = 64<rt>; Size = 8; Offset = 192 }
       { RID = rid ZMM3A; RType = 64<rt>; Size = 8; Offset = 200 }
       { RID = rid ZMM3B; RType = 64<rt>; Size = 8; Offset = 208 }
       { RID = rid ZMM4A; RType = 64<rt>; Size = 8; Offset = 216 }
       { RID = rid ZMM4B; RType = 64<rt>; Size = 8; Offset = 224 }
       { RID = rid ZMM5A; RType = 64<rt>; Size = 8; Offset = 232 }
       { RID = rid ZMM5B; RType = 64<rt>; Size = 8; Offset = 240 }
       { RID = rid ZMM6A; RType = 64<rt>; Size = 8; Offset = 248 }
       { RID = rid ZMM6B; RType = 64<rt>; Size = 8; Offset = 256 }
       { RID = rid ZMM7A; RType = 64<rt>; Size = 8; Offset = 264 }
       { RID = rid MXCSR; RType = 32<rt>; Size = 4; Offset = 272 }
       { RID = rid MXCSRMASK; RType = 32<rt>; Size = 4; Offset = 276 }
       { RID = rid CSBase; RType = 32<rt>; Size = 4; Offset = 280 }
       { RID = rid DSBase; RType = 32<rt>; Size = 4; Offset = 284 } |]
    |> LLVMContext.ofRegisterElements

[<RequireQualifiedAccess>]
module ARM32Context =
  open type ARM32.Register
  let init () =
    let rid = ARM32.Register.toRegID
    [| { RID = rid R0; RType = 32<rt>; Size = 4; Offset = 0 }
       { RID = rid R1; RType = 32<rt>; Size = 4; Offset = 4 }
       { RID = rid R2; RType = 32<rt>; Size = 4; Offset = 8 }
       { RID = rid R3; RType = 32<rt>; Size = 4; Offset = 12 }
       { RID = rid R4; RType = 32<rt>; Size = 4; Offset = 16 }
       { RID = rid R5; RType = 32<rt>; Size = 4; Offset = 20 }
       { RID = rid R6; RType = 32<rt>; Size = 4; Offset = 24 }
       { RID = rid R7; RType = 32<rt>; Size = 4; Offset = 28 }
       { RID = rid R8; RType = 32<rt>; Size = 4; Offset = 32 }
       { RID = rid SB; RType = 32<rt>; Size = 4; Offset = 36 }
       { RID = rid SL; RType = 32<rt>; Size = 4; Offset = 40 }
       { RID = rid FP; RType = 32<rt>; Size = 4; Offset = 44 }
       { RID = rid IP; RType = 32<rt>; Size = 4; Offset = 48 }
       { RID = rid SP; RType = 32<rt>; Size = 4; Offset = 52 }
       { RID = rid LR; RType = 32<rt>; Size = 4; Offset = 56 }
       { RID = rid PC; RType = 32<rt>; Size = 4; Offset = 60 }
       { RID = rid D0; RType = 64<rt>; Size = 8; Offset = 64 }
       { RID = rid D1; RType = 64<rt>; Size = 8; Offset = 72 }
       { RID = rid D2; RType = 64<rt>; Size = 8; Offset = 80 }
       { RID = rid D3; RType = 64<rt>; Size = 8; Offset = 88 }
       { RID = rid D4; RType = 64<rt>; Size = 8; Offset = 96 }
       { RID = rid D5; RType = 64<rt>; Size = 8; Offset = 104 }
       { RID = rid D6; RType = 64<rt>; Size = 8; Offset = 112 }
       { RID = rid D7; RType = 64<rt>; Size = 8; Offset = 120 }
       { RID = rid D8; RType = 64<rt>; Size = 8; Offset = 128 }
       { RID = rid D9; RType = 64<rt>; Size = 8; Offset = 136 }
       { RID = rid D10; RType = 64<rt>; Size = 8; Offset = 144 }
       { RID = rid D11; RType = 64<rt>; Size = 8; Offset = 152 }
       { RID = rid D12; RType = 64<rt>; Size = 8; Offset = 160 }
       { RID = rid D13; RType = 64<rt>; Size = 8; Offset = 168 }
       { RID = rid D14; RType = 64<rt>; Size = 8; Offset = 176 }
       { RID = rid D15; RType = 64<rt>; Size = 8; Offset = 184 }
       { RID = rid D16; RType = 64<rt>; Size = 8; Offset = 192 }
       { RID = rid D17; RType = 64<rt>; Size = 8; Offset = 200 }
       { RID = rid D18; RType = 64<rt>; Size = 8; Offset = 208 }
       { RID = rid D19; RType = 64<rt>; Size = 8; Offset = 216 }
       { RID = rid D20; RType = 64<rt>; Size = 8; Offset = 224 }
       { RID = rid D21; RType = 64<rt>; Size = 8; Offset = 232 }
       { RID = rid D22; RType = 64<rt>; Size = 8; Offset = 240 }
       { RID = rid D23; RType = 64<rt>; Size = 8; Offset = 248 }
       { RID = rid D24; RType = 64<rt>; Size = 8; Offset = 256 }
       { RID = rid D25; RType = 64<rt>; Size = 8; Offset = 264 }
       { RID = rid D26; RType = 64<rt>; Size = 8; Offset = 272 }
       { RID = rid D27; RType = 64<rt>; Size = 8; Offset = 280 }
       { RID = rid D28; RType = 64<rt>; Size = 8; Offset = 288 }
       { RID = rid D29; RType = 64<rt>; Size = 8; Offset = 296 }
       { RID = rid D30; RType = 64<rt>; Size = 8; Offset = 304 }
       { RID = rid D31; RType = 64<rt>; Size = 8; Offset = 312 }
       { RID = rid CPSR; RType = 32<rt>; Size = 4; Offset = 320 } |]
    |> LLVMContext.ofRegisterElements

[<RequireQualifiedAccess>]
module ARM64Context =
  open type ARM64.Register
  let init () =
    let rid = ARM64.Register.toRegID
    [| { RID = rid X0; RType = 64<rt>; Size = 8; Offset = 0 }
       { RID = rid X1; RType = 64<rt>; Size = 8; Offset = 8 }
       { RID = rid X2; RType = 64<rt>; Size = 8; Offset = 16 }
       { RID = rid X3; RType = 64<rt>; Size = 8; Offset = 24 }
       { RID = rid X4; RType = 64<rt>; Size = 8; Offset = 32 }
       { RID = rid X5; RType = 64<rt>; Size = 8; Offset = 40 }
       { RID = rid X6; RType = 64<rt>; Size = 8; Offset = 48 }
       { RID = rid X7; RType = 64<rt>; Size = 8; Offset = 56 }
       { RID = rid X8; RType = 64<rt>; Size = 8; Offset = 64 }
       { RID = rid X9; RType = 64<rt>; Size = 8; Offset = 72 }
       { RID = rid X10; RType = 64<rt>; Size = 8; Offset = 80 }
       { RID = rid X11; RType = 64<rt>; Size = 8; Offset = 88 }
       { RID = rid X12; RType = 64<rt>; Size = 8; Offset = 96 }
       { RID = rid X13; RType = 64<rt>; Size = 8; Offset = 104 }
       { RID = rid X14; RType = 64<rt>; Size = 8; Offset = 112 }
       { RID = rid X15; RType = 64<rt>; Size = 8; Offset = 120 }
       { RID = rid X16; RType = 64<rt>; Size = 8; Offset = 128 }
       { RID = rid X17; RType = 64<rt>; Size = 8; Offset = 136 }
       { RID = rid X18; RType = 64<rt>; Size = 8; Offset = 144 }
       { RID = rid X19; RType = 64<rt>; Size = 8; Offset = 152 }
       { RID = rid X20; RType = 64<rt>; Size = 8; Offset = 160 }
       { RID = rid X21; RType = 64<rt>; Size = 8; Offset = 168 }
       { RID = rid X22; RType = 64<rt>; Size = 8; Offset = 176 }
       { RID = rid X23; RType = 64<rt>; Size = 8; Offset = 184 }
       { RID = rid X24; RType = 64<rt>; Size = 8; Offset = 192 }
       { RID = rid X25; RType = 64<rt>; Size = 8; Offset = 200 }
       { RID = rid X26; RType = 64<rt>; Size = 8; Offset = 208 }
       { RID = rid X27; RType = 64<rt>; Size = 8; Offset = 216 }
       { RID = rid X28; RType = 64<rt>; Size = 8; Offset = 224 }
       { RID = rid X29; RType = 64<rt>; Size = 8; Offset = 232 }
       { RID = rid X30; RType = 64<rt>; Size = 8; Offset = 240 }
       { RID = rid XZR; RType = 64<rt>; Size = 8; Offset = 248 }
       { RID = rid V0A; RType = 64<rt>; Size = 8; Offset = 256 }
       { RID = rid V0B; RType = 64<rt>; Size = 8; Offset = 264 }
       { RID = rid V1A; RType = 64<rt>; Size = 8; Offset = 272 }
       { RID = rid V1B; RType = 64<rt>; Size = 8; Offset = 280 }
       { RID = rid V2A; RType = 64<rt>; Size = 8; Offset = 288 }
       { RID = rid V2B; RType = 64<rt>; Size = 8; Offset = 296 }
       { RID = rid V3A; RType = 64<rt>; Size = 8; Offset = 304 }
       { RID = rid V3B; RType = 64<rt>; Size = 8; Offset = 312 }
       { RID = rid V4A; RType = 64<rt>; Size = 8; Offset = 320 }
       { RID = rid V4B; RType = 64<rt>; Size = 8; Offset = 328 }
       { RID = rid V5A; RType = 64<rt>; Size = 8; Offset = 336 }
       { RID = rid V5B; RType = 64<rt>; Size = 8; Offset = 344 }
       { RID = rid V6A; RType = 64<rt>; Size = 8; Offset = 352 }
       { RID = rid V6B; RType = 64<rt>; Size = 8; Offset = 360 }
       { RID = rid V7A; RType = 64<rt>; Size = 8; Offset = 368 }
       { RID = rid V7B; RType = 64<rt>; Size = 8; Offset = 376 }
       { RID = rid V8A; RType = 64<rt>; Size = 8; Offset = 384 }
       { RID = rid V8B; RType = 64<rt>; Size = 8; Offset = 392 }
       { RID = rid V9A; RType = 64<rt>; Size = 8; Offset = 400 }
       { RID = rid V9B; RType = 64<rt>; Size = 8; Offset = 408 }
       { RID = rid V10A; RType = 64<rt>; Size = 8; Offset = 416 }
       { RID = rid V10B; RType = 64<rt>; Size = 8; Offset = 424 }
       { RID = rid V11A; RType = 64<rt>; Size = 8; Offset = 432 }
       { RID = rid V11B; RType = 64<rt>; Size = 8; Offset = 440 }
       { RID = rid V12A; RType = 64<rt>; Size = 8; Offset = 448 }
       { RID = rid V12B; RType = 64<rt>; Size = 8; Offset = 456 }
       { RID = rid V13A; RType = 64<rt>; Size = 8; Offset = 464 }
       { RID = rid V13B; RType = 64<rt>; Size = 8; Offset = 472 }
       { RID = rid V14A; RType = 64<rt>; Size = 8; Offset = 480 }
       { RID = rid V14B; RType = 64<rt>; Size = 8; Offset = 488 }
       { RID = rid V15A; RType = 64<rt>; Size = 8; Offset = 496 }
       { RID = rid V15B; RType = 64<rt>; Size = 8; Offset = 504 }
       { RID = rid V16A; RType = 64<rt>; Size = 8; Offset = 512 }
       { RID = rid V16B; RType = 64<rt>; Size = 8; Offset = 520 }
       { RID = rid V17A; RType = 64<rt>; Size = 8; Offset = 528 }
       { RID = rid V17B; RType = 64<rt>; Size = 8; Offset = 536 }
       { RID = rid V18A; RType = 64<rt>; Size = 8; Offset = 544 }
       { RID = rid V18B; RType = 64<rt>; Size = 8; Offset = 552 }
       { RID = rid V19A; RType = 64<rt>; Size = 8; Offset = 560 }
       { RID = rid V19B; RType = 64<rt>; Size = 8; Offset = 568 }
       { RID = rid V20A; RType = 64<rt>; Size = 8; Offset = 576 }
       { RID = rid V20B; RType = 64<rt>; Size = 8; Offset = 584 }
       { RID = rid V21A; RType = 64<rt>; Size = 8; Offset = 592 }
       { RID = rid V21B; RType = 64<rt>; Size = 8; Offset = 600 }
       { RID = rid V22A; RType = 64<rt>; Size = 8; Offset = 608 }
       { RID = rid V22B; RType = 64<rt>; Size = 8; Offset = 616 }
       { RID = rid V23A; RType = 64<rt>; Size = 8; Offset = 624 }
       { RID = rid V23B; RType = 64<rt>; Size = 8; Offset = 632 }
       { RID = rid V24A; RType = 64<rt>; Size = 8; Offset = 640 }
       { RID = rid V24B; RType = 64<rt>; Size = 8; Offset = 648 }
       { RID = rid V25A; RType = 64<rt>; Size = 8; Offset = 656 }
       { RID = rid V25B; RType = 64<rt>; Size = 8; Offset = 664 }
       { RID = rid V26A; RType = 64<rt>; Size = 8; Offset = 672 }
       { RID = rid V26B; RType = 64<rt>; Size = 8; Offset = 680 }
       { RID = rid V27A; RType = 64<rt>; Size = 8; Offset = 688 }
       { RID = rid V27B; RType = 64<rt>; Size = 8; Offset = 696 }
       { RID = rid V28A; RType = 64<rt>; Size = 8; Offset = 704 }
       { RID = rid V28B; RType = 64<rt>; Size = 8; Offset = 712 }
       { RID = rid V29A; RType = 64<rt>; Size = 8; Offset = 720 }
       { RID = rid V29B; RType = 64<rt>; Size = 8; Offset = 728 }
       { RID = rid V30A; RType = 64<rt>; Size = 8; Offset = 736 }
       { RID = rid V30B; RType = 64<rt>; Size = 8; Offset = 744 }
       { RID = rid V31A; RType = 64<rt>; Size = 8; Offset = 752 }
       { RID = rid V31B; RType = 64<rt>; Size = 8; Offset = 760 }
       { RID = rid N; RType = 1<rt>; Size = 1; Offset = 768 }
       { RID = rid Z; RType = 1<rt>; Size = 1; Offset = 769 }
       { RID = rid C; RType = 1<rt>; Size = 1; Offset = 770 }
       { RID = rid V; RType = 1<rt>; Size = 1; Offset = 771 }
       { RID = rid DCZIDEL0; RType = 64<rt>; Size = 8; Offset = 772 }
       { RID = rid SP; RType = 64<rt>; Size = 8; Offset = 780 } |]
    |> LLVMContext.ofRegisterElements

[<RequireQualifiedAccess>]
module MIPS32Context =
  open type MIPS.Register
  let init () =
    let rid = MIPS.Register.toRegID
    [| { RID = rid R0; RType = 32<rt>; Size = 4; Offset = 0 }
       { RID = rid R1; RType = 32<rt>; Size = 4; Offset = 4 }
       { RID = rid R2; RType = 32<rt>; Size = 4; Offset = 8 }
       { RID = rid R3; RType = 32<rt>; Size = 4; Offset = 12 }
       { RID = rid R4; RType = 32<rt>; Size = 4; Offset = 16 }
       { RID = rid R5; RType = 32<rt>; Size = 4; Offset = 20 }
       { RID = rid R6; RType = 32<rt>; Size = 4; Offset = 24 }
       { RID = rid R7; RType = 32<rt>; Size = 4; Offset = 28 }
       { RID = rid R8; RType = 32<rt>; Size = 4; Offset = 32 }
       { RID = rid R9; RType = 32<rt>; Size = 4; Offset = 36 }
       { RID = rid R10; RType = 32<rt>; Size = 4; Offset = 40 }
       { RID = rid R11; RType = 32<rt>; Size = 4; Offset = 44 }
       { RID = rid R12; RType = 32<rt>; Size = 4; Offset = 48 }
       { RID = rid R13; RType = 32<rt>; Size = 4; Offset = 52 }
       { RID = rid R14; RType = 32<rt>; Size = 4; Offset = 56 }
       { RID = rid R15; RType = 32<rt>; Size = 4; Offset = 60 }
       { RID = rid R16; RType = 32<rt>; Size = 4; Offset = 64 }
       { RID = rid R17; RType = 32<rt>; Size = 4; Offset = 68 }
       { RID = rid R18; RType = 32<rt>; Size = 4; Offset = 72 }
       { RID = rid R19; RType = 32<rt>; Size = 4; Offset = 76 }
       { RID = rid R20; RType = 32<rt>; Size = 4; Offset = 80 }
       { RID = rid R21; RType = 32<rt>; Size = 4; Offset = 84 }
       { RID = rid R22; RType = 32<rt>; Size = 4; Offset = 88 }
       { RID = rid R23; RType = 32<rt>; Size = 4; Offset = 92 }
       { RID = rid R24; RType = 32<rt>; Size = 4; Offset = 96 }
       { RID = rid R25; RType = 32<rt>; Size = 4; Offset = 100 }
       { RID = rid R26; RType = 32<rt>; Size = 4; Offset = 104 }
       { RID = rid R27; RType = 32<rt>; Size = 4; Offset = 108 }
       { RID = rid R28; RType = 32<rt>; Size = 4; Offset = 112 }
       { RID = rid R29; RType = 32<rt>; Size = 4; Offset = 116 }
       { RID = rid R30; RType = 32<rt>; Size = 4; Offset = 120 }
       { RID = rid R31; RType = 32<rt>; Size = 4; Offset = 124 }
       { RID = rid F0; RType = 32<rt>; Size = 4; Offset = 128 }
       { RID = rid F1; RType = 32<rt>; Size = 4; Offset = 132 }
       { RID = rid F2; RType = 32<rt>; Size = 4; Offset = 136 }
       { RID = rid F3; RType = 32<rt>; Size = 4; Offset = 140 }
       { RID = rid F4; RType = 32<rt>; Size = 4; Offset = 144 }
       { RID = rid F5; RType = 32<rt>; Size = 4; Offset = 148 }
       { RID = rid F6; RType = 32<rt>; Size = 4; Offset = 152 }
       { RID = rid F7; RType = 32<rt>; Size = 4; Offset = 156 }
       { RID = rid F8; RType = 32<rt>; Size = 4; Offset = 160 }
       { RID = rid F9; RType = 32<rt>; Size = 4; Offset = 164 }
       { RID = rid F10; RType = 32<rt>; Size = 4; Offset = 168 }
       { RID = rid F11; RType = 32<rt>; Size = 4; Offset = 172 }
       { RID = rid F12; RType = 32<rt>; Size = 4; Offset = 176 }
       { RID = rid F13; RType = 32<rt>; Size = 4; Offset = 180 }
       { RID = rid F14; RType = 32<rt>; Size = 4; Offset = 184 }
       { RID = rid F15; RType = 32<rt>; Size = 4; Offset = 188 }
       { RID = rid F16; RType = 32<rt>; Size = 4; Offset = 192 }
       { RID = rid F17; RType = 32<rt>; Size = 4; Offset = 196 }
       { RID = rid F18; RType = 32<rt>; Size = 4; Offset = 200 }
       { RID = rid F19; RType = 32<rt>; Size = 4; Offset = 204 }
       { RID = rid F20; RType = 32<rt>; Size = 4; Offset = 208 }
       { RID = rid F21; RType = 32<rt>; Size = 4; Offset = 212 }
       { RID = rid F22; RType = 32<rt>; Size = 4; Offset = 216 }
       { RID = rid F23; RType = 32<rt>; Size = 4; Offset = 220 }
       { RID = rid F24; RType = 32<rt>; Size = 4; Offset = 224 }
       { RID = rid F25; RType = 32<rt>; Size = 4; Offset = 228 }
       { RID = rid F26; RType = 32<rt>; Size = 4; Offset = 232 }
       { RID = rid F27; RType = 32<rt>; Size = 4; Offset = 236 }
       { RID = rid F28; RType = 32<rt>; Size = 4; Offset = 240 }
       { RID = rid F29; RType = 32<rt>; Size = 4; Offset = 244 }
       { RID = rid F30; RType = 32<rt>; Size = 4; Offset = 248 }
       { RID = rid F31; RType = 32<rt>; Size = 4; Offset = 252 }
       { RID = rid HI; RType = 32<rt>; Size = 4; Offset = 256 }
       { RID = rid LO; RType = 32<rt>; Size = 4; Offset = 260 } |]
    |> LLVMContext.ofRegisterElements

[<RequireQualifiedAccess>]
module MIPS64Context =
  open type MIPS.Register
  let init () =
    let rid = MIPS.Register.toRegID
    [| { RID = rid R0; RType = 64<rt>; Size = 8; Offset = 0 }
       { RID = rid R1; RType = 64<rt>; Size = 8; Offset = 8 }
       { RID = rid R2; RType = 64<rt>; Size = 8; Offset = 16 }
       { RID = rid R3; RType = 64<rt>; Size = 8; Offset = 24 }
       { RID = rid R4; RType = 64<rt>; Size = 8; Offset = 32 }
       { RID = rid R5; RType = 64<rt>; Size = 8; Offset = 40 }
       { RID = rid R6; RType = 64<rt>; Size = 8; Offset = 48 }
       { RID = rid R7; RType = 64<rt>; Size = 8; Offset = 56 }
       { RID = rid R8; RType = 64<rt>; Size = 8; Offset = 64 }
       { RID = rid R9; RType = 64<rt>; Size = 8; Offset = 72 }
       { RID = rid R10; RType = 64<rt>; Size = 8; Offset = 80 }
       { RID = rid R11; RType = 64<rt>; Size = 8; Offset = 88 }
       { RID = rid R12; RType = 64<rt>; Size = 8; Offset = 96 }
       { RID = rid R13; RType = 64<rt>; Size = 8; Offset = 104 }
       { RID = rid R14; RType = 64<rt>; Size = 8; Offset = 112 }
       { RID = rid R15; RType = 64<rt>; Size = 8; Offset = 120 }
       { RID = rid R16; RType = 64<rt>; Size = 8; Offset = 128 }
       { RID = rid R17; RType = 64<rt>; Size = 8; Offset = 136 }
       { RID = rid R18; RType = 64<rt>; Size = 8; Offset = 144 }
       { RID = rid R19; RType = 64<rt>; Size = 8; Offset = 152 }
       { RID = rid R20; RType = 64<rt>; Size = 8; Offset = 160 }
       { RID = rid R21; RType = 64<rt>; Size = 8; Offset = 168 }
       { RID = rid R22; RType = 64<rt>; Size = 8; Offset = 176 }
       { RID = rid R23; RType = 64<rt>; Size = 8; Offset = 184 }
       { RID = rid R24; RType = 64<rt>; Size = 8; Offset = 192 }
       { RID = rid R25; RType = 64<rt>; Size = 8; Offset = 200 }
       { RID = rid R26; RType = 64<rt>; Size = 8; Offset = 208 }
       { RID = rid R27; RType = 64<rt>; Size = 8; Offset = 216 }
       { RID = rid R28; RType = 64<rt>; Size = 8; Offset = 224 }
       { RID = rid R29; RType = 64<rt>; Size = 8; Offset = 232 }
       { RID = rid R30; RType = 64<rt>; Size = 8; Offset = 240 }
       { RID = rid R31; RType = 64<rt>; Size = 8; Offset = 248 }
       { RID = rid F0; RType = 64<rt>; Size = 8; Offset = 256 }
       { RID = rid F1; RType = 64<rt>; Size = 8; Offset = 264 }
       { RID = rid F2; RType = 64<rt>; Size = 8; Offset = 272 }
       { RID = rid F3; RType = 64<rt>; Size = 8; Offset = 280 }
       { RID = rid F4; RType = 64<rt>; Size = 8; Offset = 288 }
       { RID = rid F5; RType = 64<rt>; Size = 8; Offset = 296 }
       { RID = rid F6; RType = 64<rt>; Size = 8; Offset = 304 }
       { RID = rid F7; RType = 64<rt>; Size = 8; Offset = 312 }
       { RID = rid F8; RType = 64<rt>; Size = 8; Offset = 320 }
       { RID = rid F9; RType = 64<rt>; Size = 8; Offset = 328 }
       { RID = rid F10; RType = 64<rt>; Size = 8; Offset = 336 }
       { RID = rid F11; RType = 64<rt>; Size = 8; Offset = 344 }
       { RID = rid F12; RType = 64<rt>; Size = 8; Offset = 352 }
       { RID = rid F13; RType = 64<rt>; Size = 8; Offset = 360 }
       { RID = rid F14; RType = 64<rt>; Size = 8; Offset = 368 }
       { RID = rid F15; RType = 64<rt>; Size = 8; Offset = 376 }
       { RID = rid F16; RType = 64<rt>; Size = 8; Offset = 384 }
       { RID = rid F17; RType = 64<rt>; Size = 8; Offset = 392 }
       { RID = rid F18; RType = 64<rt>; Size = 8; Offset = 400 }
       { RID = rid F19; RType = 64<rt>; Size = 8; Offset = 408 }
       { RID = rid F20; RType = 64<rt>; Size = 8; Offset = 416 }
       { RID = rid F21; RType = 64<rt>; Size = 8; Offset = 424 }
       { RID = rid F22; RType = 64<rt>; Size = 8; Offset = 432 }
       { RID = rid F23; RType = 64<rt>; Size = 8; Offset = 440 }
       { RID = rid F24; RType = 64<rt>; Size = 8; Offset = 448 }
       { RID = rid F25; RType = 64<rt>; Size = 8; Offset = 456 }
       { RID = rid F26; RType = 64<rt>; Size = 8; Offset = 464 }
       { RID = rid F27; RType = 64<rt>; Size = 8; Offset = 472 }
       { RID = rid F28; RType = 64<rt>; Size = 8; Offset = 480 }
       { RID = rid F29; RType = 64<rt>; Size = 8; Offset = 488 }
       { RID = rid F30; RType = 64<rt>; Size = 8; Offset = 496 }
       { RID = rid F31; RType = 64<rt>; Size = 8; Offset = 504 }
       { RID = rid HI; RType = 64<rt>; Size = 8; Offset = 512 }
       { RID = rid LO; RType = 64<rt>; Size = 8; Offset = 520 } |]
    |> LLVMContext.ofRegisterElements

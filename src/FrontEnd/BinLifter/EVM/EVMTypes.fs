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

namespace B2R2.FrontEnd.BinLifter.EVM

open B2R2
open System.Runtime.CompilerServices

[<assembly: InternalsVisibleTo("B2R2.FrontEnd.BinLifter.Tests")>]
do ()

exception internal InvalidConditionException
exception internal InvalidFmtException

type Register =
  /// Program counter.
  | PC = 0x1
  /// Gas.
  | GAS = 0x2
  /// Stack pointer.
  | SP = 0x3

/// Shortcut for Register type.
type internal R = Register

/// Operation Size.
type OperationSize = int
module internal OperationSize =
  let regType = 256<rt>

/// This module exposes several useful functions to handle EVM registers.
[<RequireQualifiedAccess>]
module Register =
  let inline ofRegID (n: RegisterID): Register =
    int n |> LanguagePrimitives.EnumOfValue

  let inline toRegID (reg: Register) =
    LanguagePrimitives.EnumToValue (reg) |> RegisterID.create

  let ofString (str: string) =
    match str.ToLower () with
    | "PC" -> R.PC
    | "GAS" -> R.GAS
    | "SP" -> R.SP
    | _ -> Utils.impossible ()

  let toString = function
    | R.PC -> "PC"
    | R.GAS -> "GAS"
    | R.SP -> "SP"
    | _ -> Utils.impossible ()

  let toRegType = function
    | R.PC -> 256<rt>
    | R.GAS -> 64<rt>
    | R.SP -> 256<rt>
    | _ -> Utils.impossible ()


/// <summary>
///   EVM opcodes. This type should be generated using
///   <c>scripts/genOpcode.fsx</c> from the `EVMSupportedOpcode.txt` file.
/// </summary>
type Opcode =
  /// Halts execution
  | STOP
  /// Addition operation
  | ADD
  /// Multiplication operation
  | MUL
  /// Subtraction operation
  | SUB
  /// Integer division operation
  | DIV
  /// Signed integer division operation (truncated)
  | SDIV
  /// Modulo remainder operation
  | MOD
  /// Signed modulo remainder operation
  | SMOD
  /// Modulo addition operation
  | ADDMOD
  /// Modulo multiplication operation
  | MULMOD
  /// Exponential operation
  | EXP
  /// Extend length of two's complement signed integer
  | SIGNEXTEND
  /// Less-than comparison
  | LT
  /// Greater-than comparison
  | GT
  /// Signed less-than comparison
  | SLT
  /// Signed greater-than comparison
  | SGT
  /// Equality comparison
  | EQ
  /// Simple not operator
  | ISZERO
  /// Bitwise AND operation
  | AND
  /// Bitwise OR operation
  | OR
  /// Bitwise XOR operation
  | XOR
  /// Bitwise NOT operation
  | NOT
  /// Retrieve single byte from word
  | BYTE
  /// Shift Left
  | SHL
  /// Logical Shift Right
  | SHR
  /// Arithmetic Shift Right
  | SAR
  /// Compute Keccak-256 hash
  | SHA3
  /// Get address of currently executing account
  | ADDRESS
  /// Get balance of the given account
  | BALANCE
  /// Get execution origination address
  | ORIGIN
  /// Get caller address
  | CALLER
  /// Get deposited value by the instruction/transaction responsible for this
  /// execution
  | CALLVALUE
  /// Get input data of current environment
  | CALLDATALOAD
  /// Get size of input data in current environment
  | CALLDATASIZE
  /// Copy input data in current environment to memory
  | CALLDATACOPY
  /// Get size of code running in current environment
  | CODESIZE
  /// Copy code running in current environment to memory
  | CODECOPY
  /// Get price of gas in current environment
  | GASPRICE
  /// Get size of an account's code
  | EXTCODESIZE
  /// Copy an account's code to memory
  | EXTCODECOPY
  /// Pushes the size of the return data buffer onto the stack
  | RETURNDATASIZE
  /// Copies data from the return data buffer to memory
  | RETURNDATACOPY
  /// Get the hash of one of the 256 most recent complete blocks
  | BLOCKHASH
  /// Get the block's beneficiary address
  | COINBASE
  /// Get the block's timestamp
  | TIMESTAMP
  /// Get the block's number
  | NUMBER
  /// Get the block's difficulty
  | DIFFICULTY
  /// Get the block's gas limit
  | GASLIMIT
  /// Remove word from stack
  | POP
  /// Load word from memory
  | MLOAD
  /// Save word to memory
  | MSTORE
  /// Save byte to memory
  | MSTORE8
  /// Load word from storage
  | SLOAD
  /// Save word to storage
  | SSTORE
  /// Alter the program counter
  | JUMP
  /// Conditionally alter the program counter
  | JUMPI
  /// Get the value of the program counter prior to the increment
  | GETPC
  /// Get the size of active memory in bytes
  | MSIZE
  /// Get the amount of available gas, including the corresponding reduction
  /// the amount of available gas
  | GAS
  /// Mark a valid destination for jumps
  | JUMPDEST
  /// Place 1 byte item on stack
  | PUSH1 of BitVector
  /// Place 2-byte item on stack
  | PUSH2 of BitVector
  /// Place 3-byte item on stack
  | PUSH3 of BitVector
  /// Place 4-byte item on stack
  | PUSH4 of BitVector
  /// Place 5-byte item on stack
  | PUSH5 of BitVector
  /// Place 6-byte item on stack
  | PUSH6 of BitVector
  /// Place 7-byte item on stack
  | PUSH7 of BitVector
  /// Place 8-byte item on stack
  | PUSH8 of BitVector
  /// Place 9-byte item on stack
  | PUSH9 of BitVector
  /// Place 10-byte item on stack
  | PUSH10 of BitVector
  /// Place 11-byte item on stack
  | PUSH11 of BitVector
  /// Place 12-byte item on stack
  | PUSH12 of BitVector
  /// Place 13-byte item on stack
  | PUSH13 of BitVector
  /// Place 14-byte item on stack
  | PUSH14 of BitVector
  /// Place 15-byte item on stack
  | PUSH15 of BitVector
  /// Place 16-byte item on stack
  | PUSH16 of BitVector
  /// Place 17-byte item on stack
  | PUSH17 of BitVector
  /// Place 18-byte item on stack
  | PUSH18 of BitVector
  /// Place 19-byte item on stack
  | PUSH19 of BitVector
  /// Place 20-byte item on stack
  | PUSH20 of BitVector
  /// Place 21-byte item on stack
  | PUSH21 of BitVector
  /// Place 22-byte item on stack
  | PUSH22 of BitVector
  /// Place 23-byte item on stack
  | PUSH23 of BitVector
  /// Place 24-byte item on stack
  | PUSH24 of BitVector
  /// Place 25-byte item on stack
  | PUSH25 of BitVector
  /// Place 26-byte item on stack
  | PUSH26 of BitVector
  /// Place 27-byte item on stack
  | PUSH27 of BitVector
  /// Place 28-byte item on stack
  | PUSH28 of BitVector
  /// Place 29-byte item on stack
  | PUSH29 of BitVector
  /// Place 30-byte item on stack
  | PUSH30 of BitVector
  /// Place 31-byte item on stack
  | PUSH31 of BitVector
  /// Place 32-byte (full word) item on stack
  | PUSH32 of BitVector
  /// Duplicate 1st stack item
  | DUP1
  /// Duplicate 2nd stack item
  | DUP2
  /// Duplicate 3rd stack item
  | DUP3
  /// Duplicate 4th stack item
  | DUP4
  /// Duplicate 5th stack item
  | DUP5
  /// Duplicate 6th stack item
  | DUP6
  /// Duplicate 7th stack item
  | DUP7
  /// Duplicate 8th stack item
  | DUP8
  /// Duplicate 9th stack item
  | DUP9
  /// Duplicate 10th stack item
  | DUP10
  /// Duplicate 11th stack item
  | DUP11
  /// Duplicate 12th stack item
  | DUP12
  /// Duplicate 13th stack item
  | DUP13
  /// Duplicate 14th stack item
  | DUP14
  /// Duplicate 15th stack item
  | DUP15
  /// Duplicate 16th stack item
  | DUP16
  /// Exchange 1st and 2nd stack items
  | SWAP1
  /// Exchange 1st and 3rd stack items
  | SWAP2
  /// Exchange 1st and 4th stack items
  | SWAP3
  /// Exchange 1st and 5th stack items
  | SWAP4
  /// Exchange 1st and 6th stack items
  | SWAP5
  /// Exchange 1st and 7th stack items
  | SWAP6
  /// Exchange 1st and 8th stack items
  | SWAP7
  /// Exchange 1st and 9th stack items
  | SWAP8
  /// Exchange 1st and 10th stack items
  | SWAP9
  /// Exchange 1st and 11th stack items
  | SWAP10
  /// Exchange 1st and 12th stack items
  | SWAP11
  /// Exchange 1st and 13th stack items
  | SWAP12
  /// Exchange 1st and 14th stack items
  | SWAP13
  /// Exchange 1st and 15th stack items
  | SWAP14
  /// Exchange 1st and 16th stack items
  | SWAP15
  /// Exchange 1st and 17th stack items
  | SWAP16
  /// Append log record with no topics
  | LOG0
  /// Append log record with one topic
  | LOG1
  /// Append log record with two topics
  | LOG2
  /// Append log record with three topics
  | LOG3
  /// Append log record with four topics
  | LOG4
  /// Tentative libevmasm has different numbers
  | JUMPTO
  /// Tentative
  | JUMPIF
  /// Tentative
  | JUMPSUB
  /// Tentative
  | JUMPSUBV
  /// Tentative
  | BEGINSUB
  /// Tentative
  | BEGINDATA
  /// Tentative
  | RETURNSUB
  /// Tentative
  | PUTLOCAL
  /// Tentative
  | GETLOCAL
  /// Only referenced in pyethereum
  | SLOADBYTES
  /// Only referenced in pyethereum
  | SSTOREBYTES
  /// Only referenced in pyethereum
  | SSIZE
  /// Create a new account with associated code
  | CREATE
  /// Message-call into an account
  | CALL
  /// Message-call into this account with alternative account's code
  | CALLCODE
  /// Halt execution returning output data
  | RETURN
  /// Message-call into this account with an alternative account's code, but
  /// persisting into this account with an alternative account's code
  | DELEGATECALL
  /// Create a new account and set creation address to
  /// sha3(sender + sha3(init code)) % 2**160
  | CREATE2
  /// Similar to CALL, but does not modify state
  | STATICCALL
  /// FIXME: Not in the yellow paper.
  | TXEXECGAS
  /// Stop execution and revert state changes, without consuming all provided
  /// gas and providing a reason
  | REVERT
  /// Designated invalid instruction
  | INVALID
  /// Halt execution and register account for later deletion
  | SELFDESTRUCT

type internal Op = Opcode

type internal Instruction = Opcode

/// Basic information obtained by parsing a MIPS instruction.
[<NoComparison; CustomEquality>]
type InsInfo = {
  /// Address.
  Address: Addr
  /// Instruction length.
  NumBytes: uint32
  /// Offset of the instruction. When codecopy (or similar) is used, we should
  /// adjust the address of the copied instructions using this offset.
  Offset: Addr
  /// Opcode.
  Opcode: Opcode
  /// Gas
  GAS: int
}
with
  override __.GetHashCode () =
    hash (__.Address,
          __.NumBytes,
          __.Opcode,
          __.GAS)
  override __.Equals (i) =
    match i with
    | :? InsInfo as i ->
      i.Address = __.Address
      && i.NumBytes = __.NumBytes
      && i.Opcode = __.Opcode
      && i.GAS = __.GAS
    | _ -> false

// vim: set tw=80 sts=2 sw=2:

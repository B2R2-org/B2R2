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

/// <summary>
/// Encodes every EVM instruction there is.
///
/// An EVM instruction is the one byte naming it and nothing more, save for a
/// push, which holds the number it pushes in the bytes just after that byte.
/// There is therefore no field to lay out and no register to name here: the
/// whole of the instruction set is which byte each name stands for, and the
/// only thing an encoder has to work out is what a push holds.
///
/// The names are the ones B2R2's own disassembler writes, so that a line of
/// disassembly can be handed straight back. Three of them are written with a
/// mark in the middle rather than as one word.
/// </summary>
module internal B2R2.Assembly.EVM.AsmOpcode

open B2R2.Assembly.EVM.ParserHelper
open B2R2.Assembly.EVM.AsmField

/// An instruction naming nothing at all, which is the byte naming it and no
/// more.
let private plain code ins =
  match ins.Operands with
  | [] -> [ code ]
  | _ -> wrongOperands ins

/// A push, which holds what the source wrote in as many bytes as its name says.
let private push width code ins =
  match ins.Operands with
  | [ operand ] -> code :: immediate width ins operand
  | _ -> wrongOperands ins

/// The instructions computing over the numbers the stack holds, which is what
/// halting the machine outright is listed among.
let arithmeticEncoders () =
  [ "stop", plain 0x00uy
    "add", plain 0x01uy
    "mul", plain 0x02uy
    "sub", plain 0x03uy
    "div", plain 0x04uy
    "sdiv", plain 0x05uy
    "mod", plain 0x06uy
    "smod", plain 0x07uy
    "addmod", plain 0x08uy
    "mulmod", plain 0x09uy
    "exp", plain 0x0Auy
    "signextend", plain 0x0Buy ]

/// The instructions comparing two numbers and the ones working over the bits of
/// them, which answer with a number as everything here does.
let comparisonEncoders () =
  [ "lt", plain 0x10uy
    "gt", plain 0x11uy
    "slt", plain 0x12uy
    "sgt", plain 0x13uy
    "eq", plain 0x14uy
    "iszero", plain 0x15uy
    "and", plain 0x16uy
    "or", plain 0x17uy
    "xor", plain 0x18uy
    "not", plain 0x19uy
    "byte", plain 0x1Auy
    "shl", plain 0x1Buy
    "shr", plain 0x1Cuy
    "sar", plain 0x1Duy ]

/// The instructions reading what the program was called with and what the
/// accounts around it hold, together with the one hashing a run of memory,
/// which is listed here because what it hashes is what those instructions
/// fetch.
let environmentEncoders () =
  [ "sha3", plain 0x20uy
    "address", plain 0x30uy
    "balance", plain 0x31uy
    "origin", plain 0x32uy
    "caller", plain 0x33uy
    "callvalue", plain 0x34uy
    "calldataload", plain 0x35uy
    "calldatasize", plain 0x36uy
    "calldatacopy", plain 0x37uy
    "codesize", plain 0x38uy
    "codecopy", plain 0x39uy
    "gasprice", plain 0x3Auy
    "extcodesize", plain 0x3Buy
    "extcodecopy", plain 0x3Cuy
    "returndatasize", plain 0x3Duy
    "returndatacopy", plain 0x3Euy
    "extcodehash", plain 0x3Fuy ]

/// The instructions reading the block the program runs in and the chain that
/// block belongs to.
let blockEncoders () =
  [ "blockhash", plain 0x40uy
    "coinbase", plain 0x41uy
    "timestamp", plain 0x42uy
    "number", plain 0x43uy
    "difficulty", plain 0x44uy
    "gaslimit", plain 0x45uy
    "chain_id", plain 0x46uy
    "this.balance", plain 0x47uy
    "block.basefee", plain 0x48uy ]

/// The instructions moving values between the stack and the places a program
/// keeps them, together with the ones going somewhere other than the next byte
/// and the ones saying what the machine has left to spend.
let stateEncoders () =
  [ "pop", plain 0x50uy
    "mload", plain 0x51uy
    "mstore", plain 0x52uy
    "mstore8", plain 0x53uy
    "sload", plain 0x54uy
    "sstore", plain 0x55uy
    "jump", plain 0x56uy
    "jumpi", plain 0x57uy
    "getpc", plain 0x58uy
    "msize", plain 0x59uy
    "gas", plain 0x5Auy
    "jumpdest", plain 0x5Buy
    "tload", plain 0x5Cuy
    "tstore", plain 0x5Duy
    "mcopy", plain 0x5Euy ]

/// <summary>
/// The pushes, which are the only instructions holding anything beyond the byte
/// naming them.
///
/// The one pushing nothing but zero holds nothing, and the thirty-two others
/// hold as many bytes as their names say. Which of them a source wrote is
/// therefore how wide the instruction is as well as what it pushes, so a name
/// here is not shorthand for a width the assembler is free to pick.
/// </summary>
let pushEncoders () =
  ("push0", plain 0x5Fuy)
  :: [ for n in 1 .. 32 -> $"push{n}", push n (byte (0x5F + n)) ]

/// The instructions reaching back into the stack, either to copy what is there
/// or to bring it to the top.
let stackEncoders () =
  [ for n in 1 .. 16 -> $"dup{n}", plain (byte (0x7F + n)) ]
  @ [ for n in 1 .. 16 -> $"swap{n}", plain (byte (0x8F + n)) ]

/// The instructions writing a record of what the program did, told apart by how
/// many values they file that record under.
let logEncoders () =
  [ for n in 0 .. 4 -> $"log{n}", plain (byte (0xA0 + n)) ]

/// The instructions making another program, calling one, and leaving the one
/// running, whether because it is done or because it is giving up.
let systemEncoders () =
  [ "create", plain 0xF0uy
    "call", plain 0xF1uy
    "callcode", plain 0xF2uy
    "return", plain 0xF3uy
    "delegatecall", plain 0xF4uy
    "create2", plain 0xF5uy
    "staticcall", plain 0xFAuy
    "revert", plain 0xFDuy
    "invalid", plain 0xFEuy
    "selfdestruct", plain 0xFFuy ]

// vim: set tw=80 sts=2 sw=2:

// ----------------------------------------------------------------------------
// B2R2 C# Sample.
// ----------------------------------------------------------------------------

#r "nuget: B2R2.FrontEnd.BinInterface"

using System;
using B2R2;
using B2R2.FrontEnd.BinLifter;
using B2R2.FrontEnd.BinInterface;

ISA isa = ISA("amd64");
byte [] binary = new byte[] { 0x65, 0xff, 0x15, 0x10, 0x00, 0x00, 0x00 };
BinHandle handler = BinHandle.Init(isa, binary);
// Parse the binary.
Instruction ins = BinHandle.ParseInstr(handler, 0UL);
// Disassemble it.
string s = ins.Disasm();
// Print it.
Console.WriteLine(s);

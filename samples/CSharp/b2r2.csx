// ----------------------------------------------------------------------------
// B2R2 C# Sample.
// ----------------------------------------------------------------------------

#r "nuget: B2R2.FrontEnd.API, 0.10.0"

using System;
using B2R2;
using B2R2.FrontEnd;
using B2R2.FrontEnd.BinLifter;

ISA isa = new ISA("amd64");
byte [] binary = new byte[] { 0x65, 0xff, 0x15, 0x10, 0x00, 0x00, 0x00 };
BinHandle hdl = new BinHandle(binary, isa);
LiftingUnit lifter = hdl.NewLiftingUnit();
IInstruction ins = lifter.ParseInstruction(0UL);
string s = lifter.DisasmInstruction(ins);
Console.WriteLine(s);

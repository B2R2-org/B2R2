// ----------------------------------------------------------------------------
// B2R2 C# Sample.
// ----------------------------------------------------------------------------
// Currently we assume that you have published all the binaries into the
// `../../build` directory. To do so, you can simply run `make publish` in the
// source root directory.
// ----------------------------------------------------------------------------

#r "../../build/B2R2.Core.dll"
#r "../../build/B2R2.BinIR.dll"
#r "../../build/B2R2.FrontEnd.Core.dll"
#r "../../build/B2R2.FrontEnd.Library.dll"

using System;
using B2R2;
using B2R2.FrontEnd;
using B2R2.BinIR.LowUIR;

ISA isa = ISA.OfString( "amd64" );
byte [] binary = new byte[] { 0x65, 0xff, 0x15, 0x10, 0x00, 0x00, 0x00 };
BinHandler handler = BinHandler.Init( isa, binary );
// Parse the binary.
Instruction ins = BinHandler.ParseInstr( handler, 0UL );
// Disassemble it.
string s = ins.Disasm();
// Print it.
Console.WriteLine( s );

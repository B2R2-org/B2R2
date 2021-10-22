' ---------------------------------------------------------------------------- '
' B2R2 VB Sample.
' ---------------------------------------------------------------------------- '

Imports System
Imports B2R2
Imports B2R2.FrontEnd.BinInterface

Module Program
    Sub Main(args As String())
        Dim i = ISA.OfString("amd64")
        Dim bs = New Byte() { &H65, &Hff, &H15, &H10, &H00, &H00, &H00 }
        Dim hdl = BinHandle.Init(i, bs)
        Dim ins = BinHandle.ParseInstr(hdl, 0)
        Console.WriteLine(ins.Disasm())
    End Sub
End Module

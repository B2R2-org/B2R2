' ---------------------------------------------------------------------------- '
' B2R2 VB Sample.
' ---------------------------------------------------------------------------- '

Imports System
Imports B2R2
Imports B2R2.FrontEnd

Module Program
    Sub Main(args As String())
        Dim i = New ISA("amd64")
        Dim bs = New Byte() { &H65, &Hff, &H15, &H10, &H00, &H00, &H00 }
        Dim hdl = New BinHandle(bs, i)
        Dim lifter = hdl.NewLiftingUnit()
        Dim ins = lifter.ParseInstruction(0)
        Dim s = lifter.DisasmInstruction(ins)
        Console.WriteLine(s)
    End Sub
End Module

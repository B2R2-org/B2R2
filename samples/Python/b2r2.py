# -----------------------------------------------------------------------------
# B2R2 Python Sample.
# -----------------------------------------------------------------------------
# Currently we assume that you have published all the binaries into the
# `../../build` directory. To do so, you can simply run `make publish` in the
# source root directory.
# -----------------------------------------------------------------------------

import clr
import os, sys
sys.path.append(os.path.abspath(r'../../build/'))
clr.AddReferenceToFile(r'B2R2.Core.dll')
clr.AddReferenceToFile(r'B2R2.FrontEnd.Core.dll')
clr.AddReferenceToFile(r'B2R2.FrontEnd.Library.dll')

from B2R2 import *
from B2R2.FrontEnd import *

isa = ISA.OfString("amd64")
binary = ByteArray.ofHexString('65ff1510000000')
handler = BinHandler.Init(isa, binary)
ins = handler.ParseInstr(handler, 0)
print(ins.Disasm())

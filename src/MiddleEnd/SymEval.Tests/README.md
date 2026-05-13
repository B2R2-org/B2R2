# SymEval.Tests

Some SymEval tests exercise the SMT-LIB export path against the external Z3
binary. To enable those checks, install Z3 and make `z3` available on `PATH`, or
set `Z3_PATH` to the Z3 executable.

If Z3 is not available, the Z3-dependent tests are reported as inconclusive
instead of failed.

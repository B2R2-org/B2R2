# B2R2.MiddleEnd.SSA

### B2R2?

B2R2 is a fully managed binary analysis framework written in F#. It provides a
rich set of algorithms, functions, and tools for reverse engineering, program
analysis, and binary-level inspection.

### B2R2.MiddleEnd.SSA Package?

`B2R2.MiddleEnd.SSA` turns a LowUIR CFG into an SSA CFG, and promotes the stack
slots of such a graph into variables of their own.

### Lifting and promotion

These are two operations. `SSALifterFactory` answers an `ISSALiftable`, whose
`Lift` translates a `LowUIRCFG` into SSA form. `SSAPromoterFactory` answers an
`ISSAPromotable`, whose `Promote` rewrites every memory access at a known stack
address into a variable of the slot it names.

```fsharp
let lifted = SSALifterFactory.Create(hdl).Lift cfg
let promoted = SSAPromoterFactory.Create(hdl).Promote lifted
```

Promotion costs a sparse data-flow analysis and a second round of phi placement
and renaming, so a caller that only reads an SSA graph stops after `Lift`. A
`StackVar` exists only after promotion.

The stack pointer propagation `Promote` reads cannot be handed over afterwards,
since the renaming that follows mutates the SSA variables it is keyed under.
Pass an `ISSAStackPointerObserver` to `SSAPromoterFactory.Create` to read it.

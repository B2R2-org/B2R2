# B2R2.MiddleEnd.BinGraph

### B2R2?

B2R2 is a fully managed binary analysis framework written in F#. It provides a
rich set of algorithms, functions, and tools for reverse engineering, program
analysis, and binary-level inspection.

### B2R2.MiddleEnd.BinGraph Package?

`B2R2.MiddleEnd.BinGraph` defines basic graph types and values. Our CFG analyses
are dependent on this package.

### Where things live

The graph types and the interfaces over them sit directly in
`B2R2.MiddleEnd.BinGraph`, so a single `open` of it covers `IVertex`, `Edge`,
`IDiGraph`, and the graph implementations. The algorithms live one level down,
one namespace per family and one module per concrete algorithm:

- `B2R2.MiddleEnd.BinGraph.Traversal` — `DFS` and `BFS`.
- `B2R2.MiddleEnd.BinGraph.SCC` — `Tarjan`.
- `B2R2.MiddleEnd.BinGraph.Dominance` — six dominance algorithms, two
  dominance frontier providers, and `DominanceFactory`, which picks one of
  them by value at run time.
- `B2R2.MiddleEnd.BinGraph.Loop` — `NaturalLoop`.

F# resolves a partial namespace path, so that one `open` reaches all of them:
`Traversal.DFS.foldPreorder`, `SCC.Tarjan.compute`, `Loop.NaturalLoop.findAll`.
Every module named above carries `[<RequireQualifiedAccess>]`, so the family
prefix stays visible at the call site.

An interface that an algorithm returns belongs with the data structures rather
than with the algorithm, which is why `IDominance` is in the root namespace
while nothing that implements it is. A new algorithm is
one more file and one more module in the family it belongs to; only utilities
over the data structures themselves, such as `DiGraph`, stay at the root.

# WebAssembly test fixtures

| Fixture | Purpose |
| --- | --- |
| `wasm_basic` | A minimal module exercising the section table, the import table, and the custom `name` section (entry-point/import/local function name resolution). |

`wasm_basic.wasm` is assembled from a small `.wat` with `wat2wasm
--debug-names` (the `--debug-names` flag emits the `name` section):

```wat
(module
  (import "env" "putc_js" (func $putc_js (param i32)))
  (func $__wasm_call_ctors)
  (func $main (result i32)
    i32.const 0)
  (memory 1)
  (export "memory" (memory 0))
  (export "main" (func $main))
  (start $__wasm_call_ctors))
```

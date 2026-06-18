# Python bytecode test fixtures

| Fixture | Purpose |
| --- | --- |
| `python_basic` | A `.pyc` file exercising the magic header and the marshalled code-object parser (constants extraction). |

`python_basic.pyc` is produced with CPython **3.12** (the parser targets the
3.12 marshal format and magic `0x0A0D0DCB`):

```sh
printf 'def helper(x):\n    return x + 1\n' > python_basic.py
python3.12 -m py_compile python_basic.py
cp __pycache__/python_basic.cpython-312.pyc python_basic.pyc
```

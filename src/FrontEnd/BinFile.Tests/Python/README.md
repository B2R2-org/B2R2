# Python bytecode test fixtures

| Fixture | Purpose |
| --- | --- |
| `python_basic` | A `.pyc` file exercising the magic header and the marshalled code-object parser (constants extraction). |
| `python_exception` | A `.pyc` file whose nested code object carries a `co_exceptiontable`, exercising the exception-table decoder. |

`python_basic.pyc` is produced with CPython **3.12** (the parser targets the
3.12 marshal format and magic `0x0A0D0DCB`):

```sh
printf 'def helper(x):\n    return x + 1\n' > python_basic.py
python3.12 -m py_compile python_basic.py
cp __pycache__/python_basic.cpython-312.pyc python_basic.pyc
```

`python_exception.pyc` is produced the same way, from a function whose
`try`/`except`/`finally` is what makes the compiler emit an exception table
(there is none before 3.11, which handles exceptions with a run-time block
stack instead):

```sh
printf 'def f(x):\n    try:\n        y = 1 / x\n    except ZeroDivisionError:\n        y = 0\n    finally:\n        print(y)\n    return y\n' > python_exception.py
python3.12 -m py_compile python_exception.py
cp __pycache__/python_exception.cpython-312.pyc python_exception.pyc
```
